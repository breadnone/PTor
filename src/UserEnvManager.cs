using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace PTor
{

    public class UserEnvManager
    {
        static readonly string[] ProxyVars = { "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy" };

        static readonly string[] LegacySocksVars = { "ALL_PROXY", "all_proxy" };
        static readonly string[] NoProxyVars = { "NO_PROXY", "no_proxy" };
        static readonly string[] AllVars = ProxyVars.Concat(NoProxyVars).Concat(LegacySocksVars).ToArray();
        const string LoopbackNoProxy = "localhost,127.0.0.1,::1";

        const string StorePath = @"Software\PTor";
        const string ManagedValue = "EnvManaged";
        const string StateValue = "EnvState";

        const uint WM_SETTINGCHANGE = 0x001A;
        const uint SMTO_ABORTIFHUNG = 0x0002;
        static readonly IntPtr HWND_BROADCAST = new(0xFFFF);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
            uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);

        public record SavedVal(string? V, int K);
        // Diverged: values the strict reassert stomped mid-run, recorded so
        // Disable restores the user's latest setting instead of the stale
        // pre-run backup (same contract as the DNS/proxy Diverged records;
        // here it rides inside the state JSON so it clears with the marker).
        // Null on states written before this existed — treated as "none".
        internal record EnvState(Dictionary<string, SavedVal> Saved, Dictionary<string, string> Applied, Dictionary<string, SavedVal>? Diverged);
        public record EnvSnapshot(bool Managed, int VarCount);

        public EnvSnapshot GetSnapshot()
        {
            try
            {
                using var store = Registry.CurrentUser.OpenSubKey(StorePath, writable: false);
                var managed = store != null && Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) == 1;
                using var env = Registry.CurrentUser.OpenSubKey("Environment", writable: false);
                var count = env == null ? 0 : AllVars.Count(v => env.GetValue(v) != null);
                return new EnvSnapshot(managed, count);
            }
            catch { return new EnvSnapshot(false, 0); }
        }

        public bool MatchesApplied()
        {
            try
            {
                using var store = Registry.CurrentUser.OpenSubKey(StorePath, writable: false);
                if (store == null || Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) != 1)
                    return false;
                var state = ReadState(store);
                if (state == null) return false;
                using var env = Registry.CurrentUser.OpenSubKey("Environment", writable: false);
                if (env == null) return false;
                foreach (var kv in state.Applied)
                {
                    if (!string.Equals(env.GetValue(kv.Key) as string, kv.Value, StringComparison.Ordinal))
                        return false;
                }
                return true;
            }
            catch { return false; }
        }

        public string Enable(int socksPort, int bridgePort)
        {
            string? recoveryNote = null;
            using var store = Registry.CurrentUser.CreateSubKey(StorePath, writable: true)
                ?? throw new InvalidOperationException("Could not open HKCU\\Software\\PTor for writing.");
            using var env = Registry.CurrentUser.CreateSubKey("Environment", writable: true)
                ?? throw new InvalidOperationException("Could not open HKCU\\Environment for writing.");

            if (Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) == 1)
                recoveryNote = Recover(store, env);

            var http = $"http://127.0.0.1:{bridgePort}";
            var applied = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var v in ProxyVars) applied[v] = http;

            var saved = new Dictionary<string, SavedVal>(StringComparer.Ordinal);
            foreach (var v in AllVars)
                saved[v] = ReadSaved(env, v);

            foreach (var v in AllVars)
            {
                var s = saved[v];
                if (s.V != null && (s.V.Contains($"127.0.0.1:{socksPort}", StringComparison.Ordinal) ||
                                    s.V.Contains($"127.0.0.1:{bridgePort}", StringComparison.Ordinal)))
                    saved[v] = new SavedVal(null, 0);
            }

            foreach (var v in LegacySocksVars)
                if (saved[v].V == null) { try { env.DeleteValue(v, throwOnMissingValue: false); } catch { } }

            foreach (var v in NoProxyVars) applied[v] = MergeNoProxy(saved[v].V);

            store.SetValue(StateValue, JsonSerializer.Serialize(new EnvState(saved, applied, null), PtorJsonContext.Default.EnvState), RegistryValueKind.String);
            store.SetValue(ManagedValue, 1, RegistryValueKind.DWord);
            foreach (var kv in applied)
                env.SetValue(kv.Key, kv.Value, RegistryValueKind.String);
            Broadcast();

            foreach (var kv in applied)
            {
                var back = env.GetValue(kv.Key) as string;
                if (!string.Equals(back, kv.Value, StringComparison.Ordinal))
                {
                    try { RestoreValues(env, saved); ClearMarker(store); Broadcast(); } catch { }
                    throw new InvalidOperationException(
                        $"Environment proxy write did not stick ({kv.Key} read-back mismatch) — routing via env " +
                        "is OFF, previous values restored.");
                }
            }

            var msg = "Env proxy ON: newly launched CLI apps (Go/Python/curl/Java, Node CLIs that read HTTP_PROXY) inherit it automatically; restart already-running apps (and their terminal) to pick them up.";
            return recoveryNote != null ? recoveryNote + " " + msg : msg;
        }

        // broadcast=false SKIPS the WM_SETTINGCHANGE broadcast: that ping
        // is SendMessageTimeout(HWND_BROADCAST, ..., 2s) and can park the
        // caller up to 2s behind hung windows. The registry restore above
        // is the source of truth for new launches (running processes keep
        // their copied env either way), so the barbaric quit path passes
        // false — dying must never wait on other apps' windows. Every
        // other caller keeps the default true (running app, nudge live).
        // Fail-closed repair for mid-run overwrites: rewrites the APPLIED
        // env values without touching the saved backup. Returns true when
        // it actually rewrote something. Never throws. Runs on the intact
        // watcher in every mode (see engine ReassertRoutingDetached).
        //
        // The stomped values are recorded into the state's Diverged map
        // (latest wins, deletion recorded as a null value) and persisted, so
        // Disable restores the user's most recent values instead of the
        // stale pre-run backup — stomping must never destroy evidence of
        // user intent.
        public bool ReassertApplied()
        {
            try
            {
                using var store = Registry.CurrentUser.OpenSubKey(StorePath, writable: true);
                if (store == null || Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) != 1)
                    return false;
                var state = ReadState(store);
                if (state == null || state.Applied == null || state.Applied.Count == 0) return false;
                using var env = Registry.CurrentUser.OpenSubKey("Environment", writable: true);
                if (env == null) return false;
                var need = false;
                foreach (var kv in state.Applied)
                {
                    string? cur = null;
                    try { cur = env.GetValue(kv.Key) as string; } catch { continue; }
                    if (!string.Equals(cur, kv.Value, StringComparison.Ordinal)) { need = true; break; }
                }
                if (!need) return false;
                Dictionary<string, SavedVal>? diverged = null;
                try
                {
                    diverged = state.Diverged != null
                        ? new Dictionary<string, SavedVal>(state.Diverged, StringComparer.Ordinal)
                        : new Dictionary<string, SavedVal>(StringComparer.Ordinal);
                    foreach (var kv in state.Applied)
                    {
                        string? cur = null;
                        try { cur = env.GetValue(kv.Key) as string; } catch { continue; }
                        if (!string.Equals(cur, kv.Value, StringComparison.Ordinal))
                            diverged[kv.Key] = ReadSaved(env, kv.Key);
                    }
                }
                catch { diverged = null; }
                foreach (var kv in state.Applied)
                {
                    try { env.SetValue(kv.Key, kv.Value, RegistryValueKind.String); }
                    catch { return false; }
                }
                try
                {
                    if (diverged != null && diverged.Count > 0)
                        store.SetValue(StateValue,
                            JsonSerializer.Serialize(new EnvState(state.Saved, state.Applied, diverged), PtorJsonContext.Default.EnvState),
                            RegistryValueKind.String);
                }
                catch { }
                try { Broadcast(); } catch { }
                return true;
            }
            catch { return false; }
        }

        public string Disable(bool broadcast = true)
        {
            using var store = Registry.CurrentUser.OpenSubKey(StorePath, writable: true);
            if (store == null || Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) != 1)
                return "Env proxy was not managed by PTor — nothing to restore.";

            var state = ReadState(store);
            using var env = Registry.CurrentUser.OpenSubKey("Environment", writable: true);
            if (state == null || env == null)
            {
                try { ClearMarker(store); } catch { }
                return "Env proxy state unreadable — marker cleared, values left as-is.";
            }

            var left = new List<string>();
            var restored = 0;
            var divergedRestored = 0;
            foreach (var kv in state.Applied)
            {
                string? cur = null;
                try { cur = env.GetValue(kv.Key) as string; } catch { }
                if (!string.Equals(cur, kv.Value, StringComparison.Ordinal))
                {
                    left.Add(kv.Key);
                    continue;
                }
                try
                {
                    // Latest-intent-wins: this var was diverged mid-run and
                    // stomped back by the reassert — put back the user's most
                    // recent value (or deletion), not the pre-run backup.
                    SavedVal? div = null;
                    try
                    {
                        if (state.Diverged != null && state.Diverged.TryGetValue(kv.Key, out var d))
                            div = d;
                    }
                    catch { div = null; }
                    if (div != null)
                    {
                        if (div.V == null) env.DeleteValue(kv.Key, throwOnMissingValue: false);
                        else env.SetValue(kv.Key, div.V, (RegistryValueKind)div.K);
                        divergedRestored++;
                    }
                    else if (state.Saved.TryGetValue(kv.Key, out var s) && s.V != null)
                        env.SetValue(kv.Key, s.V, (RegistryValueKind)s.K);
                    else
                        env.DeleteValue(kv.Key, throwOnMissingValue: false);
                    restored++;
                }
                catch { left.Add(kv.Key + " (error)"); }
            }

            foreach (var kv in state.Saved)
            {
                if (state.Applied.ContainsKey(kv.Key)) continue;
                try
                {
                    var cur = env.GetValue(kv.Key)?.ToString();
                    if (string.Equals(cur, kv.Value.V, StringComparison.Ordinal))
                    {
                        if (kv.Value.V == null) env.DeleteValue(kv.Key, throwOnMissingValue: false);
                        else env.SetValue(kv.Key, kv.Value.V, (RegistryValueKind)kv.Value.K);
                    }
                }
                catch { }
            }

            ClearMarker(store);
            if (broadcast)
            {
                try { Broadcast(); } catch { }
            }
            var divergedNote = divergedRestored > 0
                ? $" ({divergedRestored} restored to what you set mid-run instead of the older pre-run value.)"
                : "";
            if (left.Count == 0)
                return "Env proxy OFF: previous environment values restored (new launches stop inheriting Tor)." + divergedNote;
            return $"Env proxy OFF: restored {restored} var(s); left {left.Count} you changed mid-run untouched ({string.Join(", ", left)}).{divergedNote}";
        }

        static string? Recover(RegistryKey store, RegistryKey env)
        {
            try
            {
                var state = ReadState(store);
                if (state != null)
                {
                    var stillOurs = true;
                    foreach (var kv in state.Applied)
                    {
                        if (!string.Equals(env.GetValue(kv.Key) as string, kv.Value, StringComparison.Ordinal))
                        { stillOurs = false; break; }
                    }
                    if (stillOurs)
                    {
                        // Chain intent across the crash like the proxy path:
                        // diverged (user's latest) wins per var over the
                        // pre-run backup, so the fresh Enable below snapshots
                        // that as the new backup.
                        Dictionary<string, SavedVal>? effective = null;
                        try
                        {
                            if (state.Diverged != null && state.Diverged.Count > 0)
                            {
                                effective = new Dictionary<string, SavedVal>(state.Saved, StringComparer.Ordinal);
                                foreach (var kv in state.Diverged)
                                    effective[kv.Key] = kv.Value;
                            }
                        }
                        catch { effective = null; }
                        RestoreValues(env, effective ?? state.Saved);
                        ClearMarker(store);
                        Broadcast();
                        return "Recovered: previous run died with env proxy on — old values restored first.";
                    }
                }
                ClearMarker(store);
                return "Recovered: stale env-proxy marker cleared (values were already changed).";
            }
            catch { return null; }
        }

        static SavedVal ReadSaved(RegistryKey env, string name)
        {
            try
            {
                var v = env.GetValue(name);
                if (v == null) return new SavedVal(null, 0);
                int kind;
                try { kind = (int)env.GetValueKind(name); }
                catch { kind = (int)RegistryValueKind.String; }
                return new SavedVal(v.ToString(), kind);
            }
            catch { return new SavedVal(null, 0); }
        }

        static void RestoreValues(RegistryKey env, Dictionary<string, SavedVal> saved)
        {
            foreach (var kv in saved)
            {
                try
                {
                    if (kv.Value.V == null) env.DeleteValue(kv.Key, throwOnMissingValue: false);
                    else env.SetValue(kv.Key, kv.Value.V, (RegistryValueKind)kv.Value.K);
                }
                catch { }
            }
        }

        static EnvState? ReadState(RegistryKey store)
        {
            try
            {
                var json = store.GetValue(StateValue, "") as string;
                return string.IsNullOrEmpty(json) ? null : JsonSerializer.Deserialize(json, PtorJsonContext.Default.EnvState);
            }
            catch { return null; }
        }

        static void ClearMarker(RegistryKey store)
        {
            try { store.DeleteValue(ManagedValue, throwOnMissingValue: false); } catch { }
            try { store.DeleteValue(StateValue, throwOnMissingValue: false); } catch { }
        }

        static string MergeNoProxy(string? existing)
        {
            var parts = (existing ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var have = new HashSet<string>(parts, StringComparer.OrdinalIgnoreCase);
            var out_ = new List<string>(parts);
            foreach (var need in LoopbackNoProxy.Split(','))
                if (!have.Contains(need)) out_.Add(need);
            return string.Join(",", out_);
        }

        static void Broadcast()
        {
            try
            {
                // Bounded courtesy ping: new launches read the registry
                // directly, this only nudges already-running apps. Hung
                // windows must never park the exit path, so 2s max.
                SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, UIntPtr.Zero, "Environment",
                    SMTO_ABORTIFHUNG, 2000, out _);
            }
            catch {  }
        }
    }
}
