using System;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace PTor
{

    public class SystemProxyManager
    {
        const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        const string ManagedValue = "PTorManaged";
        const string StateValue = "PTorState";
        // Mid-run intent memory (same contract as the DNS Diverged_* values):
        // when the strict reassert stomps a diverged proxy/auto-config back
        // to ours, the stomped values are recorded here (overwritten every
        // stomp: latest intent wins) so Disable restores what the user most
        // recently had — not the stale pre-run backup.
        const string DivergedServerValue = "PTorDivergedServer";
        const string DivergedOverrideValue = "PTorDivergedOverride";
        const string DivergedEnabledValue = "PTorDivergedEnabled";
        const string DivergedAutoUrlValue = "PTorDivergedAutoUrl";
        const string DivergedAutoDetectValue = "PTorDivergedAutoDetect";
        const string LoopbackBypass = "127.*;localhost;[::1]";

        const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
        const int INTERNET_OPTION_REFRESH = 37;

        [DllImport("wininet.dll", SetLastError = true)]
        static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

        internal record ProxyTriple(int Enabled, string Server, string Override);
        internal record ManagedState(ProxyTriple Saved, string AppliedServer, string AppliedOverride,
            bool HasAutoBackup, string? SavedAutoConfigUrl, int SavedAutoDetect);

        public record ProxySnapshot(bool ManagedByPTor, int Enabled, string Server, string Override);

        public ProxySnapshot GetSnapshot()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: false);
                if (key == null) return new ProxySnapshot(false, 0, "", "");
                var t = ReadTriple(key);
                return new ProxySnapshot(IsManaged(key), t.Enabled, t.Server, t.Override);
            }
            catch { return new ProxySnapshot(false, 0, "", ""); }
        }

        public bool MatchesApplied()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: false);
                if (key == null || !IsManaged(key)) return false;
                var state = ReadState(key);
                if (state == null) return false;
                var cur = ReadTriple(key);
                if (cur.Enabled != 1 ||
                    !string.Equals(cur.Server, state.AppliedServer, StringComparison.Ordinal) ||
                    !string.Equals(cur.Override, state.AppliedOverride, StringComparison.Ordinal))
                    return false;
                // A reappearing PAC/auto-detect silently overrides our manual
                // proxy (Windows prefers auto-config): routing is NOT intact.
                if (state.HasAutoBackup && !AutoIsOurs(key)) return false;
                return true;
            }
            catch { return false; }
        }

        public string Enable(int socksPort, int bridgePort)
        {
            string? recoveryNote = null;
            using var key = Registry.CurrentUser.CreateSubKey(KeyPath, writable: true)
                ?? throw new InvalidOperationException("Could not open HKCU Internet Settings for writing.");

            if (IsManaged(key))
                recoveryNote = RecoverFromUncleanShutdown(key);

            var saved = ReadTriple(key);
            var savedAutoUrl = ReadAutoUrl(key);
            var savedAutoDetect = ReadAutoDetect(key);
            var hadAuto = !string.IsNullOrEmpty(savedAutoUrl) || savedAutoDetect != 0;

            if (saved.Enabled == 1 && saved.Server.Contains("127.0.0.1:", StringComparison.Ordinal))
                saved = new ProxyTriple(0, "", saved.Override);
            var appliedServer = $"http=127.0.0.1:{bridgePort};https=127.0.0.1:{bridgePort};ftp=127.0.0.1:{bridgePort};socks=127.0.0.1:{socksPort}";
            var appliedOverride = MergeBypass(saved.Override);

            WriteState(key, new ManagedState(saved, appliedServer, appliedOverride,
                HasAutoBackup: true, SavedAutoConfigUrl: savedAutoUrl, SavedAutoDetect: savedAutoDetect));
            key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            key.SetValue("ProxyServer", appliedServer, RegistryValueKind.String);
            key.SetValue("ProxyOverride", appliedOverride, RegistryValueKind.String);
            // An auto-config script (PAC) or auto-detect overrides manual
            // proxy settings in Windows: pause both while routing is on, or
            // apps silently bypass Tor entirely.
            ClearAuto(key);
            Notify();

            var verify = ReadTriple(key);
            if (verify.Enabled != 1 ||
                !string.Equals(verify.Server, appliedServer, StringComparison.Ordinal) ||
                !string.Equals(verify.Override, appliedOverride, StringComparison.Ordinal) ||
                !AutoIsOurs(key))
            {
                try { WriteTriple(key, saved); RestoreAuto(key, ReadState(key)); ClearMarker(key); Notify(); } catch { }
                throw new InvalidOperationException(
                    "System proxy write did not stick (read-back mismatch) — routing is OFF, your old " +
                    "settings were restored. Something is reverting HKCU proxy changes (group policy, " +
                    "a security tool, or a forced auto-config script).");
            }

            var msg = "Routing ON: all proxy-aware apps of this user now go through Tor. Services and other users unaffected.";
            if (hadAuto)
                msg += " (Your auto proxy-setup PAC/script was paused while routing is on and comes back on stop.)";
            try
            {
                // Loud when we stripped a total-bypass "*" or when broad
                // intranet bypasses remain: in proxy-only mode those hosts go
                // direct (Divert lockdown makes them fail closed instead).
                var hadStar = false;
                try
                {
                    foreach (var t in (saved.Override ?? "").Split(';'))
                        if ((t ?? "").Trim() == "*") { hadStar = true; break; }
                }
                catch { hadStar = false; }
                if (hadStar)
                    msg += " (Your ProxyOverride contained \"*\" (bypass everything) — stripped while routing is on and restored on stop; without this nothing would have used Tor.)";
                else if (!string.IsNullOrEmpty(saved.Override) && saved.Override.IndexOf("*", StringComparison.Ordinal) >= 0)
                    msg += " (Note: your ProxyOverride keeps wildcard intranet bypasses — those hosts bypass the proxy; Tor-only lockdown blocks them instead of leaking direct.)";
            }
            catch { }
            return recoveryNote != null ? recoveryNote + " " + msg : msg;
        }

        // Fail-closed repair for mid-run overwrites (VPN/GPO/another tool):
        // rewrites the APPLIED proxy values without touching the saved
        // backup, so a later Disable still restores the user's originals.
        // The stomped values are recorded as diverged (latest wins) so
        // Disable restores the user's most recent setting instead of the
        // stale pre-run backup — stomping must never destroy evidence of
        // user intent. Returns true when it actually rewrote something.
        // Never throws. Runs on the intact watcher in every mode (a
        // diverged proxy leaks proxy-aware apps immediately); the 5s
        // cadence bounds the window to seconds.
        public bool ReassertApplied()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: true);
                if (key == null || !IsManaged(key)) return false;
                var state = ReadState(key);
                if (state == null) return false;
                var cur = ReadTriple(key);
                var autoOurs = AutoIsOurs(key);
                if (cur.Enabled == 1 &&
                    string.Equals(cur.Server, state.AppliedServer, StringComparison.Ordinal) &&
                    string.Equals(cur.Override, state.AppliedOverride, StringComparison.Ordinal) &&
                    autoOurs)
                    return false;
                try { RecordDiverged(key, cur); } catch { }
                try
                {
                    key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                    key.SetValue("ProxyServer", state.AppliedServer, RegistryValueKind.String);
                    key.SetValue("ProxyOverride", state.AppliedOverride, RegistryValueKind.String);
                    ClearAuto(key);
                    Notify();
                }
                catch { return false; }
                try
                {
                    var back = ReadTriple(key);
                    return back.Enabled == 1 &&
                        string.Equals(back.Server, state.AppliedServer, StringComparison.Ordinal) &&
                        string.Equals(back.Override, state.AppliedOverride, StringComparison.Ordinal) &&
                        AutoIsOurs(key);
                }
                catch { return false; }
            }
            catch { return false; }
        }

        public string Disable()
        {
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: true);
            if (key == null || !IsManaged(key))
                return "System proxy was not managed by PTor — nothing to restore.";

            var state = ReadState(key);
            var current = ReadTriple(key);

            if (state == null ||
                current.Enabled != 1 ||
                !string.Equals(current.Server, state.AppliedServer, StringComparison.Ordinal) ||
                !string.Equals(current.Override, state.AppliedOverride, StringComparison.Ordinal))
            {

                ClearMarker(key);
                Notify();
                return "Proxy changed while PTor ran — left your current settings untouched.";
            }

            // Latest-intent-wins: a mid-run change the strict reassert
            // stomped was recorded (RecordDiverged) — put back the user's
            // most recent setting, not the stale pre-run backup.
            ProxyTriple? diverged = null;
            try { diverged = DivergedTriple(key); } catch { diverged = null; }
            WriteTriple(key, diverged ?? state.Saved);
            // Restore backed-up auto-config only if nobody set their own
            // mid-run (same compare-before-restore philosophy as the triple).
            // Ancient states without a backup leave auto-config untouched.
            // A stomped mid-run auto-config (recorded diverged) wins over the
            // pre-run backup — latest intent, same as the triple above.
            string autoNote = "";
            if (state.HasAutoBackup)
            {
                if (AutoIsOurs(key))
                {
                    autoNote = RestoreAutoLatest(key, state);
                    // Absent also means off — but if we restored a nonzero
                    // value and it is already gone, say so instead of looking
                    // broken (hardening tools eat this value on some systems).
                    try
                    {
                        if (state.SavedAutoDetect != 0 &&
                            Convert.ToInt32(key.GetValue("AutoDetect", 0) ?? 0) == 0)
                            autoNote += " (note: AutoDetect would not stay set on this system — absent means off too)";
                    }
                    catch { }
                }
                else autoNote = " (auto-config changed mid-run — left your current one untouched)";
            }
            ClearMarker(key);
            Notify();
            return (diverged != null
                ? "Routing OFF: restored the proxy settings you set mid-run (instead of the older pre-run backup)."
                : "Routing OFF: previous system proxy settings restored.") + autoNote;
        }

        public bool WasLeftManaged()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: false);
                return key != null && IsManaged(key);
            }
            catch { return false; }
        }

        static bool IsManaged(RegistryKey key)
        {
            try { return Convert.ToInt32(key.GetValue(ManagedValue, 0) ?? 0) == 1; }
            catch { return false; }
        }

        static string? RecoverFromUncleanShutdown(RegistryKey key)
        {
            try
            {
                var state = ReadState(key);
                var current = ReadTriple(key);
                if (state != null && current.Enabled == 1 &&
                    string.Equals(current.Server, state.AppliedServer, StringComparison.Ordinal))
                {
                    // Chain intent across the crash: restore the user's most
                    // recent (diverged) setting first, so the fresh Enable
                    // below snapshots THAT as the new backup — not our stale
                    // pre-crash original (Enable re-applies ours right after
                    // anyway; the backup is what matters here).
                    ProxyTriple? diverged = null;
                    try { diverged = DivergedTriple(key); } catch { diverged = null; }
                    WriteTriple(key, diverged ?? state.Saved);
                    if (state.HasAutoBackup)
                    {
                        try { if (AutoIsOurs(key)) RestoreAutoLatest(key, state); } catch { }
                    }
                    ClearMarker(key);
                    Notify();
                    return "Recovered: previous run died with routing on — your old proxy settings were restored first.";
                }
                ClearMarker(key);
                return "Recovered: stale PTor proxy marker cleared (settings were already changed).";
            }
            catch { return null; }
        }

        static ProxyTriple ReadTriple(RegistryKey key)
        {
            int enabled;
            try { enabled = Convert.ToInt32(key.GetValue("ProxyEnable", 0) ?? 0); }
            catch { enabled = 0; }
            return new ProxyTriple(
                enabled,
                key.GetValue("ProxyServer", "") as string ?? "",
                key.GetValue("ProxyOverride", "") as string ?? "");
        }

        static void WriteTriple(RegistryKey key, ProxyTriple t)
        {
            key.SetValue("ProxyEnable", t.Enabled, RegistryValueKind.DWord);
            if (string.IsNullOrEmpty(t.Server)) { try { key.DeleteValue("ProxyServer", throwOnMissingValue: false); } catch { } }
            else key.SetValue("ProxyServer", t.Server, RegistryValueKind.String);
            if (string.IsNullOrEmpty(t.Override)) { try { key.DeleteValue("ProxyOverride", throwOnMissingValue: false); } catch { } }
            else key.SetValue("ProxyOverride", t.Override, RegistryValueKind.String);
        }

        static ManagedState? ReadState(RegistryKey key)
        {
            try
            {
                var json = key.GetValue(StateValue, "") as string;
                if (string.IsNullOrEmpty(json)) return null;
                return JsonSerializer.Deserialize(json, PtorJsonContext.Default.ManagedState);
            }
            catch { return null; }
        }

        static void WriteState(RegistryKey key, ManagedState state)
        {
            key.SetValue(StateValue, JsonSerializer.Serialize(state, PtorJsonContext.Default.ManagedState), RegistryValueKind.String);
            key.SetValue(ManagedValue, 1, RegistryValueKind.DWord);
        }

        static void ClearMarker(RegistryKey key)
        {
            try { key.DeleteValue(ManagedValue, throwOnMissingValue: false); } catch { }
            try { key.DeleteValue(StateValue, throwOnMissingValue: false); } catch { }
            // Diverged intent without its marker/backup is an orphan a future
            // session could mistake for fresh intent — always drop it here.
            try { key.DeleteValue(DivergedServerValue, throwOnMissingValue: false); } catch { }
            try { key.DeleteValue(DivergedOverrideValue, throwOnMissingValue: false); } catch { }
            try { key.DeleteValue(DivergedEnabledValue, throwOnMissingValue: false); } catch { }
            try { key.DeleteValue(DivergedAutoUrlValue, throwOnMissingValue: false); } catch { }
            try { key.DeleteValue(DivergedAutoDetectValue, throwOnMissingValue: false); } catch { }
        }

        // Records the live triple + auto-config we are about to stomp, so a
        // later restore puts back the user's latest setting instead of the
        // stale pre-run backup. Overwritten on every stomp (latest wins).
        // Never throws.
        static void RecordDiverged(RegistryKey key, ProxyTriple cur)
        {
            try
            {
                key.SetValue(DivergedEnabledValue, cur.Enabled, RegistryValueKind.DWord);
                if (string.IsNullOrEmpty(cur.Server))
                {
                    try { key.DeleteValue(DivergedServerValue, throwOnMissingValue: false); } catch { }
                }
                else key.SetValue(DivergedServerValue, cur.Server, RegistryValueKind.String);
                if (string.IsNullOrEmpty(cur.Override))
                {
                    try { key.DeleteValue(DivergedOverrideValue, throwOnMissingValue: false); } catch { }
                }
                else key.SetValue(DivergedOverrideValue, cur.Override, RegistryValueKind.String);
                var url = ReadAutoUrl(key);
                if (string.IsNullOrEmpty(url))
                {
                    try { key.DeleteValue(DivergedAutoUrlValue, throwOnMissingValue: false); } catch { }
                }
                else key.SetValue(DivergedAutoUrlValue, url, RegistryValueKind.String);
                // Presence of the detect record matters (null = "was absent"
                // is itself intent): always stamp it.
                key.SetValue(DivergedAutoDetectValue, ReadAutoDetect(key), RegistryValueKind.DWord);
            }
            catch { }
        }

        // The recorded stomped triple, or null when nothing was ever stomped
        // (or the record is unusable). Never throws.
        static ProxyTriple? DivergedTriple(RegistryKey key)
        {
            try
            {
                var rawEnabled = key.GetValue(DivergedEnabledValue, null);
                if (rawEnabled == null) return null;
                return new ProxyTriple(
                    Convert.ToInt32(rawEnabled),
                    key.GetValue(DivergedServerValue, "") as string ?? "",
                    key.GetValue(DivergedOverrideValue, "") as string ?? "");
            }
            catch { return null; }
        }

        // Restores auto-config preferring a recorded stomped (diverged)
        // mid-run value over the pre-run backup. Caller must have verified
        // AutoIsOurs. Returns the message suffix (possibly ""). Never throws.
        static string RestoreAutoLatest(RegistryKey key, ManagedState state)
        {
            try
            {
                var rawDet = key.GetValue(DivergedAutoDetectValue, null);
                if (rawDet != null)
                {
                    var url = key.GetValue(DivergedAutoUrlValue, null) as string;
                    if (string.IsNullOrEmpty(url))
                    {
                        try { key.DeleteValue("AutoConfigURL", throwOnMissingValue: false); } catch { }
                    }
                    else key.SetValue("AutoConfigURL", url, RegistryValueKind.String);
                    try { key.SetValue("AutoDetect", Convert.ToInt32(rawDet), RegistryValueKind.DWord); }
                    catch { key.SetValue("AutoDetect", 0, RegistryValueKind.DWord); }
                    return " (auto-config restored to what you set mid-run)";
                }
            }
            catch { }
            try { RestoreAuto(key, state); return ""; }
            catch { return " (auto-config restore had an issue)"; }
        }

        static string MergeBypass(string? existing)
        {
            // A pre-existing bare "*" bypass matches EVERYTHING and would make
            // the applied proxy a no-op (total direct bypass while routing
            // claims ON). Strip wildcard tokens fail-closed — the backup keeps
            // the original so Disable restores it exactly.
            string cleaned = "";
            try
            {
                var keep = new System.Collections.Generic.List<string>();
                foreach (var tok in (existing ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries))
                {
                    var t = (tok ?? "").Trim();
                    if (t.Length == 0) continue;
                    // "*." prefix wildcards ("*.corp") are kept (intranet
                    // intent) — Divert still drops their direct path under
                    // lockdown so they fail closed, not leaked. Only the
                    // global "*" is stripped here.
                    if (t == "*") continue;
                    keep.Add(t);
                }
                cleaned = string.Join(";", keep);
            }
            catch { cleaned = existing ?? ""; }
            var have = cleaned.Split(';', StringSplitOptions.RemoveEmptyEntries);
            var haveSet = new System.Collections.Generic.HashSet<string>(have, StringComparer.OrdinalIgnoreCase);
            var toAdd = new System.Collections.Generic.List<string>();
            foreach (var need in LoopbackBypass.Split(';'))
                if (!haveSet.Contains(need)) toAdd.Add(need);
            if (toAdd.Count == 0) return cleaned;
            return string.IsNullOrEmpty(cleaned) ? string.Join(";", toAdd) : cleaned + ";" + string.Join(";", toAdd);
        }

        static string? ReadAutoUrl(RegistryKey key)
        {
            try { return key.GetValue("AutoConfigURL", null) as string; }
            catch { return null; }
        }

        static int ReadAutoDetect(RegistryKey key)
        {
            try { return Convert.ToInt32(key.GetValue("AutoDetect", 0) ?? 0); }
            catch { return 0; }
        }

        // What WE leave behind: no PAC URL, auto-detect off-or-absent.
        static bool AutoIsOurs(RegistryKey key)
        {
            try
            {
                if (!string.IsNullOrEmpty(key.GetValue("AutoConfigURL", null) as string))
                    return false;
                var det = key.GetValue("AutoDetect", null);
                if (det != null && Convert.ToInt32(det) != 0) return false;
                return true;
            }
            catch { return false; }
        }

        static void ClearAuto(RegistryKey key)
        {
            try { key.DeleteValue("AutoConfigURL", throwOnMissingValue: false); } catch { }
            try
            {
                if (key.GetValue("AutoDetect", null) != null)
                    key.SetValue("AutoDetect", 0, RegistryValueKind.DWord);
            }
            catch { }
        }

        static void RestoreAuto(RegistryKey key, ManagedState? state)
        {
            try
            {
                if (state == null || !state.HasAutoBackup) return;
                if (string.IsNullOrEmpty(state.SavedAutoConfigUrl))
                {
                    try { key.DeleteValue("AutoConfigURL", throwOnMissingValue: false); } catch { }
                }
                else key.SetValue("AutoConfigURL", state.SavedAutoConfigUrl, RegistryValueKind.String);
                key.SetValue("AutoDetect", state.SavedAutoDetect, RegistryValueKind.DWord);
            }
            catch { }
        }

        static void Notify()
        {
            try
            {
                InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
                InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
            }
            catch {  }
        }
    }
}
