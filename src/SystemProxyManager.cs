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
        const string LoopbackBypass = "127.*;localhost;[::1]";

        const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
        const int INTERNET_OPTION_REFRESH = 37;

        [DllImport("wininet.dll", SetLastError = true)]
        static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

        record ProxyTriple(int Enabled, string Server, string Override);
        record ManagedState(ProxyTriple Saved, string AppliedServer, string AppliedOverride,
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
            var appliedServer = $"http=127.0.0.1:{bridgePort};https=127.0.0.1:{bridgePort};socks=127.0.0.1:{socksPort}";
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
            return recoveryNote != null ? recoveryNote + " " + msg : msg;
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

            WriteTriple(key, state.Saved);
            // Restore backed-up auto-config only if nobody set their own
            // mid-run (same compare-before-restore philosophy as the triple).
            // Ancient states without a backup leave auto-config untouched.
            string autoNote = "";
            if (state.HasAutoBackup)
            {
                if (AutoIsOurs(key))
                {
                    try { RestoreAuto(key, state); } catch { autoNote = " (auto-config restore had an issue)"; }
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
            return "Routing OFF: previous system proxy settings restored." + autoNote;
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
                    WriteTriple(key, state.Saved);
                    if (state.HasAutoBackup)
                    {
                        try { if (AutoIsOurs(key)) RestoreAuto(key, state); } catch { }
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
                return JsonSerializer.Deserialize<ManagedState>(json);
            }
            catch { return null; }
        }

        static void WriteState(RegistryKey key, ManagedState state)
        {
            key.SetValue(StateValue, JsonSerializer.Serialize(state), RegistryValueKind.String);
            key.SetValue(ManagedValue, 1, RegistryValueKind.DWord);
        }

        static void ClearMarker(RegistryKey key)
        {
            try { key.DeleteValue(ManagedValue, throwOnMissingValue: false); } catch { }
            try { key.DeleteValue(StateValue, throwOnMissingValue: false); } catch { }
        }

        static string MergeBypass(string? existing)
        {
            var have = (existing ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries);
            var haveSet = new System.Collections.Generic.HashSet<string>(have, StringComparer.OrdinalIgnoreCase);
            var toAdd = new System.Collections.Generic.List<string>();
            foreach (var need in LoopbackBypass.Split(';'))
                if (!haveSet.Contains(need)) toAdd.Add(need);
            if (toAdd.Count == 0) return existing ?? "";
            return string.IsNullOrEmpty(existing) ? string.Join(";", toAdd) : existing + ";" + string.Join(";", toAdd);
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
