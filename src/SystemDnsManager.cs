using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Win32;

namespace PTor
{

    // Points interface DNS at 127.0.0.1 with exact backup/restore: read-back
    // verify on apply, compare-before-restore on teardown, divergence
    // detection, crash-persistent marker. HKLM: admin required.
    public class SystemDnsManager
    {
        const string IfaceBase = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
        const string StoreBase = @"SOFTWARE\PTor\Dns";
        const string ManagedValue = "Managed";
        const string BackupPrefix = "Backup_";
        const string BackupKindPrefix = "BackupKind_";
        public const string LoopbackDns = "127.0.0.1";

        public record DnsSnapshot(bool Managed, int InterfaceCount);

        public DnsSnapshot GetSnapshot()
        {
            try
            {
                using var store = Registry.LocalMachine.OpenSubKey(StoreBase, writable: false);
                var managed = store != null && Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) == 1;
                return new DnsSnapshot(managed, managed ? BackupNames(store!).Count : 0);
            }
            catch { return new DnsSnapshot(false, 0); }
        }

        // Only backed-up interfaces are tracked; newcomers (VPN dial-up) keep
        // their DNS, but the packet layer drops their direct-53 bypasses: fail-closed.
        public bool MatchesApplied()
        {
            try
            {
                using var store = Registry.LocalMachine.OpenSubKey(StoreBase, writable: false);
                if (store == null || Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) != 1)
                    return false;
                using var ifaces = Registry.LocalMachine.OpenSubKey(IfaceBase, writable: false);
                if (ifaces == null) return false;
                foreach (var guid in BackupNames(store))
                {
                    using var key = ifaces.OpenSubKey(guid, writable: false);
                    if (key == null) continue; // interface vanished: nothing to diverge
                    if (!string.Equals(key.GetValue("NameServer", "") as string, LoopbackDns, StringComparison.Ordinal))
                        return false;
                }
                return true;
            }
            catch { return false; }
        }

        public string Enable()
        {
            if (!AdminHelper.IsAdministrator())
                throw new NeedAdminException("Pointing system DNS at Tor needs administrator rights — restart PTor as administrator.");
            using var ifaces = Registry.LocalMachine.OpenSubKey(IfaceBase, writable: true)
                ?? throw new InvalidOperationException("Could not open interface DNS registry for writing.");
            using var store = Registry.LocalMachine.CreateSubKey(StoreBase, writable: true)
                ?? throw new InvalidOperationException("Could not open HKLM\\SOFTWARE\\PTor\\Dns for writing.");

            if (Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) == 1)
                Recover(store, ifaces);

            var guids = ifaces.GetSubKeyNames();
            foreach (var guid in guids)
                BackupOne(store, ifaces, guid);

            foreach (var guid in guids)
            {
                using var key = ifaces.OpenSubKey(guid, writable: true);
                key?.SetValue("NameServer", LoopbackDns, RegistryValueKind.String);
            }
            store.SetValue(ManagedValue, 1, RegistryValueKind.DWord);
            FlushDns();

            foreach (var guid in guids)
            {
                using var key = ifaces.OpenSubKey(guid, writable: false);
                var back = key?.GetValue("NameServer", "") as string;
                if (!string.Equals(back, LoopbackDns, StringComparison.Ordinal))
                {
                    try { RestoreLocked(store, ifaces, out _); } catch { }
                    throw new InvalidOperationException(
                        $"DNS swap did not stick on interface {guid} — rolled back, system DNS untouched. " +
                        "Something is reverting HKLM DNS changes (group policy, MDM, or a security tool).");
                }
            }
            return $"DNS via Tor: {guids.Length} interface(s) now resolve through 127.0.0.1 (Tor DNSPort). Direct port-53 bypasses are dropped at the packet layer.";
        }

        public string Disable()
        {
            using var store = Registry.LocalMachine.OpenSubKey(StoreBase, writable: true);
            if (store == null || Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) != 1)
                return "System DNS was not managed by PTor — nothing to restore.";
            using var ifaces = Registry.LocalMachine.OpenSubKey(IfaceBase, writable: true);
            if (ifaces == null)
            {
                try { ClearMarker(store); } catch { }
                return "Interface DNS registry unreadable — marker cleared, values left as-is.";
            }
            var (restored, left) = RestoreLocked(store, ifaces, out _);
            FlushDns();
            if (left.Count == 0)
                return $"DNS restored: previous resolver settings put back on {restored} interface(s).";
            return $"DNS restore: {restored} interface(s) restored; left {left.Count} you/VPN changed mid-run untouched ({string.Join(", ", left)}).";
        }

        public bool WasLeftManaged()
        {
            try
            {
                using var store = Registry.LocalMachine.OpenSubKey(StoreBase, writable: false);
                return store != null && Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) == 1;
            }
            catch { return false; }
        }

        static List<string> BackupNames(RegistryKey store)
        {
            var out_ = new List<string>();
            try
            {
                foreach (var name in store.GetValueNames())
                    if (name.StartsWith(BackupPrefix, StringComparison.Ordinal))
                        out_.Add(name.Substring(BackupPrefix.Length));
            }
            catch { }
            return out_;
        }

        static void BackupOne(RegistryKey store, RegistryKey ifaces, string guid)
        {
            try
            {
                using var key = ifaces.OpenSubKey(guid, writable: false);
                if (key == null) return;
                var names = key.GetValueNames();
                if (names.Contains("NameServer"))
                {
                    store.SetValue(BackupPrefix + guid, key.GetValue("NameServer", "") as string ?? "", RegistryValueKind.String);
                    // Preserve KIND too (wrong kind on restore corrupts the entry).
                    var kind = RegistryValueKind.String;
                    try { kind = key.GetValueKind("NameServer"); } catch { }
                    store.SetValue(BackupKindPrefix + guid, (int)kind, RegistryValueKind.DWord);
                }
                // Absent value => no backup entry => delete-on-restore (DHCP back).
            }
            catch { }
        }

        // Only values still reading our marker are touched.
        static (int restored, List<string> left) RestoreLocked(RegistryKey store, RegistryKey ifaces, out bool _)
        {
            _ = false;
            var restored = 0;
            var left = new List<string>();
            List<string> guids;
            try { guids = ifaces.GetSubKeyNames().ToList(); }
            catch { guids = new List<string>(); }
            var backedUp = new HashSet<string>(BackupNames(store), StringComparer.OrdinalIgnoreCase);
            foreach (var guid in guids)
            {
                RegistryKey? key = null;
                try
                {
                    key = ifaces.OpenSubKey(guid, writable: true);
                    if (key == null) continue;
                    var cur = key.GetValue("NameServer", "") as string;
                    if (!string.Equals(cur, LoopbackDns, StringComparison.Ordinal))
                    {
                        if (backedUp.Contains(guid)) left.Add(guid);
                        continue;
                    }
                    var backupName = BackupPrefix + guid;
                    var hadBackup = store.GetValueNames().Contains(backupName);
                    if (hadBackup)
                    {
                        var kind = RegistryValueKind.String;
                        try
                        {
                            var rawKind = Convert.ToInt32(store.GetValue(BackupKindPrefix + guid, (int)RegistryValueKind.String) ?? (int)RegistryValueKind.String);
                            if (Enum.IsDefined(typeof(RegistryValueKind), rawKind))
                                kind = (RegistryValueKind)rawKind;
                        }
                        catch { }
                        key.SetValue("NameServer", (store.GetValue(backupName, "") as string) ?? "", kind);
                    }
                    else
                        try { key.DeleteValue("NameServer", throwOnMissingValue: false); } catch { }
                    restored++;
                }
                catch { left.Add(guid + " (error)"); }
                finally { try { key?.Dispose(); } catch { } }
            }
            try { ClearMarker(store); } catch { }
            return (restored, left);
        }

        static string? Recover(RegistryKey store, RegistryKey ifaces)
        {
            try
            {
                var (restored, _) = RestoreLocked(store, ifaces, out _);
                return restored > 0
                    ? $"Recovered: previous run died with Tor-DNS on — resolver settings restored on {restored} interface(s) first."
                    : "Recovered: stale Tor-DNS marker cleared (settings were already changed).";
            }
            catch { return null; }
        }

        static void ClearMarker(RegistryKey store)
        {
            List<string> names;
            try { names = store.GetValueNames().ToList(); } catch { return; }
            foreach (var n in names)
            {
                if (n == ManagedValue || n.StartsWith(BackupPrefix, StringComparison.Ordinal) || n.StartsWith(BackupKindPrefix, StringComparison.Ordinal))
                    try { store.DeleteValue(n, throwOnMissingValue: false); } catch { }
            }
        }

        static void FlushDns()
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                });
                if (p == null) return;
                p.WaitForExit(15000);
            }
            catch { }
        }
    }
}
