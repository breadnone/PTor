using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Win32;

namespace PTor
{

    // Points interface DNS at loopback (127.0.0.1 + ::1) with exact
    // backup/restore: read-back verify on apply, compare-before-restore on
    // teardown, divergence detection, crash-persistent marker. HKLM: admin
    // required. Both families are managed: Tcpip (IPv4) always, Tcpip6
    // (IPv6) when requested AND present — IPv6 resolvers left at ISP values
    // would leak hostnames around Tor (the v4-only gap). Backups live under
    // distinct Backup_/Backup6_ (+Kind) names so v4/v6 restores never collide.
    public class SystemDnsManager
    {
        const string IfaceBase = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
        const string Iface6Base = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";
        const string StoreBase = @"SOFTWARE\PTor\Dns";
        const string ManagedValue = "Managed";
        const string Ipv6AppliedValue = "Ipv6Applied";
        const string BackupPrefix = "Backup_";
        const string BackupKindPrefix = "BackupKind_";
        const string Backup6Prefix = "Backup6_";
        const string BackupKind6Prefix = "BackupKind6_";
        // Mid-run intent memory (see ReassertApplied/RestoreFamily): when the
        // strict reassert stomps a diverged interface back to loopback, the
        // stomped value is recorded here (overwritten every stomp: latest
        // intent wins) so the exit restore puts back what the user most
        // recently had — not the stale pre-run backup.
        const string DivergedPrefix = "Diverged_";
        const string DivergedKindPrefix = "DivergedKind_";
        const string Diverged6Prefix = "Diverged6_";
        const string DivergedKind6Prefix = "DivergedKind6_";
        public const string LoopbackDns = "127.0.0.1";
        public const string LoopbackDns6 = "::1";

        public record DnsSnapshot(bool Managed, int InterfaceCount);

        // One-interface restore policy shared by Disable (managed path),
        // the marker-loss sweep below, and the rescue script's documented
        // contract — one ground truth, no drift:
        //   Leave         — not ours to touch (not loopback, or unmanaged
        //                   loopback with no backup: explicit-consent rescue
        //                   script only, never automatic exit code).
        //   RestoreBackup — still ours with a good recorded original: put it back.
        //   RevertDhcp    — ours but the original is unrecoverable (poisoned
        //                   backup, or managed with no backup): delete
        //                   NameServer so DHCP gives working internet instead
        //                   of a dead loopback resolver.
        public enum DnsRestoreAction { Leave, RestoreBackup, RevertDhcp }

        public static DnsRestoreAction DecideInterfaceRestore(bool managed, string? current, bool haveBackup, string? savedBackup, string loopback)
        {
            if (!string.Equals(current, loopback, StringComparison.Ordinal))
                return DnsRestoreAction.Leave;
            if (haveBackup)
                return string.Equals(savedBackup, loopback, StringComparison.Ordinal)
                    ? DnsRestoreAction.RevertDhcp
                    : DnsRestoreAction.RestoreBackup;
            return managed ? DnsRestoreAction.RevertDhcp : DnsRestoreAction.Leave;
        }

        public DnsSnapshot GetSnapshot()
        {
            try
            {
                using var store = Registry.LocalMachine.OpenSubKey(StoreBase, writable: false);
                var managed = store != null && Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) == 1;
                return new DnsSnapshot(managed, managed ? BackupNames(store!, BackupPrefix).Count + BackupNames(store!, Backup6Prefix).Count : 0);
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
                foreach (var guid in BackupNames(store, BackupPrefix))
                {
                    using var key = ifaces.OpenSubKey(guid, writable: false);
                    if (key == null) continue; // interface vanished: nothing to diverge
                    if (!string.Equals(key.GetValue("NameServer", "") as string, LoopbackDns, StringComparison.Ordinal))
                        return false;
                }
                // v6 only when this run actually applied it (see Enable):
                // a v4-only run (no ::1 listener) must not fail the check.
                var v6Applied = Convert.ToInt32(store.GetValue(Ipv6AppliedValue, 0) ?? 0) == 1;
                if (v6Applied)
                {
                    using var ifaces6 = Registry.LocalMachine.OpenSubKey(Iface6Base, writable: false);
                    if (ifaces6 == null) return false;
                    foreach (var guid in BackupNames(store, Backup6Prefix))
                    {
                        using var key = ifaces6.OpenSubKey(guid, writable: false);
                        if (key == null) continue;
                        if (!string.Equals(key.GetValue("NameServer", "") as string, LoopbackDns6, StringComparison.Ordinal))
                            return false;
                    }
                }
                return true;
            }
            catch { return false; }
        }

        public string Enable(bool includeIpv6 = true)
        {
            if (!AdminHelper.IsAdministrator())
                throw new NeedAdminException("Pointing system DNS at Tor needs administrator rights — restart PTor as administrator.");
            using var ifaces = Registry.LocalMachine.OpenSubKey(IfaceBase, writable: true)
                ?? throw new InvalidOperationException("Could not open interface DNS registry for writing.");
            using var store = Registry.LocalMachine.CreateSubKey(StoreBase, writable: true)
                ?? throw new InvalidOperationException("Could not open HKLM\\SOFTWARE\\PTor\\Dns for writing.");

            if (Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) == 1)
                Recover(store, ifaces);

            // v6 is best-effort: the key may be absent (IPv6-less stack), and
            // the caller passes false when no ::1 listener could bind (a ::1
            // resolver with nothing answering breaks DNS — worse than a
            // divert-covered leak, and the packet layer still drops direct-53).
            RegistryKey? ifaces6 = null;
            try { ifaces6 = includeIpv6 ? Registry.LocalMachine.OpenSubKey(Iface6Base, writable: true) : null; }
            catch { ifaces6 = null; }
            try
            {
                var guids = ifaces.GetSubKeyNames();
                var guids6 = ifaces6 != null ? ifaces6.GetSubKeyNames() : Array.Empty<string>();
                // Scrub poisoned backups left by an older build / partial
                // rescue (a backup whose value IS loopback "restores"
                // loopback right back and can never fix DNS). They revert to
                // DHCP (delete) on restore instead.
                try { ScrubPoisonedBackups(store); } catch { }
                foreach (var guid in guids)
                    BackupOne(store, ifaces, guid, BackupPrefix, BackupKindPrefix, LoopbackDns);
                foreach (var guid in guids6)
                    BackupOne(store, ifaces6!, guid, Backup6Prefix, BackupKind6Prefix, LoopbackDns6);

                // Atomicity: an exception mid-loop (registry ACL, disappearing
                // NIC) would otherwise strand some interfaces at loopback with
                // Managed==0 — invisible to Disable/rescue/uninstall. Roll back
                // applied interfaces and rethrow.
                var applied = new List<string>();
                var applied6 = new List<string>();
                try
                {
                    foreach (var guid in guids)
                    {
                        using var key = ifaces.OpenSubKey(guid, writable: true);
                        key?.SetValue("NameServer", LoopbackDns, RegistryValueKind.String);
                        applied.Add(guid);
                    }
                    if (ifaces6 != null)
                    {
                        foreach (var guid in guids6)
                        {
                            using var key = ifaces6.OpenSubKey(guid, writable: true);
                            key?.SetValue("NameServer", LoopbackDns6, RegistryValueKind.String);
                            applied6.Add(guid);
                        }
                    }
                }
                catch
                {
                    try { RollbackList(store, ifaces, applied, BackupPrefix, BackupKindPrefix, LoopbackDns); } catch { }
                    try { if (ifaces6 != null) RollbackList(store, ifaces6, applied6, Backup6Prefix, BackupKind6Prefix, LoopbackDns6); } catch { }
                    try { ClearMarker(store); } catch { }
                    throw;
                }
                store.SetValue(ManagedValue, 1, RegistryValueKind.DWord);
                store.SetValue(Ipv6AppliedValue, guids6.Length > 0 ? 1 : 0, RegistryValueKind.DWord);
                FlushDns();

                foreach (var guid in guids)
                {
                    using var key = ifaces.OpenSubKey(guid, writable: false);
                    var back = key?.GetValue("NameServer", "") as string;
                    if (!string.Equals(back, LoopbackDns, StringComparison.Ordinal))
                    {
                        try { RestoreLocked(store, ifaces, ifaces6); } catch { }
                        throw new InvalidOperationException(
                            $"DNS swap did not stick on interface {guid} — rolled back, system DNS untouched. " +
                            "Something is reverting HKLM DNS changes (group policy, MDM, or a security tool).");
                    }
                }
                if (ifaces6 != null)
                {
                    foreach (var guid in guids6)
                    {
                        using var key = ifaces6.OpenSubKey(guid, writable: false);
                        var back = key?.GetValue("NameServer", "") as string;
                        if (!string.Equals(back, LoopbackDns6, StringComparison.Ordinal))
                        {
                            try { RestoreLocked(store, ifaces, ifaces6); } catch { }
                            throw new InvalidOperationException(
                                $"DNS swap did not stick on IPv6 interface {guid} — rolled back, system DNS untouched. " +
                                "Something is reverting HKLM DNS changes (group policy, MDM, or a security tool).");
                        }
                    }
                }
                return guids6.Length > 0
                    ? $"DNS via Tor: {guids.Length} IPv4 + {guids6.Length} IPv6 interface(s) now resolve through loopback (Tor DNSPort). Direct port-53 bypasses are dropped at the packet layer."
                    : $"DNS via Tor: {guids.Length} interface(s) now resolve through 127.0.0.1 (Tor DNSPort). Direct port-53 bypasses are dropped at the packet layer.";
            }
            finally { try { ifaces6?.Dispose(); } catch { } }
        }

        // Mid-run repair for interfaces that appeared AFTER Enable (VPN
        // dial-up, Wi-Fi reconnect, USB tether, new vNIC): they still carry
        // ISP resolvers, so they bypass Tor DNS. While lockdown holds their
        // direct port-53 is dropped at the packet layer (breakage, not a
        // leak — this repair fixes that breakage); without lockdown it would
        // leak hostnames outright. Backs each newcomer up (so Disable
        // restores it exactly) and points it at loopback. No-op when not
        // managed. Returns a human note when it fixed anything, else null.
        // Never throws. Called on the link-tick cadence while enforcement
        // owns DNS.
        public string? ReassertNewInterfaces()
        {
            try
            {
                using var store = Registry.LocalMachine.OpenSubKey(StoreBase, writable: true);
                if (store == null || Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) != 1)
                    return null;
                var v6Applied = Convert.ToInt32(store.GetValue(Ipv6AppliedValue, 0) ?? 0) == 1;
                using var ifaces = Registry.LocalMachine.OpenSubKey(IfaceBase, writable: true);
                if (ifaces == null) return null;
                RegistryKey? ifaces6 = null;
                try { ifaces6 = v6Applied ? Registry.LocalMachine.OpenSubKey(Iface6Base, writable: true) : null; }
                catch { ifaces6 = null; }
                try
                {
                    var fixed4 = ReassertFamily(store, ifaces, LoopbackDns, BackupPrefix, BackupKindPrefix);
                    var fixed6 = 0;
                    try { if (ifaces6 != null) fixed6 = ReassertFamily(store, ifaces6, LoopbackDns6, Backup6Prefix, BackupKind6Prefix); } catch { }
                    if (fixed4 + fixed6 == 0) return null;
                    try { FlushDns(); } catch { }
                    return $"DNS: {fixed4 + fixed6} new interface(s) appeared mid-run and now resolve through Tor DNS (loopback).";
                }
                finally { try { ifaces6?.Dispose(); } catch { } }
            }
            catch { return null; }
        }

        static int ReassertFamily(RegistryKey store, RegistryKey ifaces, string loopback, string backupPrefix, string backupKindPrefix)
        {
            var fixed_ = 0;
            try
            {
                HashSet<string> backed;
                try { backed = new HashSet<string>(BackupNames(store, backupPrefix), StringComparer.OrdinalIgnoreCase); }
                catch { return 0; }
                string[] guids;
                try { guids = ifaces.GetSubKeyNames(); }
                catch { return 0; }
                foreach (var guid in guids)
                {
                    try
                    {
                        if (backed.Contains(guid)) continue;
                        using var key = ifaces.OpenSubKey(guid, writable: true);
                        if (key == null) continue;
                        var cur = key.GetValue("NameServer", "") as string;
                        // Always record the backup first, even when the value
                        // already reads loopback (e.g. the user's own DNS on
                        // 127.0.0.1): Disable restores the recorded value
                        // instead of deleting a NameServer it never set.
                        // (BackupOne keeps a pre-existing backup and never
                        // records loopback as an "original" — see its notes.)
                        BackupOne(store, ifaces, guid, backupPrefix, backupKindPrefix, loopback);
                        if (string.Equals(cur, loopback, StringComparison.Ordinal)) continue;
                        key.SetValue("NameServer", loopback, RegistryValueKind.String);
                        fixed_++;
                    }
                    catch { }
                }
            }
            catch { }
            return fixed_;
        }

        // Fail-closed repair for mid-run DNS overwrites (VPN/GPO/MDM):
        // rewrites loopback on backed-up interfaces that diverged plus any
        // newcomers, without touching backups. The stomped value is recorded
        // (RecordDiverged, latest wins) so Disable restores the user's most
        // recent setting instead of the stale pre-run backup — stomping must
        // never destroy evidence of user intent. Returns true when it fixed
        // anything. Never throws. Requires admin (HKLM). Strict-mode only.
        public bool ReassertApplied()
        {
            try
            {
                if (!AdminHelper.IsAdministrator()) return false;
                using var store = Registry.LocalMachine.OpenSubKey(StoreBase, writable: true);
                if (store == null || Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) != 1)
                    return false;
                var fixed_ = 0;
                try
                {
                    using var ifaces = Registry.LocalMachine.OpenSubKey(IfaceBase, writable: true);
                    if (ifaces != null)
                    {
                        var backed = new HashSet<string>(BackupNames(store, BackupPrefix), StringComparer.OrdinalIgnoreCase);
                        foreach (var guid in ifaces.GetSubKeyNames())
                        {
                            if (!backed.Contains(guid)) continue;
                            try
                            {
                                using var key = ifaces.OpenSubKey(guid, writable: true);
                                if (key == null) continue;
                                var cur = key.GetValue("NameServer", "") as string;
                                if (!string.Equals(cur, LoopbackDns, StringComparison.Ordinal))
                                {
                                    try { RecordDiverged(store, key, guid, DivergedPrefix, DivergedKindPrefix, cur); } catch { }
                                    key.SetValue("NameServer", LoopbackDns, RegistryValueKind.String);
                                    fixed_++;
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
                try
                {
                    var v6Applied = Convert.ToInt32(store.GetValue(Ipv6AppliedValue, 0) ?? 0) == 1;
                    if (v6Applied)
                    {
                        using var ifaces6 = Registry.LocalMachine.OpenSubKey(Iface6Base, writable: true);
                        if (ifaces6 != null)
                        {
                            var backed6 = new HashSet<string>(BackupNames(store, Backup6Prefix), StringComparer.OrdinalIgnoreCase);
                            foreach (var guid in ifaces6.GetSubKeyNames())
                            {
                                if (!backed6.Contains(guid)) continue;
                                try
                                {
                                    using var key = ifaces6.OpenSubKey(guid, writable: true);
                                    if (key == null) continue;
                                    var cur = key.GetValue("NameServer", "") as string;
                                    if (!string.Equals(cur, LoopbackDns6, StringComparison.Ordinal))
                                    {
                                        try { RecordDiverged(store, key, guid, Diverged6Prefix, DivergedKind6Prefix, cur); } catch { }
                                        key.SetValue("NameServer", LoopbackDns6, RegistryValueKind.String);
                                        fixed_++;
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                }
                catch { }
                try
                {
                    var note = ReassertNewInterfaces();
                    if (!string.IsNullOrEmpty(note)) fixed_++;
                }
                catch { }
                if (fixed_ > 0) { try { FlushDns(); } catch { } return true; }
                return false;
            }
            catch { return false; }
        }

        public string Disable()
        {
            using var store = Registry.LocalMachine.OpenSubKey(StoreBase, writable: true);
            if (store == null || Convert.ToInt32(store.GetValue(ManagedValue, 0) ?? 0) != 1)
                return SweepOrphaned(store);
            using var ifaces = Registry.LocalMachine.OpenSubKey(IfaceBase, writable: true);
            RegistryKey? ifaces6 = null;
            try { ifaces6 = Registry.LocalMachine.OpenSubKey(Iface6Base, writable: true); }
            catch { ifaces6 = null; }
            try
            {
                if (ifaces == null)
                {
                    try { ClearMarker(store); } catch { }
                    return "Interface DNS registry unreadable — marker cleared, values left as-is.";
                }
                var (restored, left, poisoned, divergedCount) = RestoreLocked(store, ifaces, ifaces6);
                FlushDns();
                var poisonNote = poisoned > 0
                    ? $" ({poisoned} had corrupted backups from an older run and were reverted to DHCP instead — working internet, but a previously-static DNS on those interfaces needs re-entering.)"
                    : "";
                var divergedNote = divergedCount > 0
                    ? $" ({divergedCount} restored to the resolver you set mid-run instead of the pre-run value.)"
                    : "";
                if (left.Count == 0)
                    return $"DNS restored: previous resolver settings put back on {restored} interface(s).{poisonNote}{divergedNote}";
                return $"DNS restore: {restored} interface(s) restored; left {left.Count} you/VPN changed mid-run untouched ({string.Join(", ", left)}).{poisonNote}{divergedNote}";
            }
            finally { try { ifaces6?.Dispose(); } catch { } }
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

        static List<string> BackupNames(RegistryKey store, string prefix)
        {
            var out_ = new List<string>();
            try
            {
                foreach (var name in store.GetValueNames())
                    if (name.StartsWith(prefix, StringComparison.Ordinal))
                        out_.Add(name.Substring(prefix.Length));
            }
            catch { }
            return out_;
        }

        static void BackupOne(RegistryKey store, RegistryKey ifaces, string guid, string backupPrefix, string backupKindPrefix, string loopback)
        {
            try
            {
                // First backup wins: a re-Enable while resolvers still read
                // loopback (stale marker cleared without a restore, partial
                // rescue, crash between restore and marker-clear) must never
                // overwrite the good "original" with loopback. Recording
                // loopback as the backup poisons the restore: Disable would
                // "restore" 127.0.0.1/::1 right back and the box stays
                // offline with a success message (and so does rescue).
                try
                {
                    if (Array.IndexOf(store.GetValueNames(), backupPrefix + guid) >= 0)
                        return;
                }
                catch { }
                using var key = ifaces.OpenSubKey(guid, writable: false);
                if (key == null) return;
                var names = key.GetValueNames();
                if (names.Contains("NameServer"))
                {
                    var cur = key.GetValue("NameServer", "") as string ?? "";
                    // No known original when already at loopback (a local
                    // resolver on 127.0.0.1 is indistinguishable from our
                    // mark): leave NO entry so restore reverts to DHCP
                    // (working internet) instead of loopback (broken).
                    if (string.Equals(cur, loopback, StringComparison.Ordinal))
                        return;
                    store.SetValue(backupPrefix + guid, cur, RegistryValueKind.String);
                    // Preserve KIND too (wrong kind on restore corrupts the entry).
                    var kind = RegistryValueKind.String;
                    try { kind = key.GetValueKind("NameServer"); } catch { }
                    store.SetValue(backupKindPrefix + guid, (int)kind, RegistryValueKind.DWord);
                }
                // Absent value => no backup entry => delete-on-restore (DHCP back).
            }
            catch { }
        }

        // Deletes backup entries whose recorded "original" IS loopback
        // (poison written by older builds): restoring them would put
        // loopback right back. After the scrub those interfaces revert to
        // DHCP (delete) on restore — working internet instead of broken.
        static void ScrubPoisonedBackups(RegistryKey store)
        {
            try
            {
                foreach (var n in store.GetValueNames().ToList())
                {
                    try
                    {
                        if (n.StartsWith(Backup6Prefix, StringComparison.Ordinal))
                        {
                            var v = store.GetValue(n, null) as string;
                            if (string.Equals(v, LoopbackDns6, StringComparison.Ordinal))
                            {
                                try { store.DeleteValue(n, throwOnMissingValue: false); } catch { }
                                try
                                {
                                    var guid = n.Substring(Backup6Prefix.Length);
                                    store.DeleteValue(BackupKind6Prefix + guid, throwOnMissingValue: false);
                                }
                                catch { }
                            }
                        }
                        else if (n.StartsWith(BackupPrefix, StringComparison.Ordinal))
                        {
                            var v = store.GetValue(n, null) as string;
                            if (string.Equals(v, LoopbackDns, StringComparison.Ordinal))
                            {
                                try { store.DeleteValue(n, throwOnMissingValue: false); } catch { }
                                try
                                {
                                    var guid = n.Substring(BackupPrefix.Length);
                                    store.DeleteValue(BackupKindPrefix + guid, throwOnMissingValue: false);
                                }
                                catch { }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        // Remembers a live value we are about to stomp back to loopback, so
        // the exit restore can put back the user's LATEST setting instead of
        // the stale pre-run backup. Overwritten on every stomp (latest intent
        // wins). A loopback/empty value is never recorded (it carries no
        // intent and must never be "restored"). Never throws.
        static void RecordDiverged(RegistryKey store, RegistryKey key, string guid, string divergedPrefix, string divergedKindPrefix, string? cur)
        {
            try
            {
                if (string.IsNullOrEmpty(cur)) return;
                store.SetValue(divergedPrefix + guid, cur, RegistryValueKind.String);
                var kind = RegistryValueKind.String;
                try { kind = key.GetValueKind("NameServer"); } catch { }
                store.SetValue(divergedKindPrefix + guid, (int)kind, RegistryValueKind.DWord);
            }
            catch { }
        }

        static void RollbackList(RegistryKey store, RegistryKey ifaces, List<string> applied, string backupPrefix, string backupKindPrefix, string loopback)
        {
            foreach (var guid in applied)
            {
                try
                {
                    using var key = ifaces.OpenSubKey(guid, writable: true);
                    if (key == null) continue;
                    var backupName = backupPrefix + guid;
                    if (Array.IndexOf(store.GetValueNames(), backupName) >= 0)
                    {
                        var saved = (store.GetValue(backupName, "") as string) ?? "";
                        // Poisoned backup (original recorded as loopback):
                        // revert to DHCP instead of re-applying loopback,
                        // and drop the poisoned entry.
                        if (string.Equals(saved, loopback, StringComparison.Ordinal))
                        {
                            try { key.DeleteValue("NameServer", throwOnMissingValue: false); } catch { }
                            try { store.DeleteValue(backupName, throwOnMissingValue: false); } catch { }
                            try { store.DeleteValue(backupKindPrefix + guid, throwOnMissingValue: false); } catch { }
                            continue;
                        }
                        var kind = RegistryValueKind.String;
                        try
                        {
                            var rawKind = Convert.ToInt32(store.GetValue(backupKindPrefix + guid, (int)RegistryValueKind.String) ?? (int)RegistryValueKind.String);
                            if (Enum.IsDefined(typeof(RegistryValueKind), rawKind))
                                kind = (RegistryValueKind)rawKind;
                        }
                        catch { }
                        key.SetValue("NameServer", saved, kind);
                    }
                    else
                    {
                        try { key.DeleteValue("NameServer", throwOnMissingValue: false); } catch { }
                    }
                }
                catch { }
            }
        }

        // Only values still reading our marker are touched.
        static (int restored, List<string> left, int poisoned, int diverged) RestoreLocked(RegistryKey store, RegistryKey ifaces, RegistryKey? ifaces6)
        {
            var restored = 0;
            var poisoned = 0;
            var diverged = 0;
            var left = new List<string>();
            RestoreFamily(store, ifaces, LoopbackDns, BackupPrefix, BackupKindPrefix, DivergedPrefix, DivergedKindPrefix, ref restored, ref poisoned, ref diverged, left);
            if (ifaces6 != null)
                RestoreFamily(store, ifaces6, LoopbackDns6, Backup6Prefix, BackupKind6Prefix, Diverged6Prefix, DivergedKind6Prefix, ref restored, ref poisoned, ref diverged, left);
            else
            {
                // v6 key gone (stack removed mid-run?): drop stale v6 backups
                // with the marker so they never accumulate.
                try
                {
                    foreach (var n in store.GetValueNames().ToList())
                        if (n.StartsWith(Backup6Prefix, StringComparison.Ordinal) || n.StartsWith(BackupKind6Prefix, StringComparison.Ordinal))
                            try { store.DeleteValue(n, throwOnMissingValue: false); } catch { }
                }
                catch { }
            }
            try { ClearMarker(store); } catch { }
            return (restored, left, poisoned, diverged);
        }

        static void RestoreFamily(RegistryKey store, RegistryKey ifaces, string loopback, string backupPrefix, string backupKindPrefix, string divergedPrefix, string divergedKindPrefix, ref int restored, ref int poisoned, ref int diverged, List<string> left)
        {
            List<string> guids;
            try { guids = ifaces.GetSubKeyNames().ToList(); }
            catch { guids = new List<string>(); }
            var backedUp = new HashSet<string>(BackupNames(store, backupPrefix), StringComparer.OrdinalIgnoreCase);
            foreach (var guid in guids)
            {
                RegistryKey? key = null;
                try
                {
                    key = ifaces.OpenSubKey(guid, writable: true);
                    if (key == null) continue;
                    var cur = key.GetValue("NameServer", "") as string;
                    var backupName = backupPrefix + guid;
                    var hadBackup = store.GetValueNames().Contains(backupName);
                    var saved = hadBackup ? (store.GetValue(backupName, "") as string) ?? "" : "";
                    // Latest-intent-wins: a mid-run user/VPN change that the
                    // strict reassert stomped back to loopback was recorded
                    // (RecordDiverged). The live value is still ours, but the
                    // setting the user most recently had is the diverged one
                    // — restore THAT, not the stale pre-run backup. A
                    // loopback/empty diverged record, or one identical to the
                    // backup, falls through to the normal policy below.
                    if (hadBackup && string.Equals(cur, loopback, StringComparison.Ordinal))
                    {
                        string? div = null;
                        try { div = store.GetValue(divergedPrefix + guid, null) as string; } catch { div = null; }
                        if (!string.IsNullOrEmpty(div)
                            && !string.Equals(div, loopback, StringComparison.Ordinal)
                            && !string.Equals(div, saved, StringComparison.Ordinal))
                        {
                            var dkind = RegistryValueKind.String;
                            try
                            {
                                var rawKind = Convert.ToInt32(store.GetValue(divergedKindPrefix + guid, (int)RegistryValueKind.String) ?? (int)RegistryValueKind.String);
                                if (Enum.IsDefined(typeof(RegistryValueKind), rawKind))
                                    dkind = (RegistryValueKind)rawKind;
                            }
                            catch { }
                            try { key.SetValue("NameServer", div, dkind); }
                            catch { div = null; }
                            if (div != null)
                            {
                                try { store.DeleteValue(backupName, throwOnMissingValue: false); } catch { }
                                try { store.DeleteValue(backupKindPrefix + guid, throwOnMissingValue: false); } catch { }
                                try { store.DeleteValue(divergedPrefix + guid, throwOnMissingValue: false); } catch { }
                                try { store.DeleteValue(divergedKindPrefix + guid, throwOnMissingValue: false); } catch { }
                                restored++;
                                diverged++;
                                continue;
                            }
                        }
                    }
                    // Single policy (managed path, so loopback with no backup
                    // still reverts to DHCP — see DecideInterfaceRestore).
                    switch (DecideInterfaceRestore(managed: true, current: cur, haveBackup: hadBackup, savedBackup: saved, loopback: loopback))
                    {
                        case DnsRestoreAction.Leave:
                            if (backedUp.Contains(guid)) left.Add(guid);
                            continue;
                        case DnsRestoreAction.RevertDhcp:
                            // Poisoned backup (an older build recorded loopback
                            // as the "original", or a partial rescue left one):
                            // revert to DHCP instead of re-applying loopback.
                            // Counted as restored: the interface is back on
                            // working DNS, even though the true original is
                            // unrecoverable (it was DHCP in the common case).
                            try { key.DeleteValue("NameServer", throwOnMissingValue: false); } catch { }
                            if (hadBackup)
                            {
                                try { store.DeleteValue(backupName, throwOnMissingValue: false); } catch { }
                                try { store.DeleteValue(backupKindPrefix + guid, throwOnMissingValue: false); } catch { }
                                poisoned++;
                            }
                            break;
                        default:
                        {
                            var kind = RegistryValueKind.String;
                            try
                            {
                                var rawKind = Convert.ToInt32(store.GetValue(backupKindPrefix + guid, (int)RegistryValueKind.String) ?? (int)RegistryValueKind.String);
                                if (Enum.IsDefined(typeof(RegistryValueKind), rawKind))
                                    kind = (RegistryValueKind)rawKind;
                            }
                            catch { }
                            key.SetValue("NameServer", saved, kind);
                            break;
                        }
                    }
                    restored++;
                }
                catch { left.Add(guid + " (error)"); }
                finally { try { key?.Dispose(); } catch { } }
            }
        }

        // Marker-loss repair for the exit path (mirrors rescue-internet.bat):
        // the Managed flag is already gone (crash between restore and
        // marker-clear, partial rescue, manual key deletion) yet interfaces
        // still point at Tor loopback and/or leftover backups remain.
        // Only backup-anchored loopback is fixed (provably ours — we recorded
        // an original for it); unmarked loopback with no backup is left for
        // the user-invoked rescue script, which runs with explicit consent.
        // Poisoned leftovers (backup IS loopback) can never restore correctly
        // and are dropped wherever found. Never throws.
        static string SweepOrphaned(RegistryKey? store)
        {
            const string notManaged = "System DNS was not managed by PTor — nothing to restore.";
            if (store == null) return notManaged;
            var restored = 0; var poisoned = 0; var scrubbed = 0;
            try
            {
                using var ifaces = Registry.LocalMachine.OpenSubKey(IfaceBase, writable: true);
                if (ifaces != null)
                    SweepOrphanedFamily(store, ifaces, LoopbackDns, BackupPrefix, BackupKindPrefix, DivergedPrefix, DivergedKindPrefix, ref restored, ref poisoned, ref scrubbed);
            }
            catch { }
            try
            {
                using var ifaces6 = Registry.LocalMachine.OpenSubKey(Iface6Base, writable: true);
                if (ifaces6 != null)
                    SweepOrphanedFamily(store, ifaces6, LoopbackDns6, Backup6Prefix, BackupKind6Prefix, Diverged6Prefix, DivergedKind6Prefix, ref restored, ref poisoned, ref scrubbed);
            }
            catch { }
            if (restored == 0 && scrubbed == 0) return notManaged;
            if (restored > 0) { try { FlushDns(); } catch { } }
            if (restored == 0)
                return $"System DNS was not managed by PTor — dropped {scrubbed} corrupted backup leftover(s) that could never restore correctly.";
            var poisonNote = poisoned > 0
                ? $" ({poisoned} had corrupted backups and were reverted to DHCP instead)"
                : "";
            var scrubNote = scrubbed > 0
                ? $" ({scrubbed} corrupted backup leftover(s) dropped)"
                : "";
            return $"DNS repair: marker was already gone but {restored} interface(s) still pointed at Tor loopback DNS — restored.{poisonNote}{scrubNote}";
        }

        static void SweepOrphanedFamily(RegistryKey store, RegistryKey ifaces, string loopback, string backupPrefix, string backupKindPrefix, string divergedPrefix, string divergedKindPrefix, ref int restored, ref int poisoned, ref int scrubbed)
        {
            HashSet<string> backed;
            try { backed = new HashSet<string>(BackupNames(store, backupPrefix), StringComparer.OrdinalIgnoreCase); }
            catch { return; }
            if (backed.Count == 0) return;
            HashSet<string> present;
            try { present = new HashSet<string>(ifaces.GetSubKeyNames(), StringComparer.OrdinalIgnoreCase); }
            catch { present = new HashSet<string>(StringComparer.OrdinalIgnoreCase); }
            foreach (var guid in backed)
            {
                try
                {
                    var backupName = backupPrefix + guid;
                    bool haveValue;
                    try { haveValue = Array.IndexOf(store.GetValueNames(), backupName) >= 0; }
                    catch { continue; }
                    if (!haveValue) continue;
                    var saved = (store.GetValue(backupName, null) as string) ?? "";
                    var isPoison = string.Equals(saved, loopback, StringComparison.Ordinal);
                    void DropBackup()
                    {
                        try { store.DeleteValue(backupName, throwOnMissingValue: false); } catch { }
                        try { store.DeleteValue(backupKindPrefix + guid, throwOnMissingValue: false); } catch { }
                        // A diverged record without its backup is an orphan
                        // that a future session could mistake for fresh user
                        // intent — drop it with the backup, always.
                        try { store.DeleteValue(divergedPrefix + guid, throwOnMissingValue: false); } catch { }
                        try { store.DeleteValue(divergedKindPrefix + guid, throwOnMissingValue: false); } catch { }
                    }
                    if (!present.Contains(guid))
                    {
                        // Interface vanished: its backup is dead weight.
                        DropBackup();
                        if (isPoison) scrubbed++;
                        continue;
                    }
                    using var key = ifaces.OpenSubKey(guid, writable: true);
                    if (key == null) continue;
                    var cur = key.GetValue("NameServer", "") as string;
                    // Same single policy, unmanaged: anchored loopback is
                    // fixed, unanchored loopback is left (rescue-script-only).
                    switch (DecideInterfaceRestore(managed: false, current: cur, haveBackup: true, savedBackup: saved, loopback: loopback))
                    {
                        case DnsRestoreAction.Leave:
                            // Live value isn't loopback: only poison is
                            // dropped (it can never restore correctly); a
                            // good backup may still be a valid original.
                            if (isPoison) { DropBackup(); scrubbed++; }
                            continue;
                        case DnsRestoreAction.RevertDhcp:
                            try { key.DeleteValue("NameServer", throwOnMissingValue: false); } catch { }
                            DropBackup();
                            poisoned++;
                            break;
                        default:
                        {
                            var kind = RegistryValueKind.String;
                            try
                            {
                                var rawKind = Convert.ToInt32(store.GetValue(backupKindPrefix + guid, (int)RegistryValueKind.String) ?? (int)RegistryValueKind.String);
                                if (Enum.IsDefined(typeof(RegistryValueKind), rawKind))
                                    kind = (RegistryValueKind)rawKind;
                            }
                            catch { }
                            try { key.SetValue("NameServer", saved, kind); }
                            catch { continue; } // keep the backup for next time
                            DropBackup();
                            break;
                        }
                    }
                    restored++;
                }
                catch { }
            }
        }

        // Read-only count of interfaces still pointing at Tor loopback DNS.
        // Unlike GetSnapshot (marker-only), this sees stranded loopback even
        // after the marker is gone — the exit verify step reports it instead
        // of claiming "system". Never throws.
        public int CountStrandedLoopback()
        {
            var n = 0;
            try
            {
                using var ifaces = Registry.LocalMachine.OpenSubKey(IfaceBase, writable: false);
                if (ifaces != null)
                    foreach (var guid in ifaces.GetSubKeyNames())
                    {
                        try
                        {
                            using var key = ifaces.OpenSubKey(guid, writable: false);
                            if (string.Equals(key?.GetValue("NameServer", "") as string, LoopbackDns, StringComparison.Ordinal))
                                n++;
                        }
                        catch { }
                    }
            }
            catch { }
            try
            {
                using var ifaces6 = Registry.LocalMachine.OpenSubKey(Iface6Base, writable: false);
                if (ifaces6 != null)
                    foreach (var guid in ifaces6.GetSubKeyNames())
                    {
                        try
                        {
                            using var key = ifaces6.OpenSubKey(guid, writable: false);
                            if (string.Equals(key?.GetValue("NameServer", "") as string, LoopbackDns6, StringComparison.Ordinal))
                                n++;
                        }
                        catch { }
                    }
            }
            catch { }
            return n;
        }

        static string? Recover(RegistryKey store, RegistryKey ifaces)
        {
            try
            {
                RegistryKey? ifaces6 = null;
                try { ifaces6 = Registry.LocalMachine.OpenSubKey(Iface6Base, writable: true); }
                catch { ifaces6 = null; }
                try
                {
                    var (restored, _, poisoned, _) = RestoreLocked(store, ifaces, ifaces6);
                    var poisonNote = poisoned > 0 ? $" ({poisoned} had corrupted backups, reverted to DHCP.)" : "";
                    return restored > 0
                        ? $"Recovered: previous run died with Tor-DNS on — resolver settings restored on {restored} interface(s) first.{poisonNote}"
                        : "Recovered: stale Tor-DNS marker cleared (settings were already changed).";
                }
                finally { try { ifaces6?.Dispose(); } catch { } }
            }
            catch { return null; }
        }

        static void ClearMarker(RegistryKey store)
        {
            List<string> names;
            try { names = store.GetValueNames().ToList(); } catch { return; }
            foreach (var n in names)
            {
                if (n == ManagedValue || n == Ipv6AppliedValue
                    || n.StartsWith(BackupPrefix, StringComparison.Ordinal) || n.StartsWith(BackupKindPrefix, StringComparison.Ordinal)
                    || n.StartsWith(Backup6Prefix, StringComparison.Ordinal) || n.StartsWith(BackupKind6Prefix, StringComparison.Ordinal)
                    || n.StartsWith(DivergedPrefix, StringComparison.Ordinal) || n.StartsWith(DivergedKindPrefix, StringComparison.Ordinal)
                    || n.StartsWith(Diverged6Prefix, StringComparison.Ordinal) || n.StartsWith(DivergedKind6Prefix, StringComparison.Ordinal))
                    try { store.DeleteValue(n, throwOnMissingValue: false); } catch { }
            }
        }

        static void FlushDns()
        {
            // Fire-and-forget courtesy: restored resolvers work for new
            // lookups without a flush (stale cache just expires). Never
            // WaitForExit here — the exit path must not park on a child
            // process. No stdout redirect (nothing drains it), no wait.
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = false,
                    RedirectStandardError = false
                });
                // No WaitForExit by design: instant return, OS reaps ipconfig.
            }
            catch { }
        }
    }
}
