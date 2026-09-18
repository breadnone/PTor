using System;
using System.IO;
using System.Text.Json;

namespace PTor
{

    public class AppSettings
    {
        public string UserAgent { get; set; } = "";

        public List<string> BlockedDomains { get; set; } = new List<string>();

        public string HeaderSpoof { get; set; } = "";

        // Content policy enforced by PTor's own proxy relays.
        // BlockJs / BlockWebRtc / BlockCookies work on plain-HTTP directly.
        // MitmEnabled additionally decrypts CONNECT-tunneled HTTPS with a
        // locally-generated CA (free, self-signed, per-install) so the same
        // policy applies inside TLS; origins are still validated fail-closed
        // and everything still egresses via Tor. All OFF by default.
        public bool BlockJs { get; set; } = false;

        public bool BlockWebRtc { get; set; } = false;

        public bool BlockCookies { get; set; } = false;

        public bool MitmEnabled { get; set; } = false;

        public bool EnforceTorOnly { get; set; } = true;

        // Fresh installs start on direct guards: bridges (Snowflake/obfs4)
        // are flaky on many networks and must be an explicit choice.
        // Existing installs keep whatever they saved.
        public BridgeMode BridgeMode { get; set; } = BridgeMode.Direct;

        public List<string> CustomBridgeLines { get; set; } = new List<string>();

        public bool StableExitEnabled { get; set; } = false;

        // Circuit reuse lifetime, seconds (torrc MaxCircuitDirtiness).
        // 600 = Tor default (10 min). Sanitized on load: 60..86400.
        public int CircuitDirtinessSec { get; set; } = 600;

        // Stream retry timeout, seconds (torrc CircuitStreamTimeout): how
        // long until Tor detaches a stream from a sluggish circuit and tries
        // a new one. 0 = Tor's internal schedule (tor default).
        // Sanitized on load: 0..600.
        public int CircuitStreamTimeoutSec { get; set; } = 0;

        // Restrictive local firewall (torrc FascistFirewall): guard links
        // only on ports 80/443. Off by default.
        public bool RestrictiveFirewallOnly { get; set; } = false;

        // Windows logon startup (HKCU Run entry, minimized to tray).
        // Off by default: a fresh install must never surprise the user with
        // a resident on every boot. Existing installs keep whatever they saved
        // (missing field deserializes to false = off).
        public bool StartOnStartup { get; set; } = false;

        public bool ExitGeoEnabled { get; set; } = false;

        public string ExitRegion { get; set; } = "Western Europe";

        public string ExitCustomCountries { get; set; } = "";

        // Circuit pin (anti IP-hop): pin Entry/Middle/Exit to specific
        // relay fingerprints or nicknames (torrc EntryNodes/MiddleNodes/
        // ExitNodes + StrictNodes 1 + huge MaxCircuitDirtiness +
        // EnforceDistinctSubnets 0). OFF by
        // default; when ON it overrides stable mode, circuit lifetime,
        // exit geography, and scheduled rotation (see TorProcessManager /
        // TorEngine for the enforcement points).
        public bool PinnedCircuitEnabled { get; set; } = false;

        public string PinnedEntryNodes { get; set; } = "";

        public string PinnedMiddleNodes { get; set; } = "";

        public string PinnedExitNodes { get; set; } = "";

        static string SettingsPath()
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PTor");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "settings.json");
        }

        // settings.json is small (<4KB in practice): anything this big is
        // not ours (planted/corrupt) and must not be slurped into memory.
        internal const long MaxSettingsBytes = 256 * 1024;

        public static AppSettings Load()
        {
            try { return LoadFrom(SettingsPath()); }
            catch { return new AppSettings(); }
        }

        // Explicit-path twin for tests; same total contract.
        internal static AppSettings LoadFrom(string? path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path)) return new AppSettings();
                string full;
                try { full = System.IO.Path.GetFullPath(path); }
                catch { return new AppSettings(); }
                if (!File.Exists(full)) return new AppSettings();
                var text = SafeFiles.ReadAllTextCapped(full, MaxSettingsBytes);
                if (text == null) return new AppSettings();
                AppSettings s;
                try
                {
                    s = JsonSerializer.Deserialize<AppSettings>(text) ?? new AppSettings();
                }
                catch
                {
                    // Corrupt but readable: quarantine the bad file (timestamped
                    // .bak, pruned to 3) instead of silently discarding the
                    // user's bridges/pins/blocklist, then start from defaults.
                    try { QuarantineCorrupt(full); } catch { }
                    return new AppSettings();
                }
                try { s.Sanitize(); } catch { }
                return s;
            }
            catch { return new AppSettings(); }
        }

        internal static void QuarantineCorrupt(string full)
        {
            try
            {
                var dir = System.IO.Path.GetDirectoryName(full);
                if (string.IsNullOrEmpty(dir)) return;
                var bak = System.IO.Path.Combine(dir,
                    System.IO.Path.GetFileName(full) + ".corrupt-" +
                    DateTime.UtcNow.ToString("yyyyMMdd_HHmmss") + ".bak");
                try { File.Move(full, bak); }
                catch { return; }
                // Prune old quarantines so a permanently-broken writer can't
                // fill the disk one .bak per boot (we moved the file away, so
                // a healthy next save stops the cycle anyway).
                try
                {
                    var prefix = System.IO.Path.GetFileName(full) + ".corrupt-";
                    var stale = new List<string>(Directory.GetFiles(dir, prefix + "*.bak"));
                    stale.Sort(StringComparer.Ordinal);
                    for (var i = 0; i < stale.Count - 3; i++)
                        try { File.Delete(stale[i]); } catch { }
                }
                catch { }
            }
            catch { }
        }

        // Clamp hand-editable values back into range (a garbage number in
        // settings.json must reset that field, never break a start).
        public void Sanitize()
        {
            try { CircuitDirtinessSec = TorProcessManager.SanitizeDirtinessSec(CircuitDirtinessSec); }
            catch { CircuitDirtinessSec = 600; }
            try { CircuitStreamTimeoutSec = TorProcessManager.SanitizeStreamTimeoutSec(CircuitStreamTimeoutSec); }
            catch { CircuitStreamTimeoutSec = 0; }
            // A stale/unknown bridge mode (hand-edited or from another
            // version) must fall back to direct guards, never into the
            // custom-lines path with no lines (which fail-closes every boot
            // into an unusable "no bridges" start with no obvious cause).
            try { if (!Enum.IsDefined(typeof(BridgeMode), BridgeMode)) BridgeMode = BridgeMode.Direct; }
            catch { BridgeMode = BridgeMode.Direct; }
            // Explicit JSON nulls (hand-edited "BlockedDomains": null) must
            // not NRE every consumer: collapse to empty lists here.
            try { BlockedDomains ??= new List<string>(); } catch { BlockedDomains = new List<string>(); }
            try { CustomBridgeLines ??= new List<string>(); } catch { CustomBridgeLines = new List<string>(); }
            try { PinnedEntryNodes ??= ""; } catch { PinnedEntryNodes = ""; }
            try { PinnedMiddleNodes ??= ""; } catch { PinnedMiddleNodes = ""; }
            try { PinnedExitNodes ??= ""; } catch { PinnedExitNodes = ""; }
        }

        public void Save()
        {
            // Atomic via SafeFiles: a hard crash mid-write never leaves a
            // truncated settings.json (which would reset all user config on
            // next load). Failure keeps the previous good file.
            try { SafeFiles.WriteAllTextAtomic(SettingsPath(), JsonSerializer.Serialize(this)); }
            catch { }
        }
    }
}
