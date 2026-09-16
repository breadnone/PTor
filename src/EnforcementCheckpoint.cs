using System;
using System.IO;
using System.Text.Json;

namespace PTor
{

    public record CheckpointData(
        DateTime CreatedUtc,
        string Reason,
        string DriverService,
        bool DriverFilesPresent,
        string ProxyServer,
        int EnvVarCount,
        bool HostsHadPtorSection,
        string TorExe,
        bool DnsWasChanged);

    static class EnforcementCheckpoint
    {
        // Ours-vs-foreign predicate for the driver service. ONLY "created"
        // (service absent when WE enabled enforcement) authorizes removal —
        // "pre-existing", "unknown", null and anything else keep the service,
        // wherever it came from. Single rule shared by toggle-off, exit
        // teardown, rollback, audit and uninstall paths: no drift.
        internal static bool IsOurs(string? driverService)
        {
            try { return string.Equals(driverService, "created", StringComparison.Ordinal); }
            catch { return false; }
        }

        // Removal-grade ownership: the checkpoint marker PLUS a live image-
        // path corroboration. The checkpoint file lives under %ProgramData%
        // and is only a hint (a user-owned directory could let a planted
        // marker authorize deleting a FOREIGN driver); the image path is the
        // ground truth. Unknown/unreadable image fails open to the marker
        // (a mere SCM read hiccup must not wedge our own cleanup).
        internal static bool IsOursSafe(string? driverService, string? ourSysPath, string? serviceImagePath)
        {
            try
            {
                if (!IsOurs(driverService)) return false;
                if (string.IsNullOrWhiteSpace(serviceImagePath)) return true;
                if (string.IsNullOrWhiteSpace(ourSysPath)) return true;
                return string.Equals(NormDriverPath(ourSysPath), NormDriverPath(serviceImagePath),
                    StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        static string NormDriverPath(string p)
        {
            try
            {
                var s = (p ?? "").Trim().Trim('"').Trim();
                if (s.StartsWith(@"\\?\", StringComparison.Ordinal)) s = s.Substring(4);
                if (s.StartsWith(@"\??\", StringComparison.Ordinal)) s = s.Substring(4);
                if (s.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                    s = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                        s.Substring(@"\SystemRoot\".Length));
                try { s = Environment.ExpandEnvironmentVariables(s); } catch { }
                try { s = System.IO.Path.GetFullPath(s); } catch { }
                return s.TrimEnd(System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar);
            }
            catch { return p ?? ""; }
        }

        static string Path()
        {
            var dir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PTor");
            Directory.CreateDirectory(dir);
            return System.IO.Path.Combine(dir, "checkpoint.json");
        }

        public static void Create(string reason, bool driverFilesPresent, string proxyServer,
            int envVarCount, bool hostsHadSection, string torExe, bool dnsWasChanged = false)
        {
            string svc = "unknown";
            try
            {
                var exists = DivertNative.ServiceExists();
                svc = exists == true ? "pre-existing" : exists == false ? "created" : "unknown";
                // Stale-ours preservation: if a crash left our service
                // installed, ServiceExists reads true ("pre-existing") and
                // would overwrite the crash leftover "created" proof — then
                // DivertEnforcement refuses our own stale service as foreign.
                // A prior "created" marker wins over a live-service read.
                try
                {
                    var prev = Load();
                    if (IsOurs(prev?.DriverService))
                        svc = "created";
                }
                catch { }
            }
            catch { }

            var data = new CheckpointData(DateTime.UtcNow, reason, svc, driverFilesPresent,
                proxyServer ?? "", envVarCount, hostsHadSection, torExe ?? "", dnsWasChanged);
            // Atomic: a torn checkpoint is worse than none (Load swallows
            // errors as "no checkpoint", silently skipping driver cleanup).
            try { SafeFiles.WriteAllTextAtomic(Path(), JsonSerializer.Serialize(data, PtorJsonContext.Default.CheckpointData)); }
            catch { }
        }

        public static CheckpointData? Load()
        {
            try
            {
                // Capped: small JSON by construction; never slurp blindly.
                var text = SafeFiles.ReadAllTextCapped(Path(), 256 * 1024);
                if (text == null) return null;
                return JsonSerializer.Deserialize(text, PtorJsonContext.Default.CheckpointData);
            }
            catch { return null; }
        }

        public static bool Exists()
        {
            try { return File.Exists(Path()); }
            catch { return false; }
        }

        public static void Delete()
        {
            try { var p = Path(); if (File.Exists(p)) File.Delete(p); } catch { }
        }
    }
}
