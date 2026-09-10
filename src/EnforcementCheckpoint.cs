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
            }
            catch { }

            var data = new CheckpointData(DateTime.UtcNow, reason, svc, driverFilesPresent,
                proxyServer ?? "", envVarCount, hostsHadSection, torExe ?? "", dnsWasChanged);
            // Atomic: a torn checkpoint is worse than none (Load swallows
            // errors as "no checkpoint", silently skipping driver cleanup).
            try
            {
                var path = Path();
                var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    File.WriteAllText(tmp, JsonSerializer.Serialize(data));
                    File.Move(tmp, path, overwrite: true);
                }
                catch
                {
                    try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
                }
            }
            catch { }
        }

        public static CheckpointData? Load()
        {
            try
            {
                var path = Path();
                if (!File.Exists(path)) return null;
                return JsonSerializer.Deserialize<CheckpointData>(File.ReadAllText(path));
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
