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

        public bool EnforceTorOnly { get; set; } = true;

        public BridgeMode BridgeMode { get; set; } = BridgeMode.Auto;

        public List<string> CustomBridgeLines { get; set; } = new List<string>();

        public bool StableExitEnabled { get; set; } = false;

        public bool ExitGeoEnabled { get; set; } = false;

        public string ExitRegion { get; set; } = "Western Europe";

        public string ExitCustomCountries { get; set; } = "";

        static string SettingsPath()
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PTor");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "settings.json");
        }

        public static AppSettings Load()
        {
            try
            {
                var path = SettingsPath();
                if (!File.Exists(path)) return new AppSettings();
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path))
                    ?? new AppSettings();
            }
            catch { return new AppSettings(); }
        }

        public void Save()
        {
            // Atomic: a hard crash mid-write must never leave a truncated
            // settings.json (which would reset all user config on next load).
            var path = SettingsPath();
            var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllText(tmp, JsonSerializer.Serialize(this));
                File.Move(tmp, path, overwrite: true);
            }
            catch
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            }
        }
    }
}
