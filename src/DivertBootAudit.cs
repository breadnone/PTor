using System;
using System.Diagnostics;
using System.IO;

namespace PTor
{

    public record DivertAudit(
        bool DriverFilesPresent,
        string? OurSysPath,
        bool? ServiceExists,
        string? ServiceImagePath,
        string? ServiceState,
        bool ServiceLooksOurs,
        bool StaleCheckpointCreated,
        bool MultipleInstances,
        string Summary);

    // Boot-time safety audit for the WinDivert packet driver. The driver is a
    // system singleton (one "WinDivert" service max — Windows enforces that),
    // but installing over / deleting somebody else's driver would still wreck
    // their setup, so on EVERY app boot we verify state and report:
    //   - driver files present?
    //   - service absent (clean), ours/stale (safe to repair), or foreign
    //     (hands off — never touch it, never install a second one)?
    //   - another PTor.exe already running (two diverters = chaos)?
    // READ-ONLY: this never installs, starts, stops, or deletes anything.
    // Never throws.
    public static class DivertBootAudit
    {
        public static DivertAudit? Last { get; private set; }

        public static DivertAudit Run(string appDir)
        {
            try
            {
                var dir = DivertEnforcement.LocateDriverDir(appDir);
                var filesPresent = dir != null;
                string? ourSys = null;
                if (dir != null)
                {
                    try
                    {
                        ourSys = Path.Combine(dir,
                            Environment.Is64BitProcess ? "WinDivert64.sys" : "WinDivert32.sys");
                    }
                    catch { }
                }

                DivertNative.DivertServiceInfo? svc = null;
                try { svc = DivertNative.GetServiceInfo(); } catch { }

                bool staleCreated = false;
                try
                {
                    var cp = EnforcementCheckpoint.Load();
                    staleCreated = cp != null && cp.DriverService == "created";
                }
                catch { }

                var looksOurs = ServiceLooksOurs(ourSys, svc?.ImagePath) || staleCreated;
                var multi = AnotherInstanceRunning();

                string summary;
                if (!filesPresent)
                {
                    summary = "WinDivert check: driver files missing (tools\\WinDivert) — lockdown unavailable, nothing installed, nothing touched.";
                }
                else if (svc == null)
                {
                    summary = "WinDivert check: service state unreadable (need admin to query?) — no changes made.";
                }
                else if (svc.Exists == false)
                {
                    summary = "WinDivert check: no driver service installed — clean. Lockdown installs the single service on demand and removes it on stop.";
                }
                else if (staleCreated)
                {
                    summary = "WinDivert check: service present from PTor's own last run (unclean shutdown) — reusing it, no new install; repair runs on Tor start.";
                }
                else if (looksOurs)
                {
                    summary = "WinDivert check: service present, points at PTor's driver (" +
                        Truncate(svc.ImagePath) + ", " + (svc.State ?? "?") + ") — left as-is, no reinstall.";
                }
                else
                {
                    summary = "WinDivert check: a WinDivert service already exists (" +
                        Truncate(svc.ImagePath) + ", " + (svc.State ?? "?") +
                        ") — NOT PTor's, left untouched. If lockdown fails (driver version clash), close the other app first; PTor will not install a second driver.";
                }
                if (multi)
                    summary += " WARNING: another PTor.exe is already running — run only one copy (two diverters fight over packets).";

                var audit = new DivertAudit(filesPresent, ourSys, svc?.Exists,
                    svc?.ImagePath, svc?.State, looksOurs, staleCreated, multi, summary);
                Last = audit;
                return audit;
            }
            catch (Exception ex)
            {
                var audit = new DivertAudit(false, null, null, null, null, false, false, false,
                    "WinDivert check failed (" + ex.GetType().Name + ") — no changes made.");
                Last = audit;
                return audit;
            }
        }

        internal static bool ServiceLooksOurs(string? ourSysPath, string? imagePath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(ourSysPath) || string.IsNullOrWhiteSpace(imagePath))
                    return false;
                return string.Equals(NormalizeDriverPath(ourSysPath), NormalizeDriverPath(imagePath),
                    StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        internal static string NormalizeDriverPath(string p)
        {
            var s = (p ?? "").Trim().Trim('"').Trim();
            // Services often store an NT path (\\?\C:\...) — strip the prefix.
            if (s.StartsWith(@"\\?\", StringComparison.Ordinal))
                s = s.Substring(4);
            try { s = Environment.ExpandEnvironmentVariables(s); } catch { }
            try { s = Path.GetFullPath(s); } catch { }
            return s.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        static bool AnotherInstanceRunning()
        {
            try
            {
                var me = Process.GetCurrentProcess();
                foreach (var p in Process.GetProcessesByName(me.ProcessName))
                {
                    try { if (p.Id != me.Id) return true; }
                    catch { }
                    finally { try { p.Dispose(); } catch { } }
                }
                return false;
            }
            catch { return false; }
        }

        static string Truncate(string? v) =>
            string.IsNullOrEmpty(v) ? "(unknown path)" : (v.Length <= 90 ? v : v.Substring(0, 90) + "…");
    }
}
