using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace PTor
{

    // Windows logon startup via the per-user Run key (HKCU, no admin needed):
    //   HKCU\Software\Microsoft\Windows\CurrentVersion\Run  value "PTor"
    //     = "<exe path>" --minimized
    //
    // Minimized so a boot launch lands in the tray instead of popping a
    // window on every logon. All methods are best-effort and never throw —
    // callers report the returned message in the status line instead.
    public static class StartupManager
    {
        public const string ValueName = "PTor";
        const string RunSubKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        public const string StartupArg = "--minimized";

        public static string? CurrentExePath()
        {
            try
            {
                var p = Environment.ProcessPath;
                if (!string.IsNullOrWhiteSpace(p)) return p;
            }
            catch { }
            try { return Process.GetCurrentProcess().MainModule?.FileName; }
            catch { return null; }
        }

        public static string BuildValue(string exePath)
        {
            return "\"" + exePath + "\" " + StartupArg;
        }

        public static string? GetValue()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunSubKey, writable: false);
                return key?.GetValue(ValueName, null) as string;
            }
            catch { return null; }
        }

        public static bool IsEnabled()
        {
            try { return !string.IsNullOrWhiteSpace(GetValue()); }
            catch { return false; }
        }

        // True when the entry exists AND points at this install's exe.
        // Versioned Release folders (Release\vX.Y.Z) move the exe every
        // update, so a stale path must be rewritten, not trusted.
        public static bool PointsAtCurrentExe()
        {
            try
            {
                var cur = CurrentExePath();
                var val = GetValue();
                if (string.IsNullOrWhiteSpace(cur) || string.IsNullOrWhiteSpace(val))
                    return false;
                var target = ExtractExePath(val);
                if (string.IsNullOrWhiteSpace(target)) return false;
                return string.Equals(
                    NormPath(target), NormPath(cur), StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        static string NormPath(string p)
        {
            try
            {
                var s = p.Trim().Trim('"').Trim();
                try { s = Environment.ExpandEnvironmentVariables(s); } catch { }
                try { s = Path.GetFullPath(s); } catch { }
                return s.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }
            catch { return p ?? ""; }
        }

        internal static string? ExtractExePath(string value)
        {
            try
            {
                var v = (value ?? "").Trim();
                if (v.Length == 0) return null;
                if (v[0] == '"')
                {
                    var end = v.IndexOf('"', 1);
                    if (end > 1) return v.Substring(1, end - 1);
                    return null;
                }
                // Unquoted: exe path is the first whitespace-delimited token.
                var sp = v.IndexOfAny(new[] { ' ', '\t' });
                return sp > 0 ? v.Substring(0, sp) : v;
            }
            catch { return null; }
        }

        public static string Enable()
        {
            try
            {
                var exe = CurrentExePath();
                if (string.IsNullOrWhiteSpace(exe))
                    return "Start on startup failed: could not locate PTor.exe.";
                if (!File.Exists(exe))
                    return "Start on startup failed: PTor.exe path not found (" + exe + ").";
                using var key = Registry.CurrentUser.CreateSubKey(RunSubKey, writable: true);
                if (key == null)
                    return "Start on startup failed: could not open the Run key for writing.";
                key.SetValue(ValueName, BuildValue(exe), RegistryValueKind.String);
                // Read-back verify: something (hardening tools, GPO) may revert it.
                var back = GetValue();
                if (string.IsNullOrWhiteSpace(back))
                {
                    try { key.DeleteValue(ValueName, throwOnMissingValue: false); } catch { }
                    return "Start on startup did not stick (read-back mismatch) — entry removed again. Something is reverting Run-key changes (group policy or a security tool).";
                }
                return "Start on startup ON: PTor launches minimized to the tray on logon.";
            }
            catch (Exception ex) { return "Start on startup failed: " + ex.Message; }
        }

        public static string Disable()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunSubKey, writable: true);
                if (key == null) return "Start on startup is off (Run key unreadable, nothing to remove).";
                var cur = key.GetValue(ValueName, null) as string;
                if (string.IsNullOrWhiteSpace(cur))
                    return "Start on startup OFF: no entry found, nothing to remove.";
                try { key.DeleteValue(ValueName, throwOnMissingValue: false); } catch { }
                return "Start on startup OFF: logon entry removed.";
            }
            catch (Exception ex) { return "Start on startup disable failed: " + ex.Message; }
        }

        // Reconciles the registry with the desired setting. Returns null when
        // already in sync (caller stays silent), else a human-readable note.
        // Never throws.
        public static string? Sync(bool wantEnabled)
        {
            try
            {
                if (wantEnabled)
                {
                    if (IsEnabled() && PointsAtCurrentExe()) return null;
                    return Enable();
                }
                if (!IsEnabled()) return null;
                return Disable();
            }
            catch { return null; }
        }

        public static string StatusLine()
        {
            try
            {
                var val = GetValue();
                if (string.IsNullOrWhiteSpace(val)) return "Currently: off (no logon entry).";
                return PointsAtCurrentExe()
                    ? "Currently: on (this install, minimized to tray)."
                    : "Currently: on, but pointing elsewhere (" + Trunc(val, 90) + ") — re-save to repoint here.";
            }
            catch { return "Currently: unknown (could not read the Run key)."; }
        }

        static string Trunc(string v, int max) =>
            string.IsNullOrEmpty(v) ? "(empty)" : (v.Length <= max ? v : v.Substring(0, max) + "…");
    }
}
