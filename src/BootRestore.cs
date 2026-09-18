using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace PTor
{
    // Boot safety net for the unclean-shutdown hole: if the PC loses power,
    // BSODs, or PTor is killed while routing is on, the loopback proxy/DNS/
    // env values persist into the next boot with nothing listening — no
    // internet, and PTor itself may not autostart to repair it. (Graceful
    // OS shutdown IS covered: SessionEnding runs BarbaricQuitTeardown.)
    //
    // While routing is engaged, Ensure() arms a logon-time restore that
    // runs Uninstall.exe --restore-only, in two tiers:
    //   * elevated  -> Scheduled Task (silent, fixes proxy + env + HKLM DNS),
    //   * any level -> HKCU RunOnce value (one-time logon entry: the OS runs
    //     it once at the next logon and deletes it by itself).
    // RunOnce (not Run) is deliberate: single-fire means a single UAC prompt
    // at most (Uninstall.exe requires admin) instead of nagging every logon,
    // and the OS auto-cleanup leaves zero residue even if our own removal
    // never runs. The value name carries both documented prefixes:
    //   *  = run even in Safe Mode (where the task scheduler may be dead
    //        but registry repair works fine — exactly when repair is needed),
    //   !  = delete AFTER the command completes, so a crash/power loss
    //        mid-restore retries on the following boot instead of vanishing.
    // (HKLM RunOnce was considered and rejected: per MS docs it only fires
    // on admin logons, so it adds nothing over the task tier.)
    // RunOnce is documented for transient conditions only — ours qualifies:
    // armed while routing is engaged, removed on every clean stop.
    // Cap: RunOnce command lines are limited to 260 chars; overlong install
    // paths skip the RunOnce tier (the task tier has no such limit).
    //
    // Clean routing stop calls Remove(). If the process dies first, the next
    // logon fires the restore, which deletes the task/entry itself once the
    // state is clean — the net exists only while it is needed.
    //
    // Shared with Uninstall.exe (compiled in there too): full uninstall and
    // --restore-only both call Remove(). Best-effort throughout, never
    // throws — callers surface the returned message in the status line.
    static class BootRestore
    {
        public const string TaskName = "PTorNetRestore";
        // Legacy v1.0.6 tier (HKCU Run, every-logon): no longer armed, but
        // Remove() still scrubs it so upgraders never keep a stale entry.
        public const string LegacyRunValueName = "PTorNetRestore";
        const string RunSubKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        public const string RunOnceValueName = "*!PTorNetRestore";
        const string RunOnceSubKey = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
        const string RestoreArgs = "--restore-only";
        // Keep well under the 260-char RunOnce command-line cap.
        const int MaxRunOnceCmdLen = 240;

        // This-process latch: re-arming an already-armed net every routing
        // start would spam schtasks + the status line for no benefit. A
        // fresh process (i.e. after a crash/reboot) always re-arms.
        static bool _armedThisProcess;

        public static string? UninstallExePath(string? appDir)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(appDir)) return null;
                var exe = Path.Combine(appDir, "Uninstall.exe");
                return File.Exists(exe) ? exe : null;
            }
            catch { return null; }
        }

        // Arms the net. Returns null when already armed or when there is
        // nothing to arm with (dev runs without Uninstall.exe next door —
        // staying silent there, not nagging every F5). Never throws.
        public static string? Ensure(string? appDir)
        {
            try
            {
                if (_armedThisProcess) return null;
                var exe = UninstallExePath(appDir);
                if (exe == null) return null;
                var cmd = "\"" + exe + "\" " + RestoreArgs;
                if (AdminHelper.IsAdministrator())
                {
                    var taskNote = EnsureTask(cmd);
                    if (taskNote == null)
                    {
                        _armedThisProcess = true;
                        // Belt and suspenders: the one-time logon entry fires
                        // early at logon (proxy+env back fast, plus Safe Mode
                        // where the scheduler may be dead) while the delayed
                        // task covers HKLM DNS a minute later — and either one
                        // alone still repairs if the other mechanism is broken
                        // (disabled Task Scheduler, scrubbed entry, ...).
                        // Both self-delete once the state is clean.
                        var runExtra = EnsureRunOnceValue(cmd);
                        try { RemoveRunValue(); } catch { } // legacy tier scrub
                        return "Boot safety net armed: if this PC dies mid-routing, the next logon auto-restores your internet (scheduled task + one-time logon entry)." +
                            (runExtra ?? "");
                    }
                    // Task failed (hardened schtasks?): the one-time entry
                    // still covers the repair with a single UAC prompt —
                    // better than nothing.
                    var runNote = EnsureRunOnceValue(cmd);
                    try { RemoveRunValue(); } catch { } // legacy tier scrub
                    _armedThisProcess = true;
                    return "Boot safety net PARTIAL: logon task failed (" + taskNote + ") — armed one-time logon entry instead (one UAC prompt at next logon)." +
                        (runNote ?? "");
                }
                var note = EnsureRunOnceValue(cmd);
                try { RemoveRunValue(); } catch { } // legacy tier scrub
                _armedThisProcess = true;
                return "Boot safety net armed (one-time logon entry — expect one UAC prompt at next logon if this PC dies mid-routing; DNS repair needs the elevation)."
                    + (note ?? "");
            }
            catch (Exception ex) { return "Boot safety net failed to arm (" + ex.Message + ") — an unclean shutdown could leave loopback settings behind; rescue-internet.bat still fixes that by hand."; }
        }

        // Disarms unconditionally (clean routing stop, uninstall). Scrubs the
        // legacy every-logon Run value too, so v1.0.6 upgrades never keep a
        // stale entry. Never throws.
        public static void Remove()
        {
            try { _armedThisProcess = false; } catch { }
            try { RemoveTask(); } catch { }
            try { RemoveRunOnceValue(); } catch { }
            try { RemoveRunValue(); } catch { }
        }

        static string? EnsureTask(string cmd)
        {
            // Returns null on success, else the short failure reason.
            try
            {
                var schtasks = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe");
                if (!File.Exists(schtasks)) return "schtasks.exe not found";
                // Delayed logon start: a normal autostarted PTor wins the
                // race and --restore-only exits quietly when PTor runs.
                var args = "/Create /TN \"" + TaskName + "\" /TR \"" +
                    cmd.Replace("\"", "\\\"") +
                    "\" /SC ONLOGON /DELAY 0001:00 /RL HIGHEST /F";
                var (exit, output) = RunCapture(schtasks, args);
                if (exit == 0) return null;
                return "schtasks exit " + exit + " (" + Trunc(output, 120) + ")";
            }
            catch (Exception ex) { return ex.Message; }
        }

        static void RemoveTask()
        {
            try
            {
                var schtasks = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe");
                if (!File.Exists(schtasks)) return;
                // No /Query first: /Delete on a missing task just errors,
                // which we swallow — one call either way.
                RunCapture(schtasks, "/Delete /TN \"" + TaskName + "\" /F");
            }
            catch { }
        }

        static string? EnsureRunOnceValue(string cmd)
        {
            // Returns extra note text (possibly "") — entry failures are
            // non-fatal, the message just says so.
            try
            {
                if (cmd.Length > MaxRunOnceCmdLen)
                    return " (one-time logon entry skipped: install path too long for the RunOnce 260-char cap)";
                using var key = Registry.CurrentUser.CreateSubKey(RunOnceSubKey, writable: true);
                if (key == null) return " (logon entry unwritable)";
                var cur = key.GetValue(RunOnceValueName, null) as string;
                if (string.Equals(cur, cmd, StringComparison.Ordinal)) return null;
                key.SetValue(RunOnceValueName, cmd, RegistryValueKind.String);
                return null;
            }
            catch (Exception ex) { return " (logon entry failed: " + ex.Message + ")"; }
        }

        static void RemoveRunOnceValue()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunOnceSubKey, writable: true);
                if (key == null) return;
                try { key.DeleteValue(RunOnceValueName, throwOnMissingValue: false); } catch { }
            }
            catch { }
        }

        static void RemoveRunValue()
        {
            // Legacy v1.0.6 tier (HKCU Run, fired every logon): scrub only,
            // never armed anymore.
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunSubKey, writable: true);
                if (key == null) return;
                try { key.DeleteValue(LegacyRunValueName, throwOnMissingValue: false); } catch { }
            }
            catch { }
        }

        static (int exit, string output) RunCapture(string file, string args)
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = file,
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                });
                if (p == null) return (1, "could not start");
                // Bounded: a wedged SCM/task service must never park the caller.
                if (!p.WaitForExit(15000))
                {
                    try { p.Kill(entireProcessTree: true); } catch { }
                    return (1, "timed out");
                }
                string output = "";
                try { output = ((p.StandardOutput.ReadToEnd() ?? "") + " " + (p.StandardError.ReadToEnd() ?? "")).Trim(); } catch { }
                return (p.ExitCode, output);
            }
            catch (Exception ex) { return (1, ex.Message); }
        }

        static string Trunc(string v, int max) =>
            string.IsNullOrEmpty(v) ? "(no output)" : (v.Length <= max ? v : v.Substring(0, max) + "…");
    }
}
