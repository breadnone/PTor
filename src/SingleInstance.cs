using System;
using System.Diagnostics;
using System.Threading;

namespace PTor
{

    // Hard single-instance lock: exactly one PTor per session. No WPF deps so
    // it runs at the very top of OnStartup (and is unit-testable).
    //
    // Restart flows (relaunch / elevate) hand over via --takeover-from <pid>:
    // the new process waits for the old PID to die (releasing the mutex with
    // it) instead of bouncing off with "already running".
    public static class SingleInstance
    {
        public const string MutexName = "PTorSingleInstance";
        public const string TakeoverArg = "--takeover-from";

        static Mutex? _held;

        // True when we now own the lock. Abandoned mutexes (crashed
        // predecessor) are adopted; a lock owned by an elevated instance we
        // cannot even open counts as busy (fail closed).
        public static bool TryAcquire()
        {
            try
            {
                _held = new Mutex(false, MutexName, out _);
                try { return _held.WaitOne(0); }
                catch (AbandonedMutexException) { return true; }
            }
            catch (UnauthorizedAccessException) { return false; }
            catch { return true; } // mutex subsystem broken: fail open, don't brick the app
        }

        public static void Release()
        {
            try { _held?.ReleaseMutex(); } catch { }
            try { _held?.Dispose(); } catch { }
            _held = null;
        }

        public static int ParseTakeoverPid(string[] args)
        {
            try
            {
                for (var i = 0; i < args.Length; i++)
                {
                    if (args[i].Equals(TakeoverArg, StringComparison.OrdinalIgnoreCase) &&
                        i + 1 < args.Length &&
                        int.TryParse(args[i + 1], out var pid) && pid > 0)
                        return pid;
                }
            }
            catch { }
            return 0;
        }

        // Waits for a PID to exit (poll, bounded). True when it is gone —
        // including "never existed". Never throws.
        public static bool WaitForPidExit(int pid, TimeSpan timeout)
        {
            if (pid <= 0) return true;
            try
            {
                var sw = Stopwatch.StartNew();
                while (sw.Elapsed < timeout)
                {
                    if (IsPidGone(pid)) return true;
                    Thread.Sleep(250);
                }
                return IsPidGone(pid);
            }
            catch { return false; }
        }

        static bool IsPidGone(int pid)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                return p.HasExited;
            }
            catch (ArgumentException) { return true; } // no such PID
            catch { return false; }
        }
    }
}
