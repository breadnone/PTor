using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PTor
{

    // Efficiency-mode (Task Manager's "Eco mode" leaf) guard. An EcoQoS-tagged
    // process gets its CPU throttled by the OS scheduler: for a relay/tunnel
    // that means stalls, dead guards and app fallback to direct = leaks.
    // Throttling state is INHERITED at process creation, so the tag must be
    // cleared on OUR process before tor spawns (children are then born clean),
    // and re-asserted on tor + transports in case anything re-tags them
    // mid-run (user click, OS heuristics). All best-effort, never throws.
    static class EcoModeGuard
    {
        const int ProcessPowerThrottling = 4;
        const uint EXECUTION_SPEED = 0x1;
        const uint PROCESS_SET_INFORMATION = 0x0200;
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_POWER_THROTTLING_STATE
        {
            public uint Version;
            public uint ControlMask;
            public uint StateMask;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetProcessInformation(IntPtr hProcess, int ProcessInformationClass,
            ref PROCESS_POWER_THROTTLING_STATE ProcessInformation, uint ProcessInformationSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetProcessInformation(IntPtr hProcess, int ProcessInformationClass,
            out PROCESS_POWER_THROTTLING_STATE ProcessInformation, uint ProcessInformationSize);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // Explicitly opts a process OUT of execution-speed throttling
        // (clears EcoQoS, including inherited or user-applied Efficiency
        // mode). Returns whether clean is confirmed in effect afterwards.
        public static bool OptOut(IntPtr hProcess)
        {
            try
            {
                if (hProcess == IntPtr.Zero) return false;
                var st = new PROCESS_POWER_THROTTLING_STATE
                {
                    Version = 1,
                    ControlMask = EXECUTION_SPEED,
                    StateMask = 0
                };
                try
                {
                    SetProcessInformation(hProcess, ProcessPowerThrottling, ref st,
                        (uint)Marshal.SizeOf<PROCESS_POWER_THROTTLING_STATE>());
                }
                catch { }
                return !IsExecutionThrottled(hProcess);
            }
            catch { return false; }
        }

        public static bool OptOutCurrentProcess()
        {
            try { return OptOut(GetCurrentProcess()); }
            catch { return false; }
        }

        public static bool OptOutProcess(Process? proc)
        {
            try
            {
                if (proc == null) return false;
                try { if (proc.HasExited) return false; } catch { return false; }
                return OptOut(proc.Handle);
            }
            catch { return false; }
        }

        public static bool OptOutProcessById(int pid)
        {
            IntPtr h = IntPtr.Zero;
            try
            {
                if (pid <= 0) return false;
                h = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h == IntPtr.Zero) return false;
                return OptOut(h);
            }
            catch { return false; }
            finally
            {
                if (h != IntPtr.Zero) { try { CloseHandle(h); } catch { } }
            }
        }

        public static bool IsExecutionThrottled(IntPtr hProcess)
        {
            try
            {
                if (hProcess == IntPtr.Zero) return false;
                if (!GetProcessInformation(hProcess, ProcessPowerThrottling,
                        out var st, (uint)Marshal.SizeOf<PROCESS_POWER_THROTTLING_STATE>()))
                    return false; // unreadable (old OS): assume clean, don't cry wolf
                return (st.StateMask & EXECUTION_SPEED) != 0;
            }
            catch { return false; }
        }

        public static bool IsCurrentExecutionThrottled()
        {
            try { return IsExecutionThrottled(GetCurrentProcess()); }
            catch { return false; }
        }

        // Clears the tag only if present. Returns true when a tag was present
        // and is now confirmed gone (drives the "was throttled, fixed it"
        // log line); false when there was nothing to do or it wouldn't clear
        // (a persistent true retries on the next pass).
        public static bool ClearIfTagged(IntPtr hProcess)
        {
            try
            {
                if (!IsExecutionThrottled(hProcess)) return false;
                return OptOut(hProcess);
            }
            catch { return false; }
        }

        public static bool ClearIfTaggedCurrent()
        {
            try { return ClearIfTagged(GetCurrentProcess()); }
            catch { return false; }
        }

        public static bool ClearIfTaggedProcess(Process? proc)
        {
            try
            {
                if (proc == null) return false;
                try { if (proc.HasExited) return false; } catch { return false; }
                return ClearIfTagged(proc.Handle);
            }
            catch { return false; }
        }

        public static bool ClearIfTaggedPid(int pid)
        {
            IntPtr h = IntPtr.Zero;
            try
            {
                if (pid <= 0) return false;
                h = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h == IntPtr.Zero) return false;
                return ClearIfTagged(h);
            }
            catch { return false; }
            finally
            {
                if (h != IntPtr.Zero) { try { CloseHandle(h); } catch { } }
            }
        }
    }
}
