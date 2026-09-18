using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PTor
{

    // Death pact for child processes: puts them in a Windows Job Object with
    // KILL_ON_JOB_CLOSE, so when THIS process dies — clean exit, hard crash,
    // Task Manager kill — Windows itself terminates the children. No sweep,
    // no watchdog, no background service can do this reliably; the kernel
    // enforces it.
    //
    // Used for tor.exe: its pluggable-transport helpers are tor's children,
    // so they join the same job automatically and die with it. tor is
    // useless without our in-process relays anyway (our bridge ports die
    // with us), so killing it on our death is strictly correct.
    //
    // BCL-only (testable). Never throws: failure returns Zero and the caller
    // falls back to the stale-process sweep on next start.
    static class ProcessDeathPact
    {
        const uint LimitKillOnJobClose = 0x2000;
        const int JobObjectBasicLimitInformation = 2;

        [StructLayout(LayoutKind.Sequential)]
        struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool SetInformationJobObject(IntPtr hJob,
            int JobObjectInformationClass, ref JOBOBJECT_BASIC_LIMIT_INFORMATION lpJobObjectInformation,
            uint cbJobObjectInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        // Creates the pact job and assigns an already-started child.
        // Returns the job handle (keep it open for the child's whole life —
        // closing it IS the trigger) or Zero on any failure.
        public static IntPtr Assign(Process proc)
        {
            IntPtr job = IntPtr.Zero;
            try
            {
                if (proc == null || proc.HasExited) return IntPtr.Zero;
                job = CreateJobObject(IntPtr.Zero, null);
                if (job == IntPtr.Zero) return IntPtr.Zero;
                var limits = new JOBOBJECT_BASIC_LIMIT_INFORMATION
                {
                    LimitFlags = LimitKillOnJobClose,
                };
                if (!SetInformationJobObject(job, JobObjectBasicLimitInformation,
                        ref limits, (uint)Marshal.SizeOf<JOBOBJECT_BASIC_LIMIT_INFORMATION>()))
                {
                    Close(job);
                    return IntPtr.Zero;
                }
                // Fails if the child is already in an incompatible job
                // (e.g. we run sandboxed): backstop sweep covers that case.
                if (!AssignProcessToJobObject(job, proc.Handle))
                {
                    Close(job);
                    return IntPtr.Zero;
                }
                return job;
            }
            catch
            {
                Close(job);
                return IntPtr.Zero;
            }
        }

        public static void Close(IntPtr job)
        {
            if (job == IntPtr.Zero) return;
            try { CloseHandle(job); } catch { }
        }
    }
}
