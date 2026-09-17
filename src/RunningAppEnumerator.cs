using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PTor
{
    public record RunningAppInfo(int Pid, string Name, string ExePath, int SessionId);

    public static class RunningAppEnumerator
    {
        public static List<RunningAppInfo> GetNonSystemUserApps()
        {
            var result = new List<RunningAppInfo>();
            var windir = WindowsDir();
            var ownPath = OwnExePath();

            foreach (var p in SnapshotAll())
            {
                if (p.Pid <= 4 || p.SessionId == 0) continue;
                if (string.IsNullOrWhiteSpace(p.ExePath) || !File.Exists(p.ExePath)) continue;
                if (p.ExePath.StartsWith(windir, StringComparison.OrdinalIgnoreCase)) continue;
                if (!string.IsNullOrEmpty(ownPath) &&
                    string.Equals(p.ExePath, ownPath, StringComparison.OrdinalIgnoreCase))
                    continue;
                // NOTE: tor.exe is intentionally NOT filtered here: it is shown
                // as an Engine row (its guard traffic is the tunnel, not a
                // leak). GetLaunchedSince below still excludes it — the stop
                // dialog must not nag about a daemon we manage ourselves.
                result.Add(new RunningAppInfo(p.Pid, p.Name, p.ExePath!, p.SessionId));
            }

            result.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
            return result;
        }

        public static (List<string> shown, int total) GetLaunchedSince(DateTime utcSince, int maxShown = 10)
        {
            var shown = new List<string>();
            var total = 0;
            var windir = WindowsDir();
            var ownPath = OwnExePath();

            foreach (var p in SnapshotAll())
            {
                if (p.Pid <= 4 || p.SessionId == 0) continue;
                if (p.StartedUtc < utcSince) continue;
                if (p.Name.Equals("tor", StringComparison.OrdinalIgnoreCase)) continue;
                if (string.IsNullOrWhiteSpace(p.ExePath) || !File.Exists(p.ExePath)) continue;
                if (p.ExePath.StartsWith(windir, StringComparison.OrdinalIgnoreCase)) continue;
                if (!string.IsNullOrEmpty(ownPath) &&
                    string.Equals(p.ExePath, ownPath, StringComparison.OrdinalIgnoreCase))
                    continue;
                total++;
                if (shown.Count < maxShown) shown.Add($"{p.Name} (PID {p.Pid})");
            }
            return (shown, total);
        }

        public static string? TryGetExePath(int pid)
        {
            if (pid <= 0) return null;
            IntPtr h = IntPtr.Zero;
            try
            {
                h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h == IntPtr.Zero) return null;
                var sb = new StringBuilder(1024);
                int cap = sb.Capacity;
                if (!QueryFullProcessImageName(h, 0, sb, ref cap) || cap <= 0) return null;
                return sb.ToString(0, cap);
            }
            catch { return null; }
            finally
            {
                if (h != IntPtr.Zero) { try { CloseHandle(h); } catch { } }
            }
        }

        public record ChildProc(int Pid, string ExePath, DateTime StartedUtc);

        // Parent PID via the Toolhelp parent link; -1 when unknown. Used by
        // the exit-guard trace to identify WHAT launched a spurious second
        // copy mid-teardown. Never throws.
        public static int GetParentPid(int pid)
        {
            if (pid <= 0) return -1;
            IntPtr snap = IntPtr.Zero;
            try
            {
                snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return -1;
                var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
                if (!Process32First(snap, ref entry)) return -1;
                do
                {
                    if (entry.th32ProcessID == pid)
                        return entry.th32ParentProcessID;
                } while (Process32Next(snap, ref entry));
                return -1;
            }
            catch { return -1; }
            finally
            {
                if (snap != IntPtr.Zero && snap != new IntPtr(-1))
                { try { CloseHandle(snap); } catch { } }
            }
        }        // Identity is (pid, startTime, path): PIDs recycle, so callers must verify ExePath/StartedUtc.
        public static List<ChildProc> GetChildProcesses(int parentPid)
        {
            var out_ = new List<ChildProc>();
            if (parentPid <= 0) return out_;
            IntPtr snap = IntPtr.Zero;
            try
            {
                snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return out_;
                var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
                if (!Process32First(snap, ref entry)) return out_;
                do
                {
                    if (entry.th32ParentProcessID != parentPid) continue;
                    var pid = entry.th32ProcessID;
                    if (pid <= 0) continue;
                    IntPtr h = IntPtr.Zero;
                    try
                    {
                        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                        if (h == IntPtr.Zero) continue;
                        var sb = new StringBuilder(1024);
                        int cap = sb.Capacity;
                        if (!QueryFullProcessImageName(h, 0, sb, ref cap) || cap <= 0) continue;
                        var started = DateTime.MinValue;
                        try
                        {
                            if (GetProcessTimes(h, out var c, out _, out _, out _))
                            {
                                long ft = ((long)c.dwHighDateTime << 32) | c.dwLowDateTime;
                                if (ft > 0) started = DateTime.FromFileTimeUtc(ft);
                            }
                        }
                        catch { }
                        if (started == DateTime.MinValue) continue;
                        out_.Add(new ChildProc(pid, sb.ToString(0, cap), started));
                    }
                    catch { }
                    finally
                    {
                        if (h != IntPtr.Zero) { try { CloseHandle(h); } catch { } }
                    }
                } while (Process32Next(snap, ref entry));
            }
            catch { }
            finally
            {
                if (snap != IntPtr.Zero && snap != new IntPtr(-1))
                { try { CloseHandle(snap); } catch { } }
            }
            return out_;
        }

        static string WindowsDir()
        {
            try
            {
                return Environment.GetFolderPath(Environment.SpecialFolder.Windows)
                    .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            }
            catch { return @"C:\Windows\"; }
        }

        record RawProc(int Pid, string Name, string? ExePath, int SessionId, DateTime StartedUtc);

        const uint TH32CS_SNAPPROCESS = 0x00000002;
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags,
            StringBuilder lpExeName, ref int lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int GetModuleFileName(IntPtr hModule, StringBuilder lpFilename, int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetProcessTimes(IntPtr hProcess,
            out FILETIME lpCreationTime, out FILETIME lpExitTime,
            out FILETIME lpKernelTime, out FILETIME lpUserTime);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public int th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public int th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        static List<RawProc> SnapshotAll()
        {
            var out_ = new List<RawProc>(256);
            IntPtr snap = IntPtr.Zero;
            try
            {
                snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return out_;

                var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
                if (!Process32First(snap, ref entry)) return out_;
                do
                {
                    var pid = entry.th32ProcessID;
                    if (pid <= 0) continue;
                    var name = entry.szExeFile ?? "";
                    var dot = name.LastIndexOf('.');
                    if (dot > 0) name = name.Substring(0, dot);

                    string? path = null;
                    var session = 0;
                    var started = DateTime.MinValue;
                    IntPtr h = IntPtr.Zero;
                    try
                    {
                        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                        if (h != IntPtr.Zero)
                        {
                            var sb = new StringBuilder(1024);
                            int cap = sb.Capacity;
                            if (QueryFullProcessImageName(h, 0, sb, ref cap) && cap > 0)
                                path = sb.ToString(0, cap);

                            try
                            {
                                if (ProcessIdToSessionId((uint)pid, out var s))
                                    session = (int)s;
                            }
                            catch { }

                            try
                            {
                                if (GetProcessTimes(h, out var c, out _, out _, out _))
                                {
                                    long ft = ((long)c.dwHighDateTime << 32) | c.dwLowDateTime;
                                    if (ft > 0) started = DateTime.FromFileTimeUtc(ft);
                                }
                            }
                            catch { }
                        }
                    }
                    catch {  }
                    finally
                    {
                        if (h != IntPtr.Zero) { try { CloseHandle(h); } catch { } }
                    }

                    if (session == 0)
                    {
                        try
                        {
                            if (ProcessIdToSessionId((uint)pid, out var s2))
                                session = (int)s2;
                        }
                        catch { }
                    }

                    out_.Add(new RawProc(pid, name, path, session, started));
                } while (Process32Next(snap, ref entry));
            }
            catch {  }
            finally
            {
                if (snap != IntPtr.Zero && snap != new IntPtr(-1))
                { try { CloseHandle(snap); } catch { } }
            }
            return out_;
        }

        static string? OwnExePath()
        {
            try
            {
                var sb = new StringBuilder(1024);
                var n = GetModuleFileName(IntPtr.Zero, sb, sb.Capacity);
                return n > 0 ? sb.ToString(0, n) : null;
            }
            catch { return null; }
        }

        public static bool IsPidAlive(int pid)
        {
            if (pid <= 0) return false;
            IntPtr h = IntPtr.Zero;
            try
            {
                h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                return h != IntPtr.Zero;
            }
            catch { return false; }
            finally
            {
                if (h != IntPtr.Zero) { try { CloseHandle(h); } catch { } }
            }
        }

        const int ERROR_INVALID_PARAMETER = 87;

        public static bool IsPidDead(int pid)
        {
            if (pid <= 0) return true;
            IntPtr h = IntPtr.Zero;
            try
            {
                h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h != IntPtr.Zero) return false;
                return Marshal.GetLastWin32Error() == ERROR_INVALID_PARAMETER;
            }
            catch { return false; }
            finally
            {
                if (h != IntPtr.Zero) { try { CloseHandle(h); } catch { } }
            }
        }
    }
}
