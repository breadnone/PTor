using System;
using System.Runtime.InteropServices;

namespace PTor
{

    static class DivertNative
    {
        public const int LAYER_NETWORK = 0;

        public const int SHUTDOWN_RECV = 0x1;
        public const int SHUTDOWN_SEND = 0x2;
        public const int SHUTDOWN_BOTH = 0x3;

        public const int PARAM_QUEUE_TIME = 1;

        public const int ADDR_SIZE = 80;
        public const int PACKET_BUF_SIZE = 65535;

        public static readonly IntPtr INVALID_HANDLE = new(-1);

        public const int FLAG_OUTBOUND_BIT = 17;
        public const int FLAG_LOOPBACK_BIT = 18;
        public const int FLAG_IPV6_BIT = 20;

        const string Dll = "WinDivert.dll";

        [DllImport(Dll, EntryPoint = "WinDivertOpen", CallingConvention = CallingConvention.Cdecl, SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        public static extern IntPtr Open([MarshalAs(UnmanagedType.LPStr)] string filter, int layer, short priority, ulong flags);

        [DllImport(Dll, EntryPoint = "WinDivertRecv", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Recv(IntPtr handle, IntPtr packet, uint packetLen, out uint recvLen, IntPtr addr);

        [DllImport(Dll, EntryPoint = "WinDivertSend", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Send(IntPtr handle, IntPtr packet, uint packetLen, IntPtr sendLenOrZero, IntPtr addr);

        [DllImport(Dll, EntryPoint = "WinDivertShutdown", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Shutdown(IntPtr handle, int how);

        [DllImport(Dll, EntryPoint = "WinDivertClose", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Close(IntPtr handle);

        [DllImport(Dll, EntryPoint = "WinDivertSetParam", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetParam(IntPtr handle, int param, ulong value);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetDllDirectory(string? path);

        const uint SC_MANAGER_CONNECT = 0x0001;
        const uint SERVICE_QUERY_STATUS = 0x0004;
        const uint SERVICE_STOP = 0x0020;
        const uint DELETE_ACCESS = 0x00010000;
        const uint SERVICE_CONTROL_STOP = 0x00000001;

        [StructLayout(LayoutKind.Sequential)]
        struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool ControlService(IntPtr hService, uint dwControl, out SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseServiceHandle(IntPtr hObject);

        const uint SERVICE_QUERY_CONFIG = 0x0001;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool QueryServiceConfig(IntPtr hService, IntPtr lpServiceConfig, uint cbBufSize, out uint pcbBytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool QueryServiceStatus(IntPtr hService, out SERVICE_STATUS lpServiceStatus);

        public record DivertServiceInfo(bool Exists, string? ImagePath, string? State);

        // READ-ONLY audit: does the singleton "WinDivert" service exist, which
        // .sys does it point at, and is it running? Never installs, starts,
        // stops, or deletes anything. Returns null when the SCM can't even be
        // queried (e.g. access denied) — "unknown", not "absent".
        public static DivertServiceInfo? GetServiceInfo()
        {
            IntPtr scm = IntPtr.Zero, svc = IntPtr.Zero;
            try
            {
                scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
                if (scm == IntPtr.Zero) return null;
                svc = OpenService(scm, "WinDivert", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
                if (svc == IntPtr.Zero)
                {
                    // 1060 = service does not exist. Anything else (e.g. 5 =
                    // access denied) means we simply couldn't tell.
                    return Marshal.GetLastWin32Error() == 1060
                        ? new DivertServiceInfo(false, null, null)
                        : null;
                }
                string? image = null;
                try
                {
                    QueryServiceConfig(svc, IntPtr.Zero, 0, out var need);
                    if (need > 0 && need < 256 * 1024)
                    {
                        var buf = Marshal.AllocHGlobal((int)need);
                        try
                        {
                            if (QueryServiceConfig(svc, buf, need, out _))
                            {
                                // QUERY_SERVICE_CONFIG: 3 DWORDs, then lpBinaryPathName pointer.
                                var p = Marshal.ReadIntPtr(buf, IntPtr.Size * 3);
                                if (p != IntPtr.Zero)
                                    image = Marshal.PtrToStringUni(p);
                            }
                        }
                        finally { Marshal.FreeHGlobal(buf); }
                    }
                }
                catch { }
                string? state = null;
                try
                {
                    if (QueryServiceStatus(svc, out var st))
                        state = st.dwCurrentState switch
                        {
                            1 => "stopped",
                            2 => "starting",
                            3 => "stopping",
                            4 => "running",
                            5 => "resuming",
                            6 => "pausing",
                            7 => "paused",
                            _ => "state " + st.dwCurrentState,
                        };
                }
                catch { }
                return new DivertServiceInfo(true, image, state);
            }
            catch { return null; }
            finally
            {
                if (svc != IntPtr.Zero) { try { CloseServiceHandle(svc); } catch { } }
                if (scm != IntPtr.Zero) { try { CloseServiceHandle(scm); } catch { } }
            }
        }

        public static bool? ServiceExists()
        {
            IntPtr scm = IntPtr.Zero, svc = IntPtr.Zero;
            try
            {
                scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
                if (scm == IntPtr.Zero) return null;
                svc = OpenService(scm, "WinDivert", SERVICE_QUERY_STATUS);
                if (svc != IntPtr.Zero) return true;
                // 1060 = does not exist. Anything else (e.g. 5 = access
                // denied) means "unknown" — callers must NOT record "created"
                // (which would later authorize touching a foreign driver).
                return Marshal.GetLastWin32Error() == 1060 ? false : null;
            }
            catch { return null; }
            finally
            {
                if (svc != IntPtr.Zero) { try { CloseServiceHandle(svc); } catch { } }
                if (scm != IntPtr.Zero) { try { CloseServiceHandle(scm); } catch { } }
            }
        }

        public static string RemoveService()
        {
            IntPtr scm = IntPtr.Zero, svc = IntPtr.Zero;
            try
            {
                scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
                if (scm == IntPtr.Zero)
                    return "Could not open Service Manager (need admin) — WinDivert service left as-is (harmless when PTor isn't running).";
                svc = OpenService(scm, "WinDivert", SERVICE_STOP | DELETE_ACCESS);
                if (svc == IntPtr.Zero)
                    return "WinDivert service not present — nothing to remove.";
                try { ControlService(svc, SERVICE_CONTROL_STOP, out _); } catch { }
                if (!DeleteService(svc))
                {
                    var err = Marshal.GetLastWin32Error();
                    return $"Could not delete WinDivert service (win32 {err}) — left installed (harmless without PTor running).";
                }
                return "WinDivert driver service removed.";
            }
            catch (Exception ex)
            {
                return "Driver service removal failed: " + ex.Message + " (harmless without PTor running).";
            }
            finally
            {
                if (svc != IntPtr.Zero) { try { CloseServiceHandle(svc); } catch { } }
                if (scm != IntPtr.Zero) { try { CloseServiceHandle(scm); } catch { } }
            }
        }

        public static string DescribeOpenError(int code, string filter)
        {
            try
            {
                return code switch
                {
                    2 => "WinDivert driver files not found next to PTor (tools\\WinDivert) — reinstall PTor's tools folder.",
                    5 => "WinDivert needs administrator rights — restart PTor as administrator.",
                    87 => $"Driver rejected the filter string (bug — report it): {filter}",
                    577 => "Driver signature blocked (Secure Boot policy or antivirus). Check AV quarantine / Secure Boot settings.",
                    654 => "An incompatible WinDivert version is already loaded (another app?). Close it first.",
                    1275 => "Driver blocked (antivirus or VM without driver support). Whitelist PTor or run on bare metal.",
                    1753 => "Base Filtering Engine service is disabled — re-enable it in services.msc.",
                    _ => $"WinDivert failed to start (win32 {code})."
                };
            }
            catch { return $"WinDivert failed to start (win32 {code})."; }
        }
    }
}
