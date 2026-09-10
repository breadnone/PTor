using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PTor
{

    public static class AppTrafficMonitor
    {
        public class PidStats
        {
            public int ProxyTcp;
            public int DirectTcp;
            public int LocalTcp;
            public int Udp;
        }

        public static (string label, int kind, string detail) Verdict(PidStats? s)
        {
            if (s == null) return ("Idle", 0, "no connections");
            var udpNote = s.Udp > 0 ? $" · {s.Udp} UDP direct" : "";
            if (s.DirectTcp > 0)
                return ("Direct", 2, $"{s.DirectTcp} direct · {s.ProxyTcp} via Tor" + udpNote);
            if (s.ProxyTcp > 0)
                return ("Routed", 1, $"{s.ProxyTcp} via Tor" + udpNote);
            if (s.LocalTcp > 0)
                return ("Local", 3, "loopback only" + udpNote);
            return s.Udp > 0 ? ("UDP only", 3, $"{s.Udp} UDP direct (Tor can't relay UDP)") : ("Idle", 0, "no connections");
        }

        public static Dictionary<(bool v6, byte proto, ushort port), int> SnapshotOwners()
        {
            var m = new Dictionary<(bool v6, byte proto, ushort port), int>();
            try
            {
                ReadTcpOwners(m, AF_INET);
                ReadTcpOwners(m, AF_INET6);
                ReadUdpOwners(m, AF_INET);
                ReadUdpOwners(m, AF_INET6);
            }
            catch { }
            return m;
        }

        static void ReadTcpOwners(Dictionary<(bool v6, byte proto, ushort port), int> m, int family)
        {
            uint Query(IntPtr p, ref int l) =>
                GetExtendedTcpTable(p, ref l, false, family, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            var buf = AllocTable(Query);
            if (buf == IntPtr.Zero) return;
            try
            {
                var count = (uint)Marshal.ReadInt32(buf);
                if (count > 200000) return;
                var v6 = family == AF_INET6;
                if (!v6)
                {
                    var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                    for (uint i = 0; i < count; i++)
                    {
                        var r = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(IntPtr.Add(buf, 4 + (int)i * rowSize));
                        m[(false, 6, PortU16(r.localPort))] = r.owningPid;
                    }
                }
                else
                {
                    var rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                    for (uint i = 0; i < count; i++)
                    {
                        var r = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(IntPtr.Add(buf, 4 + (int)i * rowSize));
                        m[(true, 6, PortU16(r.localPort))] = r.owningPid;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        static void ReadUdpOwners(Dictionary<(bool v6, byte proto, ushort port), int> m, int family)
        {
            uint Query(IntPtr p, ref int l) =>
                GetExtendedUdpTable(p, ref l, false, family, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            var buf = AllocTable(Query);
            if (buf == IntPtr.Zero) return;
            try
            {
                var count = (uint)Marshal.ReadInt32(buf);
                if (count > 200000) return;
                var v6 = family == AF_INET6;
                if (!v6)
                {
                    var rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
                    for (uint i = 0; i < count; i++)
                    {
                        var r = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(IntPtr.Add(buf, 4 + (int)i * rowSize));
                        m[(false, 17, PortU16(r.localPort))] = r.owningPid;
                    }
                }
                else
                {
                    var rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();
                    for (uint i = 0; i < count; i++)
                    {
                        var r = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(IntPtr.Add(buf, 4 + (int)i * rowSize));
                        m[(true, 17, PortU16(r.localPort))] = r.owningPid;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static int? GetTcpListenerOwner(ushort port)
        {
            try
            {
                uint Query(IntPtr p, ref int l) =>
                    GetExtendedTcpTable(p, ref l, false, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                var buf = AllocTable(Query);
                if (buf == IntPtr.Zero) return null;
                try
                {
                    var count = (uint)Marshal.ReadInt32(buf);
                    if (count > 200000) return null;
                    var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                    for (uint i = 0; i < count; i++)
                    {
                        var r = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(IntPtr.Add(buf, 4 + (int)i * rowSize));
                        if (r.state == MIB_TCP_STATE_LISTEN && PortU16(r.localPort) == port)
                            return r.owningPid;
                    }
                    return null;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            catch { return null; }
        }

        public static Dictionary<int, PidStats> Snapshot(int socksPort, int bridgePort)
        {
            var out_ = new Dictionary<int, PidStats>();
            try
            {
                ReadTcpTable(out_, AF_INET, socksPort, bridgePort);
                ReadTcpTable(out_, AF_INET6, socksPort, bridgePort);
                ReadUdpTable(out_, AF_INET);
                ReadUdpTable(out_, AF_INET6);
            }
            catch {  }
            return out_;
        }

        static PidStats For(Dictionary<int, PidStats> m, int pid)
        {
            if (!m.TryGetValue(pid, out var s)) { s = new PidStats(); m[pid] = s; }
            return s;
        }

        const int AF_INET = 2;
        const int AF_INET6 = 23;
        const uint NO_ERROR = 0;
        const uint ERROR_INSUFFICIENT_BUFFER = 122;
        const uint MIB_TCP_STATE_LISTEN = 2;
        const uint MIB_TCP_STATE_SYN_SENT = 3;
        const uint MIB_TCP_STATE_ESTAB = 5;

        enum TCP_TABLE_CLASS { TCP_TABLE_OWNER_PID_ALL = 5 }
        enum UDP_TABLE_CLASS { UDP_TABLE_OWNER_PID = 1 }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TCP_TABLE_CLASS tblClass, uint reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, UDP_TABLE_CLASS tblClass, uint reserved);

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr;
            public uint localScopeId;
            public uint localPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] remoteAddr;
            public uint remoteScopeId;
            public uint remotePort;
            public uint state;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            public uint localPort;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_UDP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr;
            public uint localScopeId;
            public uint localPort;
            public int owningPid;
        }

        static int PortFromDword(uint v) => PortU16(v);
        static ushort PortU16(uint v) => (ushort)(((v & 0xFF) << 8) | ((v >> 8) & 0xFF));
        static bool IsV4Loopback(uint addr) => (addr & 0xFF) == 0x7F;
        static bool IsV6Loopback(byte[] a)
        {
            if (a == null || a.Length != 16) return false;
            for (var i = 0; i < 15; i++) if (a[i] != 0) return false;
            return a[15] == 1;
        }

        static bool IsV6Unspecified(byte[] a)
        {
            if (a == null || a.Length != 16) return false;
            for (var i = 0; i < 16; i++) if (a[i] != 0) return false;
            return true;
        }

        delegate uint TableQuery(IntPtr buf, ref int len);

        static IntPtr AllocTable(TableQuery query)
        {
            int len = 0;
            query(IntPtr.Zero, ref len);
            if (len <= 0 || len > 64 * 1024 * 1024) return IntPtr.Zero;
            var buf = Marshal.AllocHGlobal(len);
            if (query(buf, ref len) != NO_ERROR) { Marshal.FreeHGlobal(buf); return IntPtr.Zero; }
            return buf;
        }

        static void ReadTcpTable(Dictionary<int, PidStats> m, int family, int socksPort, int bridgePort)
        {
            uint Query(IntPtr p, ref int l) =>
                GetExtendedTcpTable(p, ref l, false, family, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            var buf = AllocTable(Query);
            if (buf == IntPtr.Zero) return;
            try
            {
                var count = (uint)Marshal.ReadInt32(buf);
                if (count > 200000) return;
                if (family == AF_INET)
                {
                    var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                    for (uint i = 0; i < count; i++)
                    {
                        var r = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(IntPtr.Add(buf, 4 + (int)i * rowSize));
                        if (r.state != MIB_TCP_STATE_ESTAB && r.state != MIB_TCP_STATE_SYN_SENT) continue;
                        if (r.remoteAddr == 0) continue;
                        var port = PortFromDword(r.remotePort);
                        var s = For(m, r.owningPid);
                        if (IsV4Loopback(r.remoteAddr))
                        {
                            if (port == socksPort || port == bridgePort) s.ProxyTcp++;
                            else s.LocalTcp++;
                        }
                        else s.DirectTcp++;
                    }
                }
                else
                {
                    var rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                    for (uint i = 0; i < count; i++)
                    {
                        var r = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(IntPtr.Add(buf, 4 + (int)i * rowSize));
                        if (r.state != MIB_TCP_STATE_ESTAB && r.state != MIB_TCP_STATE_SYN_SENT) continue;
                        if (IsV6Unspecified(r.remoteAddr)) continue;
                        var port = PortFromDword(r.remotePort);
                        var s = For(m, r.owningPid);
                        if (IsV6Loopback(r.remoteAddr))
                        {
                            if (port == socksPort || port == bridgePort) s.ProxyTcp++;
                            else s.LocalTcp++;
                        }
                        else s.DirectTcp++;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        static void ReadUdpTable(Dictionary<int, PidStats> m, int family)
        {
            uint Query(IntPtr p, ref int l) =>
                GetExtendedUdpTable(p, ref l, false, family, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            var buf = AllocTable(Query);
            if (buf == IntPtr.Zero) return;
            try
            {
                var count = (uint)Marshal.ReadInt32(buf);
                if (count > 200000) return;
                if (family == AF_INET)
                {
                    var rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
                    for (uint i = 0; i < count; i++)
                    {
                        var r = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(IntPtr.Add(buf, 4 + (int)i * rowSize));
                        if (!IsV4Loopback(r.localAddr)) For(m, r.owningPid).Udp++;
                    }
                }
                else
                {
                    var rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();
                    for (uint i = 0; i < count; i++)
                    {
                        var r = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(IntPtr.Add(buf, 4 + (int)i * rowSize));
                        if (!IsV6Loopback(r.localAddr)) For(m, r.owningPid).Udp++;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        static readonly Dictionary<int, string> _pathCache = new();
        static readonly object _cacheGate = new();

        public static void PruneCache(HashSet<int> livePids)
        {
            try
            {
                lock (_cacheGate)
                {
                    if (_pathCache.Count == 0) return;
                    var dead = new List<int>();
                    foreach (var pid in _pathCache.Keys)
                    {
                        if (livePids.Contains(pid)) continue;
                        if (!RunningAppEnumerator.IsPidAlive(pid)) dead.Add(pid);
                    }
                    foreach (var pid in dead) _pathCache.Remove(pid);
                }
            }
            catch { }
        }
    }
}
