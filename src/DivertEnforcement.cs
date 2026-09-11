using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace PTor
{

    public class DivertEnforcement : IDisposable
    {
        public const string Filter = "outbound and (ip or ipv6)";

        readonly Func<int?> _getTorPid;
        readonly Func<HashSet<int>> _getExtraPids;
        readonly Action<string> _log;

        // Handle ownership moves exactly once (Interlocked.Exchange); the I/O
        // loop reads it via Volatile.Read so teardown is observed immediately.
        IntPtr _handle = IntPtr.Zero;
        Thread? _thread;
        volatile bool _stop;
        int _disposed;
        int _generation;
        readonly object _lifeGate = new();
        volatile bool _running;
        long _allowed;
        long _dropped;
        long _ttlNormalized;
        int _sendFails;

        Dictionary<(bool v6, byte proto, ushort port), int> _owners = new();
        DateTime _ownersAt = DateTime.MinValue;
        DateTime _lastMissRefresh = DateTime.MinValue;

        const double OwnersRefreshMs = 250;
        const double MissRefreshMinGapMs = 20;

        public bool Running => _running;
        public long Allowed => Interlocked.Read(ref _allowed);
        public long Dropped => Interlocked.Read(ref _dropped);
        public long TtlNormalized => Interlocked.Read(ref _ttlNormalized);

        // Verified tor-child transport PIDs; refreshed slower than the
        // socket table since Toolhelp walks cost queue-drain time.
        HashSet<int> _extra = new();
        DateTime _extraAt = DateTime.MinValue;
        const double ExtraRefreshMs = 2000;

        public DivertEnforcement(Func<int?> getTorPid, Action<string> log, Func<HashSet<int>>? getExtraPids = null)
        {
            _getTorPid = getTorPid;
            _getExtraPids = getExtraPids ?? (() => new HashSet<int>());
            _log = log;
        }

        public static string? LocateDriverDir(string appDir)
        {
            try
            {
                var sub = Environment.Is64BitProcess ? "x64" : "x86";
                var dir = Path.Combine(appDir, "tools", "WinDivert", sub);
                var dll = Path.Combine(dir, "WinDivert.dll");
                var sys = Path.Combine(dir, Environment.Is64BitProcess ? "WinDivert64.sys" : "WinDivert32.sys");
                return (File.Exists(dll) && File.Exists(sys)) ? dir : null;
            }
            catch { return null; }
        }

        public static bool DriverFilesPresent(string appDir) => LocateDriverDir(appDir) != null;

        public void Start(string appDir)
        {
            Thread? thread;
            lock (_lifeGate)
            {
                if (_running) return;
                if (!AdminHelper.IsAdministrator())
                    throw new NeedAdminException("Packet enforcement needs administrator rights — restart PTor as administrator.");
                var dir = LocateDriverDir(appDir)
                    ?? throw new FileNotFoundException(
                        "WinDivert driver files not found (expected tools\\WinDivert\\x64 or \\x86 with WinDivert.dll + .sys).");

                try { DivertNative.SetDllDirectory(dir); } catch { }

                // Pre-flight: a foreign WinDivert service must never be
                // reinstalled over or mistaken for ours. Sharing works when
                // versions match, so only warn — Open's error mapping (654 =
                // version clash) covers the failure case.
                try
                {
                    var svc = DivertNative.GetServiceInfo();
                    if (svc != null && svc.Exists)
                    {
                        var sys = Path.Combine(dir,
                            Environment.Is64BitProcess ? "WinDivert64.sys" : "WinDivert32.sys");
                        bool staleOurs = false;
                        try
                        {
                            var cp = EnforcementCheckpoint.Load();
                            staleOurs = cp != null && cp.DriverService == "created";
                        }
                        catch { }
                        if (!staleOurs && !DivertBootAudit.ServiceLooksOurs(sys, svc.ImagePath))
                            _log("WinDivert service already present and NOT PTor's (" +
                                (svc.ImagePath ?? "unknown path") + ") — reusing it as-is, installing nothing. " +
                                "If this fails, close the other WinDivert app first.");
                    }
                }
                catch { }

                IntPtr h;
                try
                {
                    h = DivertNative.Open(Filter, DivertNative.LAYER_NETWORK, 0, 0);
                }
                catch (DllNotFoundException ex)
                {
                    throw new FileNotFoundException("WinDivert.dll failed to load from " + dir + ": " + ex.Message);
                }
                if (h == IntPtr.Zero || h == DivertNative.INVALID_HANDLE)
                    throw new InvalidOperationException(DivertNative.DescribeOpenError(Marshal.GetLastWin32Error(), Filter));

                try { DivertNative.SetParam(h, DivertNative.PARAM_QUEUE_TIME, 500); } catch { }

                _handle = h;
                _stop = false;
                _disposed = 0;
                System.Threading.Interlocked.Increment(ref _generation);
                _sendFails = 0;
                _owners = new Dictionary<(bool v6, byte proto, ushort port), int>();
                _ownersAt = DateTime.MinValue;
                _extra = new HashSet<int>();
                _extraAt = DateTime.MinValue;
                _lastMissRefresh = DateTime.MinValue;
                // Field published before Thread.Start: visible to the new thread.
                thread = _thread = new Thread(Loop) { IsBackground = true, Name = "PTor-Divert" };
                _running = true;
            }
            thread.Start();
        }

        public void Stop() => Dispose();

        static bool ValidHandle(IntPtr h) => h != IntPtr.Zero && h != DivertNative.INVALID_HANDLE;

        public void Dispose()
        {
            // Exactly-once ownership transfer: concurrent Dispose/FailOpen
            // calls each get the handle at most once — never double-closed.
            if (System.Threading.Interlocked.Exchange(ref _disposed, 1) == 1) return;
            _stop = true;
            System.Threading.Interlocked.Increment(ref _generation);
            var h = System.Threading.Interlocked.Exchange(ref _handle, IntPtr.Zero);
            lock (_lifeGate) { _thread = null; }
            if (ValidHandle(h))
            {
                try { DivertNative.Shutdown(h, DivertNative.SHUTDOWN_BOTH); } catch { }
            }
            // No Join: a parked Recv fails immediately on the closed handle
            // below, and the generation guard makes the stray loop exit
            // without touching anything. Joining only ever waited on an
            // already-doomed thread; skipping it keeps stops instant even
            // against a wedged driver (worst case one ghost thread holding
            // its own buffers until process death).
            if (ValidHandle(h))
            {
                try { DivertNative.Close(h); } catch { }
            }
            _running = false;
        }

        void FailOpen(string why, int loopGen)
        {
            try
            {
                // Stale generation must not close another generation's handle.
                if (loopGen != System.Threading.Volatile.Read(ref _generation)) return;
                _stop = true;
                // Same exactly-once transfer as Dispose.
                var h = System.Threading.Interlocked.Exchange(ref _handle, IntPtr.Zero);
                if (ValidHandle(h))
                {
                    try { DivertNative.Shutdown(h, DivertNative.SHUTDOWN_BOTH); } catch { }
                    try { DivertNative.Close(h); } catch { }
                }
                _running = false;
                try { _log("Divert loop died (" + why + ") — handle closed, traffic back to normal. Re-enable to resume."); }
                catch { }
            }
            catch { }
        }

        void Loop()
        {
            var h = System.Threading.Volatile.Read(ref _handle);
            if (!ValidHandle(h)) return;
            var gen = System.Threading.Volatile.Read(ref _generation);
            IntPtr pkt = IntPtr.Zero, addr = IntPtr.Zero;
            try
            {
                pkt = Marshal.AllocHGlobal(DivertNative.PACKET_BUF_SIZE);
                addr = Marshal.AllocHGlobal(DivertNative.ADDR_SIZE);
                while (!_stop)
                {
                    if (gen != System.Threading.Volatile.Read(ref _generation)) return;
                    if (!ValidHandle(System.Threading.Volatile.Read(ref _handle))) return;
                    uint recvLen = 0;
                    bool ok;
                    try
                    {
                        ok = DivertNative.Recv(h, pkt, DivertNative.PACKET_BUF_SIZE, out recvLen, addr);
                    }
                    catch { FailOpen("recv fault", gen); return; }
                    if (_stop) return;
                    if (!ok)
                    {
                        var err = Marshal.GetLastWin32Error();
                        if (err == 232) return; // driver shutdown under us
                        if (_stop || !ValidHandle(System.Threading.Volatile.Read(ref _handle))) return;
                        continue;
                    }

                    bool allow;
                    bool torTcp = false, pktV6 = false;
                    try { allow = Classify(pkt, (int)recvLen, addr, out torTcp, out pktV6); }
                    catch { Interlocked.Increment(ref _dropped); continue; }

                    if (!allow) { Interlocked.Increment(ref _dropped); continue; }

                    // Tor-attested outbound TCP only: pin TTL against OS fingerprinting.
                    if (torTcp && EgressNormalizer.TryNormalizeTtl(pkt, (int)recvLen, pktV6, 6))
                        Interlocked.Increment(ref _ttlNormalized);

                    bool sent = false;
                    try { sent = DivertNative.Send(h, pkt, recvLen, IntPtr.Zero, addr); }
                    catch { FailOpen("send fault", gen); return; }
                    if (sent)
                    {
                        _sendFails = 0;
                        Interlocked.Increment(ref _allowed);
                    }
                    else if (++_sendFails >= 50)
                    {
                        FailOpen("50 consecutive send failures", gen);
                        return;
                    }
                    else Interlocked.Increment(ref _dropped);
                }
            }
            catch { try { FailOpen("loop fault", gen); } catch { } }
            finally
            {
                if (pkt != IntPtr.Zero) { try { Marshal.FreeHGlobal(pkt); } catch { } }
                if (addr != IntPtr.Zero) { try { Marshal.FreeHGlobal(addr); } catch { } }
            }
        }

        internal static bool IsV6LocalScope(IntPtr pkt, int len)
        {
            // Dst is at fixed offset 24..39. Link-local/multicast never route.
            try
            {
                if (len < 40) return false;
                var b0 = Marshal.ReadByte(pkt, 24);
                if (b0 == 0xFF) return true;
                if (b0 != 0xFE) return false;
                return (Marshal.ReadByte(pkt, 25) & 0xC0) == 0x80;
            }
            catch { return false; }
        }

        internal bool Classify(IntPtr pkt, int len, IntPtr addr, out bool torTcp, out bool v6)
        {
            torTcp = false;
            v6 = false;
            if (len < 20) return false;
            uint flags;
            try { flags = (uint)Marshal.ReadInt32(addr, 8); }
            catch { return false; }
            if (((flags >> DivertNative.FLAG_LOOPBACK_BIT) & 1) == 1) return true;
            if (((flags >> DivertNative.FLAG_OUTBOUND_BIT) & 1) == 0) return true;
            v6 = ((flags >> DivertNative.FLAG_IPV6_BIT) & 1) == 1;
            return v6 ? ClassifyV6(pkt, len, out torTcp) : ClassifyV4(pkt, len, out torTcp);
        }

        bool ClassifyV4(IntPtr pkt, int len, out bool torTcp)
        {
            torTcp = false;
            byte b0;
            try
            {
                b0 = Marshal.ReadByte(pkt, 0);
                if ((b0 >> 4) != 4) return false;
                int ihl = (b0 & 0xF) * 4;
                if (ihl < 20 || len < ihl) return false;
                byte proto = Marshal.ReadByte(pkt, 9);
                byte f1 = Marshal.ReadByte(pkt, 6), f2 = Marshal.ReadByte(pkt, 7);
                if ((((f1 & 0x1F) << 8) | f2) != 0) return true; // non-first fragment: unattributable; lone fragments can't reassemble into usable exfil
                // Default-deny below TCP/UDP (Tor is TCP-only). Ping dies under lockdown: intended.
                if (proto != 6 && proto != 17) return false;
                if (len < ihl + 4) return false;
                ushort sport = (ushort)((Marshal.ReadByte(pkt, ihl) << 8) | Marshal.ReadByte(pkt, ihl + 1));
                ushort dport = (ushort)((Marshal.ReadByte(pkt, ihl + 2) << 8) | Marshal.ReadByte(pkt, ihl + 3));
                if (proto == 17 && (dport == 67 || dport == 68 || sport == 67 || sport == 68))
                    return true;
                if (proto == 6)
                {
                    torTcp = IsTorPort(false, proto, sport);
                    return torTcp;
                }
                return IsTorPort(false, proto, sport);
            }
            catch { return false; }
        }

        bool ClassifyV6(IntPtr pkt, int len, out bool torTcp)
        {
            torTcp = false;
            try
            {
                if (len < 40) return false;
                if ((Marshal.ReadByte(pkt, 0) >> 4) != 6) return false;
                byte next = Marshal.ReadByte(pkt, 6);
                int p = 40;
                while (true)
                {
                    if (next == 6 || next == 17) break;
                    if (next == 50) return false; // ESP/tunnel exfil: Tor is TCP-only
                    if (next == 59) return true; // No Next Header: carries no payload
                    if (next == 44)
                    {
                        if (p + 8 > len) return false;
                        int off = ((Marshal.ReadByte(pkt, p + 2) & 0xF8) << 5) | Marshal.ReadByte(pkt, p + 3);
                        if (off != 0) return true;
                        next = Marshal.ReadByte(pkt, p);
                        p += 8;
                        continue;
                    }
                    if (next == 51)
                    {
                        if (p + 4 > len) return false;
                        int hlen = (Marshal.ReadByte(pkt, p + 1) + 2) * 4;
                        if (p + hlen > len) return false; // truncated ext header: unattributable, drop
                        next = Marshal.ReadByte(pkt, p);
                        p += hlen;
                        continue;
                    }
                    if (next == 0 || next == 43 || next == 60 || next == 135 || next == 140 || next == 151)
                    {
                        if (p + 2 > len) return false;
                        int hlen = Marshal.ReadByte(pkt, p + 1) * 8 + 8;
                        if (p + hlen > len) return false; // truncated ext header: unattributable, drop
                        next = Marshal.ReadByte(pkt, p);
                        p += hlen;
                        continue;
                    }
                    // Default-deny trailers/tunnels; link-local ICMPv6 only (NDP/MLD).
                    if (next == 59) return true;
                    if (next == 58) return IsV6LocalScope(pkt, len);
                    return false;
                }
                if (p + 4 > len) return false;
                ushort sport = (ushort)((Marshal.ReadByte(pkt, p) << 8) | Marshal.ReadByte(pkt, p + 1));
                ushort dport = (ushort)((Marshal.ReadByte(pkt, p + 2) << 8) | Marshal.ReadByte(pkt, p + 3));
                if (next == 17 && (dport == 546 || dport == 547 || sport == 546 || sport == 547))
                    return true;
                if (next == 6)
                {
                    torTcp = IsTorPort(true, next, sport);
                    return torTcp;
                }
                return IsTorPort(true, next, sport);
            }
            catch { return false; }
        }

        // Hot path: full table walks are throttled (250ms periodic, 20ms
        // min-gap forced refresh only on truly-unknown ports). A known
        // foreign owner is a cheap final "no" without re-snapshotting.
        bool IsTorPort(bool v6, byte proto, ushort sport)
        {
            int? torPid = null;
            try { torPid = _getTorPid(); } catch { }
            if (torPid == null) return false;
            try
            {
                var now = DateTime.UtcNow;
                RefreshExtraPids(now);
                if ((now - _ownersAt).TotalMilliseconds >= OwnersRefreshMs)
                {
                    _owners = AppTrafficMonitor.SnapshotOwners();
                    _ownersAt = now;
                }

                var key = (v6, proto, sport);

                // Transport processes egress like tor itself (Snowflake needs
                // direct UDP; all need direct TCP).
                bool IsAllowedPid(int pid) => pid == torPid.Value || _extra.Contains(pid);

                if (_owners.TryGetValue(key, out var pid))
                    return IsAllowedPid(pid);

                // Genuinely-unknown port (e.g. fresh socket past the last
                // snapshot): one forced refresh, throttled against table-hammering.
                if ((now - _lastMissRefresh).TotalMilliseconds >= MissRefreshMinGapMs)
                {
                    _owners = AppTrafficMonitor.SnapshotOwners();
                    _ownersAt = now;
                    _lastMissRefresh = now;
                    if (_owners.TryGetValue(key, out var pid2))
                        return IsAllowedPid(pid2);
                }

                return false;
            }
            catch { return false; }
        }

        internal void RefreshExtraPids(DateTime now)
        {
            try
            {
                if ((now - _extraAt).TotalMilliseconds < ExtraRefreshMs) return;
                _extra = _getExtraPids() ?? new HashSet<int>();
                _extraAt = now;
            }
            catch { }
        }
    }
}