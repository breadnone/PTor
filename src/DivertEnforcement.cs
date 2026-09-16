using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

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
        // Consecutive Recv-false streak (loop thread only, like _sendFails).
        // A blocking Recv returns true with a packet in normal operation;
        // false is always an error/shutdown signal. Reset on every packet.
        int _recvFails;

        Dictionary<(bool v6, byte proto, ushort port), int> _owners = new();
        DateTime _ownersAt = DateTime.MinValue;

        // Unknown-port verdicts, cached briefly so a busy foreign socket
        // (QUIC, scans) costs one table walk per TTL instead of one per
        // packet. Only SAME-port repeats are throttled this way: every NEW
        // port always gets an authoritative snapshot first, so attribution
        // is immediate from the moment a process spawns.
        Dictionary<(bool v6, byte proto, ushort port), DateTime> _negMiss = new();
        const int NegMissCap = 4096;

        const double OwnersRefreshMs = 100;
        const double NegMissTtlMs = 100;

        // Cached ALLOW verdicts go stale in the leak direction (a freed
        // tor source port rebound by another app reads as allowed until
        // the next refresh), while stale DENY verdicts fail closed (drop).
        // So allows revalidate against a fresh table once it is older
        // than this; denies trust the periodic cache. Bounds the
        // port-reuse leak window to ~AllowRevalidateMs + one walk.
        const double AllowRevalidateMs = 50;

        // Recently-freed ex-tor/transport ports: any packet claiming one
        // forces an authoritative walk instead of trusting any cache, so
        // an immediate rebind can never ride the stale allow. Small and
        // short-lived (tor churn is low); swept on every refresh.
        Dictionary<(bool v6, byte proto, ushort port), DateTime> _quarantine = new();
        const double QuarantineTtlMs = 4000;
        const int QuarantineCap = 8192;
        HashSet<(bool v6, byte proto, ushort port)> _allowedPorts = new();

        public bool Running => _running;
        public long Allowed => Interlocked.Read(ref _allowed);
        public long Dropped => Interlocked.Read(ref _dropped);
        public long TtlNormalized => Interlocked.Read(ref _ttlNormalized);
        // Fail-closed latch: set when the loop gives up reinjecting (see
        // FailClosed). The handle stays open and diverted packets keep
        // dropping instead of flowing direct — lockdown holds, broken.
        // Cleared on the next Start; the engine surfaces it via the log.
        public bool Degraded => _degraded;
        volatile bool _degraded;

        // Verified tor-child transport PIDs. Refreshed TOGETHER with the
        // socket table (see RefreshAttribution): the sport->pid verdict and
        // the pid->allowed verdict always come from the same instant, so a
        // just-spawned helper is never denied by a stale transport list.
        HashSet<int> _extra = new();

        // Last tor PID seen. A restart (or death) invalidates every cached
        // verdict, so a recycled PID can never inherit a stale allow and a
        // fresh tor never pays for the old one's table entries.
        int? _lastTorPid = null;

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

        // Refuse-fast gate for foreign drivers. True = do NOT attempt Open:
        // the service exists, is not provably stale-ours, and its image is a
        // KNOWN path that isn't ours. Unknown/unreadable images fail open to
        // the attempt itself (a version clash still errors fast via 654), so
        // a mere SCM read hiccup can't brick lockdown. Never throws.
        internal static bool IsForeignDriverBlock(string? ourSysPath, string? serviceImagePath, bool staleCheckpointOurs)
        {
            try
            {
                if (staleCheckpointOurs) return false;
                if (string.IsNullOrWhiteSpace(serviceImagePath)) return false;
                if (string.IsNullOrWhiteSpace(ourSysPath)) return false;
                return !DivertBootAudit.ServiceLooksOurs(ourSysPath, serviceImagePath);
            }
            catch { return false; }
        }

        // Bounded WinDivertOpen: a wedged prior install can hang the native
        // open indefinitely (wedged SCM/driver). Fails with a TimeoutException
        // instead of hanging the app. A handle that arrives after the timeout
        // is abandoned (dies with the process; its undrained queue only drops
        // ITS copies). Throws FileNotFoundException (dll) /
        // InvalidOperationException (open error) / TimeoutException.
        static IntPtr OpenBounded(string filter, string dirForMessage)
        {
            var task = Task.Run(() =>
            {
                try
                {
                    var h = DivertNative.Open(filter, DivertNative.LAYER_NETWORK, 0, 0);
                    // Read on THIS thread, immediately: the error belongs to Open.
                    return (handle: h, error: Marshal.GetLastWin32Error(), fault: (Exception?)null);
                }
                catch (Exception ex)
                {
                    return (handle: IntPtr.Zero, error: Marshal.GetLastWin32Error(), fault: (Exception?)ex);
                }
            });
            bool finished = false;
            try { finished = task.Wait(TimeSpan.FromSeconds(25)); }
            catch { }
            if (!finished)
                throw new TimeoutException(
                    "WinDivert driver did not respond within 25s (a previous driver install may be wedged: " +
                    "reboot, or run kill-windivert.bat as admin if the service is PTor's). Lockdown NOT enabled.");
            var (handle, error, fault) = task.Result;
            if (fault is DllNotFoundException dllEx)
                throw new FileNotFoundException("WinDivert.dll failed to load from " + dirForMessage + ": " + dllEx.Message);
            if (fault != null)
                ExceptionDispatchInfo.Capture(fault).Throw();
            if (handle == IntPtr.Zero || handle == DivertNative.INVALID_HANDLE)
                throw new InvalidOperationException(DivertNative.DescribeOpenError(error, filter));
            return handle;
        }

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

                string? ourSys = null;
                try
                {
                    ourSys = Path.Combine(dir,
                        Environment.Is64BitProcess ? "WinDivert64.sys" : "WinDivert32.sys");
                }
                catch { }

                // Pre-flight: a foreign WinDivert service must never be
                // reinstalled over, shared, or mistaken for ours. Opening
                // into a live foreign filter stalls (two diverters fight
                // over packets) or clashes versions (654) — refuse fast
                // with the culprit named instead of hanging in Open.
                // Stale-OURS (same binary, checkpoint proves it) is safe to
                // reuse and proceeds.
                try
                {
                    var svc = DivertNative.GetServiceInfo();
                    if (svc != null && svc.Exists)
                    {
                        bool staleOurs = false;
                        try
                        {
                            var cp = EnforcementCheckpoint.Load();
                            staleOurs = cp != null && EnforcementCheckpoint.IsOurs(cp.DriverService);
                        }
                        catch { }
                        if (IsForeignDriverBlock(ourSys, svc.ImagePath, staleOurs))
                            throw new InvalidOperationException(
                                "A WinDivert driver from another app is already loaded (" +
                                (svc.ImagePath ?? "unknown path") + "). Close that app first, then enable " +
                                "lockdown — PTor will not share a live foreign filter (they fight over packets and stall). " +
                                "If that app is already gone but its service lingers, remove it with " +
                                "`sc delete WinDivert` (as admin) only if you're sure nothing owns it.");
                        // Own stale service (handover restart / crash leftover)
                        // already running: reuse it — Open below just takes
                        // another handle on the live driver, no reinstall, no
                        // second instance. Foreign is refused above, never here.
                        if (staleOurs)
                        {
                            try { _log("Reusing own WinDivert service already running (restart handover / previous run) — opening a handle on it, no reinstall."); }
                            catch { }
                        }
                    }
                }
                catch (InvalidOperationException) { throw; }
                catch { }

                // Bounded open: a wedged prior install (wedged SCM/driver
                // from an unclean teardown) can hang Open indefinitely.
                IntPtr h = OpenBounded(Filter, dir);

                try { DivertNative.SetParam(h, DivertNative.PARAM_QUEUE_TIME, 500); } catch { }

                _handle = h;
                _stop = false;
                _disposed = 0;
                _degraded = false;
                System.Threading.Interlocked.Increment(ref _generation);
                _sendFails = 0;
                _recvFails = 0;
                _owners = new Dictionary<(bool v6, byte proto, ushort port), int>();
                _ownersAt = DateTime.MinValue;
                _negMiss = new Dictionary<(bool v6, byte proto, ushort port), DateTime>();
                _quarantine = new Dictionary<(bool v6, byte proto, ushort port), DateTime>();
                _allowedPorts = new HashSet<(bool v6, byte proto, ushort port)>();
                _lastTorPid = null;
                _extra = new HashSet<int>();
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
            // Exactly-once ownership transfer: concurrent Dispose calls each
            // get the handle at most once — never double-closed.
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

        // Driver-gone path: the OS-level filter itself is gone (driver
        // stopped/crashed under a live lockdown — Recv fails 232). Nothing
        // is held anymore, so this is the ONE case that reports DOWN instead
        // of degraded: _running goes false, the UI drops its LOCKDOWN badge
        // within a second and rows flip red, and the engine link-tick warns.
        // Claiming "degraded, still held" here would be a lie — packets flow
        // direct with no driver to queue them. Loud on purpose; re-toggle
        // lockdown to recover (a fresh Open fails loudly if the driver is
        // still gone). Never called on our own teardown (generation-guarded).
        void FailDriverGone(string why, int loopGen)
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
                try { _log("LOCKDOWN DOWN (" + why + ") — the WinDivert driver itself is gone, traffic is NOT held and may flow direct. Re-toggle lockdown to recover (re-enable fails loudly while the driver is still gone)."); }
                catch { }
            }
            catch { }
        }

        // Fail-CLOSED park: the driver is alive but our loop can't serve it
        // (Recv/Send faults, persistent Recv errors, Send exhaustion).
        // Closing the handle here would silently resume direct traffic UNDER
        // an active lockdown (a leak). Instead the handle stays open (driver
        // queue fills and diverted packets drop: breakage, never bypass),
        // the loop parks, and the user is told to re-toggle enforcement.
        // Every fault path in Loop() below uses this — except a proven
        // driver-gone 232, which uses FailDriverGone (nothing left to hold).
        void FailClosed(string why, int loopGen)
        {
            try
            {
                if (loopGen != System.Threading.Volatile.Read(ref _generation)) return;
                _degraded = true;
                // _running stays true (lockdown still owns the filter) and the
                // handle stays open: Dispose/teardown still work normally.
                try { _log("LOCKDOWN DEGRADED (" + why + ") — holding the filter (traffic fails closed, drops) instead of leaking direct. Toggle lockdown off/on to recover."); }
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
                    // Recv fault while lockdown is supposed to be on: NEVER
                    // report DOWN / close the handle here (that would
                    // silently resume direct traffic under an active
                    // lockdown = a random-after-time leak). FailClosed holds
                    // the filter (drops) and tells the user to re-toggle. A
                    // blind Recv still drops via the queued driver filter,
                    // so breakage — never bypass. (Proven driver-gone 232 is
                    // the only DOWN case — handled below.)
                    catch { FailClosed("recv fault", gen); return; }
                    if (_stop) return;
                    if (!ok)
                    {
                        var err = Marshal.GetLastWin32Error();
                        if (err == 232)
                        {
                            // 232 = driver shutdown under us. Silent ONLY on
                            // our own teardown (stop/dispose bumped the
                            // generation, set _stop, or already took the
                            // handle — FailDriverGone's guard no-ops there
                            // too). A live run hitting this lost the OS-level
                            // filter: report DOWN (never degraded — nothing
                            // is held) so the UI flips red instead of
                            // claiming Blocked.
                            if (_stop || gen != System.Threading.Volatile.Read(ref _generation) ||
                                !ValidHandle(System.Threading.Volatile.Read(ref _handle))) return;
                            FailDriverGone("driver shutdown under lockdown", gen);
                            return;
                        }
                        if (_stop || !ValidHandle(System.Threading.Volatile.Read(ref _handle))) return;
                        // Non-232 Recv errors must never hot-spin: a wedged
                        // driver failing every Recv would pin a CPU. Same
                        // philosophy as the Send path — sustained failure
                        // parks fail-closed (driver alive, we can't serve).
                        if (++_recvFails >= 50)
                        {
                            FailClosed("50 consecutive recv failures", gen);
                            return;
                        }
                        continue;
                    }
                    _recvFails = 0;

                    bool allow;
                    bool torTcp = false, pktV6 = false;
                    try { allow = Classify(pkt, (int)recvLen, addr, out torTcp, out pktV6); }
                    catch { Interlocked.Increment(ref _dropped); continue; }

                    if (!allow) { Interlocked.Increment(ref _dropped); continue; }

                    // Tor-attested outbound TCP only: pin TTL against OS fingerprinting.
                    if (torTcp && EgressNormalizer.TryNormalizeTtl(pkt, (int)recvLen, pktV6, 6))
                        Interlocked.Increment(ref _ttlNormalized);

                    bool sent = false;
                    // Send-path exception: same fail-closed rule as Recv —
                    // never close the handle on a fault (that leaks direct).
                    try { sent = DivertNative.Send(h, pkt, recvLen, IntPtr.Zero, addr); }
                    catch { FailClosed("send fault", gen); return; }
                    if (sent)
                    {
                        _sendFails = 0;
                        Interlocked.Increment(ref _allowed);
                    }
                    else if (++_sendFails >= 50)
                    {
                        FailClosed("50 consecutive send failures", gen);
                        return;
                    }
                    else Interlocked.Increment(ref _dropped);
                }
            }
            // Any unhandled loop fault: fail CLOSED (hold the filter), never
            // FailOpen — see the Recv catch above. An unknown fault that
            // closes the handle would read as "routing on, lockdown on" in
            // the UI while packets flow direct.
            catch { try { FailClosed("loop fault", gen); } catch { } }
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
                // DHCP only, as port PAIRS: client 68 <-> server 67. A bare
                // sport match would let any app bind 68 and exfil anywhere.
                if (proto == 17 && ((sport == 68 && dport == 67) || (sport == 67 && dport == 68)))
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
                        // 13-bit fragment offset: high 8 bits at p+2, low 5
                        // in the TOP bits of p+3 (low 3 are Res/M). A bare
                        // p+3 OR misreads first-fragments with M=1 as
                        // non-first and lets them bypass attribution.
                        int off = ((Marshal.ReadByte(pkt, p + 2) & 0xF8) << 5) | (Marshal.ReadByte(pkt, p + 3) >> 3);
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
                    // Default-deny trailers/tunnels; ICMPv6 only for local
                    // neighbor-discovery/multicast-listener control (types
                    // below) to a local scope. Echo (128/129) and everything
                    // else stay dropped: ping dies under lockdown by design,
                    // and echo payloads to link-local/multicast would be a
                    // LAN exfil channel.
                    if (next == 59) return true;
                    if (next == 58)
                    {
                        if (!IsV6LocalScope(pkt, len)) return false;
                        if (p >= len) return false;
                        var icmpType = Marshal.ReadByte(pkt, p);
                        return icmpType is 130 or 131 or 132 or 133 or 134 or 135 or 136 or 137 or 143;
                    }
                    return false;
                }
                if (p + 4 > len) return false;
                ushort sport = (ushort)((Marshal.ReadByte(pkt, p) << 8) | Marshal.ReadByte(pkt, p + 1));
                ushort dport = (ushort)((Marshal.ReadByte(pkt, p + 2) << 8) | Marshal.ReadByte(pkt, p + 3));
                // DHCPv6 only, as port PAIRS (client 546 <-> server 547).
                if (next == 17 && ((sport == 546 && dport == 547) || (sport == 547 && dport == 546)))
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

        // Hot path: the periodic table walk (100ms) serves known sockets;
        // anything else is resolved authoritatively, synchronously, on the
        // packet that needs it. A known foreign owner is a cheap final "no"
        // without re-snapshotting (stale deny fails closed); an UNKNOWN
        // port is never failed on stale data — that stale-miss drop is
        // what randomly broke reconnects and fresh transports, so unknown
        // ports re-resolve from the OS. The mirror image (stale ALLOW on a
        // recycled port) is a leak, so cached allows revalidate once older
        // than AllowRevalidateMs, and recently-freed ex-tor ports always
        // re-resolve (quarantine) — neither trusts a stale allow.
        bool IsTorPort(bool v6, byte proto, ushort sport)
        {
            int? torPid = null;
            try { torPid = _getTorPid(); } catch { }
            if (torPid == null) return false;
            try
            {
                var now = DateTime.UtcNow;
                if (_lastTorPid != torPid)
                {
                    // tor restarted (or first sighting): nothing cached about
                    // the old PID applies to the new one. Resolve now so the
                    // new daemon's first connection is already covered.
                    // Quarantine survives (freed ports stay suspect).
                    _lastTorPid = torPid;
                    _negMiss = new Dictionary<(bool v6, byte proto, ushort port), DateTime>();
                    RefreshAttribution(now, torPid.Value);
                }
                else if ((now - _ownersAt).TotalMilliseconds >= OwnersRefreshMs)
                {
                    RefreshAttribution(now, torPid.Value);
                }

                var key = (v6, proto, sport);

                // Transport processes egress like tor itself (Snowflake needs
                // direct UDP; all need direct TCP).
                bool IsAllowedPid(int pid) => pid == torPid.Value || _extra.Contains(pid);

                // Recently-freed ex-tor/transport port: a rebind candidate.
                // Never trust the periodic cache here — one authoritative
                // walk decides this packet (rare path: only recently-churned
                // ports). Still throttled by the miss cache: without it a
                // sustained flow on a rebound port would cost a full table
                // walk PER PACKET and saturate the loop thread (fail-closed
                // into DEGRADED). Throttled denies stay in the safe
                // direction; tor reclaiming the port is proven by the walk
                // below and clears the quarantine outright.
                if (IsQuarantined(key, now))
                {
                    if (_negMiss.TryGetValue(key, out var qmissed) &&
                        (now - qmissed).TotalMilliseconds < NegMissTtlMs)
                        return false;
                    var freshAt = DateTime.UtcNow;
                    RefreshAttribution(freshAt, torPid.Value);
                    if (_owners.TryGetValue(key, out var qpid))
                    {
                        if (IsAllowedPid(qpid))
                        {
                            try { _quarantine.Remove(key); } catch { }
                            return true;
                        }
                        NoteMiss(key, freshAt);
                        return false;
                    }
                    NoteMiss(key, freshAt);
                    return false;
                }

                if (_owners.TryGetValue(key, out var pid))
                {
                    // Stale deny fails closed — cheap final "no".
                    if (!IsAllowedPid(pid)) return false;
                    // Cached allow: revalidate once the table is older than
                    // AllowRevalidateMs, so a port tor freed and another app
                    // rebound can ride the stale entry for 50ms at most.
                    if ((now - _ownersAt).TotalMilliseconds >= AllowRevalidateMs)
                    {
                        var freshAt = DateTime.UtcNow;
                        RefreshAttribution(freshAt, torPid.Value);
                        if (_owners.TryGetValue(key, out var pid2))
                            return IsAllowedPid(pid2);
                        NoteMiss(key, freshAt);
                        return false;
                    }
                    return true;
                }

                // Unknown source port: a socket younger than our tables — a
                // process that just spawned, tor reconnecting, a bridge
                // helper dialing, an app opening its next connection. Take
                // ONE authoritative snapshot now, on this packet, instead of
                // failing it for being newer than the periodic cache.
                if (_negMiss.TryGetValue(key, out var missedAt) &&
                    (now - missedAt).TotalMilliseconds < NegMissTtlMs)
                    return false;

                var missAt = DateTime.UtcNow;
                RefreshAttribution(missAt, torPid.Value);
                if (_owners.TryGetValue(key, out var pid3))
                    return IsAllowedPid(pid3);

                NoteMiss(key, missAt);
                return false;
            }
            catch { return false; }
        }

        // Owners and transports refresh as one atomic step: the sport->pid
        // map and the pid->allowed set always describe the same instant.
        // Also diffs the allowed-port set: ports that just left tor-side
        // ownership enter quarantine so their immediate rebind re-resolves.
        void RefreshAttribution(DateTime now, int torPid)
        {
            var owners = AppTrafficMonitor.SnapshotOwners();
            HashSet<int> extra;
            try { extra = _getExtraPids() ?? new HashSet<int>(); }
            catch { extra = new HashSet<int>(); }
            _owners = owners;
            _ownersAt = now;
            _extra = extra;
            try
            {
                var allowed = new HashSet<(bool v6, byte proto, ushort port)>();
                foreach (var kv in owners)
                    if (kv.Value == torPid || extra.Contains(kv.Value))
                        allowed.Add(kv.Key);
                foreach (var k in _allowedPorts)
                    if (!allowed.Contains(k))
                        NoteQuarantine(k, now);
                _allowedPorts = allowed;
                SweepQuarantine(now);
            }
            catch { }
        }

        bool IsQuarantined((bool v6, byte proto, ushort port) key, DateTime now)
        {
            try
            {
                if (_quarantine.TryGetValue(key, out var since))
                {
                    if ((now - since).TotalMilliseconds < QuarantineTtlMs)
                        return true;
                    _quarantine.Remove(key);
                }
            }
            catch { }
            return false;
        }

        void NoteQuarantine((bool v6, byte proto, ushort port) key, DateTime now)
        {
            try
            {
                if (_quarantine.Count >= QuarantineCap)
                {
                    SweepQuarantine(now);
                    if (_quarantine.Count >= QuarantineCap) _quarantine.Clear();
                }
                _quarantine[key] = now;
                // The quarantine verdict supersedes any older miss-cache
                // entry for this port (it may predate tor's brief ownership).
                try { _negMiss.Remove(key); } catch { }
            }
            catch { }
        }

        void SweepQuarantine(DateTime now)
        {
            try
            {
                List<(bool v6, byte proto, ushort port)>? expired = null;
                foreach (var kv in _quarantine)
                    if ((now - kv.Value).TotalMilliseconds >= QuarantineTtlMs)
                        (expired ??= new List<(bool v6, byte proto, ushort port)>()).Add(kv.Key);
                if (expired != null)
                    foreach (var k in expired) _quarantine.Remove(k);
            }
            catch { }
        }

        void NoteMiss((bool v6, byte proto, ushort port) key, DateTime now)
        {
            try
            {
                if (_negMiss.Count >= NegMissCap)
                {
                    // Bound memory under a distinct-port flood: drop expired
                    // entries first, clear outright if still over budget.
                    // Worst case we re-walk the table a little more often;
                    // verdicts stay correct either way.
                    var expired = new List<(bool v6, byte proto, ushort port)>();
                    foreach (var kv in _negMiss)
                        if ((now - kv.Value).TotalMilliseconds >= NegMissTtlMs)
                            expired.Add(kv.Key);
                    foreach (var k in expired) _negMiss.Remove(k);
                    if (_negMiss.Count >= NegMissCap) _negMiss.Clear();
                }
                _negMiss[key] = now;
            }
            catch { }
        }
    }
}