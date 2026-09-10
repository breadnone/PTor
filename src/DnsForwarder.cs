using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{

    // Loopback-only DNS forwarder to Tor's DNSPort. No cache, verbatim
    // bytes, SERVFAIL (never clearnet) on upstream failure, fresh upstream
    // TCP per query, loopback bind only.
    public class DnsForwarder : IDisposable
    {
        public         const int ListenPort = 53;
        const int MaxUdpQuery = 4096;
        const int MaxTcpQuery = 65535;
        const int ExchangeTimeoutMs = 10000;

        readonly string _upstreamHost;
        readonly int _upstreamPort;
        readonly object _startGate = new();
        // In-flight caps; UDP sheds by drop (correct for DNS).
        readonly SemaphoreSlim _udpGate = new(128, 128);
        readonly SemaphoreSlim _tcpGate = new(64, 64);
        UdpClient? _udp;
        TcpListener? _tcp;
        CancellationTokenSource? _cts;
        int _disposed;

        int _forwarded;
        int _failed;
        int _blocked;
        public int Forwarded => Volatile.Read(ref _forwarded);
        public int Failed => Volatile.Read(ref _failed);
        public int Blocked => Volatile.Read(ref _blocked);

        public DnsForwarder(string upstreamHost, int upstreamPort)
        {
            _upstreamHost = upstreamHost;
            _upstreamPort = upstreamPort;
        }

        public void Start(int listenPort = ListenPort)
        {
            CancellationToken ct;
            lock (_startGate)
            {
                if (Volatile.Read(ref _disposed) == 1)
                    throw new ObjectDisposedException(nameof(DnsForwarder));
                if (_cts != null) return;
                UdpClient udp;
                TcpListener tcp;
                try { udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, listenPort)); }
                catch (Exception ex)
                {
                    throw new InvalidOperationException(
                        $"Could not bind UDP 127.0.0.1:{listenPort} (needs administrator rights for port 53; port may be held by another DNS service). " + ex.Message, ex);
                }
                try
                {
                    tcp = new TcpListener(IPAddress.Loopback, listenPort);
                    try { tcp.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true); } catch { }
                    tcp.Start();
                }
                catch (Exception ex)
                {
                    try { udp.Dispose(); } catch { }
                    throw new InvalidOperationException($"Could not bind TCP 127.0.0.1:{listenPort}. " + ex.Message, ex);
                }
                _udp = udp;
                _tcp = tcp;
                _cts = new CancellationTokenSource();
                ct = _cts.Token;
            }
            _ = UdpLoop(ct);
            _ = TcpAcceptLoop(ct);
        }

        async Task UdpLoop(CancellationToken ct)
        {
            var udp = _udp;
            if (udp == null) return;
            while (!ct.IsCancellationRequested)
            {
                UdpReceiveResult req;
                try { req = await udp.ReceiveAsync(ct); }
                catch { break; } // closed / shutting down
                if (req.Buffer == null || req.Buffer.Length < 12 || req.Buffer.Length > MaxUdpQuery) continue;
                bool admitted;
                try { admitted = await _udpGate.WaitAsync(0, ct); }
                catch { break; }
                if (!admitted) continue; // saturated: drop (standard DNS load-shedding)
                _ = HandleUdpCappedAsync(req.Buffer, req.RemoteEndPoint, ct);
            }
        }

        async Task HandleUdpCappedAsync(byte[] query, IPEndPoint replyTo, CancellationToken ct)
        {
            try { await HandleUdpQuery(query, replyTo, ct); }
            finally { try { _udpGate.Release(); } catch { } }
        }

        async Task HandleUdpQuery(byte[] query, IPEndPoint replyTo, CancellationToken ct)
        {
            var udp = _udp;
            if (udp == null) return;
            var qname = GetQueryName(query);
            // Special-use/local names are answered locally so they never
            // reach an exit. Nothing else is blocked here.
            if (qname != null && IsLocalBlock(qname))
            {
                var nx = BuildNxDomain(query);
                Interlocked.Increment(ref _blocked);
                if (nx != null)
                {
                    try { await udp.SendAsync(nx, replyTo, ct); }
                    catch { }
                }
                return;
            }
            byte[]? answer;
            try { answer = await ForwardOverTcpAsync(query, ct); }
            catch (OperationCanceledException) { return; }
            catch { answer = null; }
            if (ct.IsCancellationRequested) return;
            try
            {
                if (answer != null)
                {
                    Interlocked.Increment(ref _forwarded);
                    await udp.SendAsync(answer, replyTo, ct);
                }
                else
                {
                    Interlocked.Increment(ref _failed);
                    var fail = BuildServFail(query);
                    if (fail != null) await udp.SendAsync(fail, replyTo, ct);
                }
            }
            catch { }
        }

        async Task TcpAcceptLoop(CancellationToken ct)
        {
            var tcp = _tcp;
            if (tcp == null) return;
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await tcp.AcceptTcpClientAsync(ct); }
                catch { break; }
                bool admitted;
                try { admitted = await _tcpGate.WaitAsync(0, ct); }
                catch { try { client.Dispose(); } catch { } break; }
                if (!admitted) { try { client.Dispose(); } catch { } continue; }
                _ = HandleTcpCappedAsync(client, ct);
            }
        }

        async Task HandleTcpCappedAsync(TcpClient client, CancellationToken ct)
        {
            try { await HandleTcpClientAsync(client, ct); }
            finally { try { _tcpGate.Release(); } catch { } }
        }

        async Task HandleTcpClientAsync(TcpClient client, CancellationToken ct)
        {
            using (client)
            {
                NetworkStream stream;
                try { stream = client.GetStream(); }
                catch { return; }
                while (!ct.IsCancellationRequested)
                {
                    var lenBuf = new byte[2];
                    if (!await TryReadAsync(stream, lenBuf, ct)) return;
                    var len = (lenBuf[0] << 8) | lenBuf[1];
                    if (len < 12 || len > MaxTcpQuery) return;
                    var query = new byte[len];
                    if (!await TryReadAsync(stream, query, ct)) return;
                    var qname = GetQueryName(query);
                    if (qname != null && IsLocalBlock(qname))
                    {
                        var nx = BuildNxDomain(query);
                        Interlocked.Increment(ref _blocked);
                        if (nx == null) return;
                        try { await WriteFramedAsync(stream, nx, ct); }
                        catch { return; }
                        continue;
                    }
                    byte[]? answer;
                    try { answer = await ForwardOverTcpAsync(query, ct); }
                    catch (OperationCanceledException) { return; }
                    catch { answer = null; }
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        if (answer != null)
                        {
                            Interlocked.Increment(ref _forwarded);
                            await WriteFramedAsync(stream, answer, ct);
                        }
                        else
                        {
                            Interlocked.Increment(ref _failed);
                            var fail = BuildServFail(query);
                            if (fail == null) return;
                            await WriteFramedAsync(stream, fail, ct);
                        }
                    }
                    catch { return; }
                }
            }
        }

        static async Task WriteFramedAsync(NetworkStream stream, byte[] payload, CancellationToken ct)
        {
            var len = new byte[2] { (byte)(payload.Length >> 8), (byte)(payload.Length & 0xFF) };
            await stream.WriteAsync(len, ct);
            await stream.WriteAsync(payload, ct);
        }

        static async Task<bool> TryReadAsync(NetworkStream stream, byte[] buffer, CancellationToken ct)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read;
                try { read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), ct); }
                catch (OperationCanceledException) { throw; }
                catch { return false; }
                if (read <= 0) return false;
                offset += read;
            }
            return true;
        }

        async Task<byte[]?> ForwardOverTcpAsync(byte[] query, CancellationToken ct)
        {
            using var timeout = new CancellationTokenSource(ExchangeTimeoutMs);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
            var lct = linked.Token;
            using var tcp = new TcpClient();
            try
            {
                // No separate connect-timeout CTS: loopback connects fail
                // fast (refused/reset) by construction, so a second
                // timer-backed CTS per query would be pure overhead.
                await tcp.ConnectAsync(_upstreamHost, _upstreamPort, lct);
            }
            catch (OperationCanceledException)
            {
                if (ct.IsCancellationRequested) throw;
                return null;
            }
            catch { return null; }
            try
            {
                var stream = tcp.GetStream();
                await WriteFramedAsync(stream, query, lct);
                var lenBuf = new byte[2];
                if (!await TryReadAsync(stream, lenBuf, lct)) return null;
                var len = (lenBuf[0] << 8) | lenBuf[1];
                if (len < 12 || len > MaxTcpQuery) return null;
                var answer = new byte[len];
                if (!await TryReadAsync(stream, answer, lct)) return null;
                return answer;
            }
            catch (OperationCanceledException)
            {
                if (ct.IsCancellationRequested) throw;
                return null;
            }
            catch { return null; }
        }

        // Minimal SERVFAIL: TXID + question preserved, QR/RA set, RCODE 2, counts zeroed.
        public static byte[]? BuildServFail(byte[] query)
        {
            try
            {
                if (query == null || query.Length < 12) return null;
                var out_ = new byte[query.Length];
                Buffer.BlockCopy(query, 0, out_, 0, query.Length);
                out_[2] = (byte)(0x80 | (query[2] & 0x79));
                out_[3] = 0x82;
                out_[6] = out_[7] = out_[8] = out_[9] = out_[10] = out_[11] = 0;
                return out_;
            }
            catch { return null; }
        }

        // Answered locally with NXDOMAIN so internal names never reach an
        // exit. Narrow by design: special-use suffixes, single labels,
        // non-public reverse zones. Arbitrary LAN FQDNs still forward
        // (inherent to Tor DNS); .onion always forwards.
        static readonly string[] BlockedSuffixes =
        {
            ".local", ".localhost", ".invalid", ".example", ".test",
            ".home.arpa", ".internal",
        };

        public static string? GetQueryName(byte[] query)
        {
            try
            {
                // Stack-only parse (per-query hot path): no StringBuilder.
                if (query == null || query.Length < 12) return null;
                Span<char> buf = stackalloc char[254];
                int n = 0, p = 12;
                bool first = true;
                while (true)
                {
                    if (p >= query.Length) return null;
                    var len = query[p++];
                    if (len == 0) break;
                    if ((len & 0xC0) != 0) return null; // compression has no business in a question
                    if (len > 63 || p + len > query.Length) return null;
                    if (!first)
                    {
                        if (n >= buf.Length) return null;
                        buf[n++] = '.';
                    }
                    first = false;
                    for (var i = 0; i < len; i++)
                    {
                        if (n >= buf.Length) return null;
                        buf[n++] = char.ToLowerInvariant((char)query[p + i]);
                    }
                    p += len;
                    if (n > 253) return null;
                }
                return new string(buf.Slice(0, n));
            }
            catch { return null; }
        }

        public static bool IsLocalBlock(string name)
        {
            try
            {
                if (string.IsNullOrEmpty(name)) return false; // root: forward
                name = name.TrimEnd('.').ToLowerInvariant();
                if (name.Length == 0) return false;
                foreach (var s in BlockedSuffixes)
                    if (name.EndsWith(s, StringComparison.Ordinal)) return true;
                if (name.IndexOf('.') < 0) return true; // single-label: LAN/NetBIOS/WPAD leftovers
                if (name.EndsWith(".in-addr.arpa", StringComparison.Ordinal))
                    return IsNonPublicV4Reverse(name);
                if (name.EndsWith(".ip6.arpa", StringComparison.Ordinal))
                    return IsNonPublicV6Reverse(name);
                return false;
            }
            catch { return false; }
        }

        static bool IsNonPublicV4Reverse(string name)
        {
            // d.c.b.a.in-addr.arpa -> a.b.c.d; block loopback/private/link-local, forward the rest.
            try
            {
                var labels = name.Substring(0, name.Length - ".in-addr.arpa".Length).Split('.');
                if (labels.Length < 4) return false; // malformed: forward, don't guess
                var octets = new int[4];
                for (var i = 0; i < 4; i++)
                {
                    if (!int.TryParse(labels[i], out octets[i]) || octets[i] < 0 || octets[i] > 255)
                        return false;
                }
                var a = octets[3]; var b = octets[2];
                if (a == 127 || a == 0) return true; // loopback / "this network"
                if (a == 10) return true;
                if (a == 172 && b >= 16 && b <= 31) return true;
                if (a == 192 && b == 168) return true;
                if (a == 169 && b == 254) return true; // link-local
                return false;
            }
            catch { return false; }
        }

        static bool IsNonPublicV6Reverse(string name)
        {
            // 32 reversed nibble labels; block ::, ::1, fe80::/10, fc00::/7, ff00::/8.
            try
            {
                var labels = name.Substring(0, name.Length - ".ip6.arpa".Length).Split('.');
                if (labels.Length != 32) return false;
                foreach (var l in labels)
                {
                    if (l.Length != 1) return false;
                    var c = l[0];
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
                }
                // Labels are low-nibble-first: byte[i] = labels[31-2i] + labels[30-2i].
                var b0 = Convert.ToInt32(labels[31] + labels[30], 16);
                var b1 = Convert.ToInt32(labels[29] + labels[28], 16);
                if (b0 == 0xFF) return true; // multicast
                if ((b0 & 0xFE) == 0xFC) return true; // unique-local
                if (b0 == 0xFE && (b1 & 0xC0) == 0x80) return true; // link-local
                var allZero = true;
                for (var i = 0; i < 16; i++)
                {
                    var v = Convert.ToInt32(labels[31 - 2 * i] + labels[30 - 2 * i], 16);
                    if (v != 0) { allZero = false; break; }
                }
                if (allZero) return true;
                var isOne = labels[0] == "1";
                if (isOne)
                {
                    for (var i = 1; i < 32 && isOne; i++)
                        if (labels[i] != "0") isOne = false;
                    if (isOne) return true;
                }
                return false;
            }
            catch { return false; }
        }

        public static byte[]? BuildNxDomain(byte[] query)
        {
            try
            {
                if (query == null || query.Length < 12) return null;
                var out_ = new byte[query.Length];
                Buffer.BlockCopy(query, 0, out_, 0, query.Length);
                out_[2] = (byte)(0x80 | (query[2] & 0x79)); // QR, keep opcode/RD
                out_[3] = 0x83; // RA, RCODE 3 NXDOMAIN
                out_[6] = out_[7] = out_[8] = out_[9] = out_[10] = out_[11] = 0;
                return out_;
            }
            catch { return null; }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
            try { _cts?.Cancel(); } catch { }
            try { _udp?.Dispose(); } catch { }
            _udp = null;
            try { _tcp?.Stop(); } catch { }
            _tcp = null;
            try { _cts?.Dispose(); } catch { }
            _cts = null;
        }
    }
}
