using System;
using System.Buffers;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{

    static class SocksUpstream
    {
        // Post-idle/wake/rotation tor needs 5-20s to rebuild circuits, but
        // apps were failed after ~6s. 5 attempts over ~14s lets an app ride
        // out a rebuild (slow load) instead of eating a 502 (broken load).
        // Delays are injectable for tests; production uses the default.
        static readonly int[] DefaultRetryDelaysMs = { 500, 1500, 4000, 8000 };

        public static async Task<TcpClient?> ConnectWithRetryAsync(
            string socksHost, int socksPort,
            string targetHost, int targetPort,
            Func<NetworkStream, Task<bool>> handshake,
            CancellationToken ct,
            int[]? retryDelaysMs = null)
        {
            var delays = retryDelaysMs ?? DefaultRetryDelaysMs;
            var attempts = delays.Length + 1;
            static void Drop(TcpClient? c) { try { c?.Dispose(); } catch { } }

            var tcp = new TcpClient();
            try
            {
                await tcp.ConnectAsync(socksHost, socksPort, ct);
            }
                catch (OperationCanceledException) { Drop(tcp); throw; }
                catch { Drop(tcp); return null; }

            // Deliberate backoff, not polling: right after a rotation (or a
            // wake-from-sleep, or a long idle) there is no event for "fresh
            // circuits ready" (Tor builds them lazily), so we back off while
            // the data path rebuilds. Cancellation-aware.
            for (var attempt = 1; attempt <= attempts; attempt++)
            {
                if (attempt > 1)
                {
                    Drop(tcp);
                    tcp = new TcpClient();
                    try
                    {
                        await tcp.ConnectAsync(socksHost, socksPort, ct);
                    }
                    catch (OperationCanceledException) { Drop(tcp); throw; }
                    catch { Drop(tcp); return null; }
                }
                bool ok;
                try
                {
                    ok = await handshake(tcp.GetStream());
                }
                catch (OperationCanceledException) { Drop(tcp); throw; }
                catch { ok = false; }
                if (ok) return tcp;
                if (attempt <= delays.Length)
                    await Task.Delay(delays[attempt - 1], ct);
            }
            Drop(tcp);
            return null;
        }
    }

    static class StreamRelay
    {
        // Bidirectional relay: graceful EOF half-closes only the finished
        // direction (no timeout); a real error tears down immediately.
        // Pump buffers come from the shared pool: CopyToAsync would allocate
        // ~80 KB per direction per connection (160 KB churn each relay).
        const int PumpBufferSize = 81920;
        public static async Task PumpBoth(NetworkStream a, Socket aSocket, NetworkStream b, Socket bSocket, CancellationToken ct)
        {
            async Task<bool> Copy(NetworkStream from, NetworkStream to)
            {
                var buf = System.Buffers.ArrayPool<byte>.Shared.Rent(PumpBufferSize);
                try
                {
                    while (true)
                    {
                        int n;
                        try { n = await from.ReadAsync(buf.AsMemory(0, PumpBufferSize), ct); }
                        catch { return false; }
                        if (n <= 0) return true;
                        try { await to.WriteAsync(buf.AsMemory(0, n), ct); }
                        catch { return false; }
                    }
                }
                finally { System.Buffers.ArrayPool<byte>.Shared.Return(buf); }
            }

            var t1 = Copy(a, b);
            var t2 = Copy(b, a);

            var completed = await Task.WhenAny(t1, t2);
            bool graceful;
            try { graceful = completed.Result; } catch { graceful = false; }

            if (!graceful || ct.IsCancellationRequested)
                return;

            var stillRunning = ReferenceEquals(completed, t1) ? t2 : t1;
            var finishedInto = ReferenceEquals(completed, t1) ? bSocket : aSocket;
            try { finishedInto.Shutdown(SocketShutdown.Send); } catch { }

            try { await stillRunning; } catch { }
        }
    }

    public class SocksRelay : IDisposable
    {
        // Loopback has no auth: cap handlers (fail-fast past it), timeout handshakes.
        // Same headroom rationale as the HTTP bridge: long-lived streams pin
        // slots, and a saturated gate drops new app connections outright.
        const int MaxConcurrent = 512;
        static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(20);
        readonly SemaphoreSlim _gate = new(MaxConcurrent, MaxConcurrent);

        readonly string _upstreamHost;
        readonly int _upstreamPort;
        TcpListener? _listener;
        CancellationTokenSource? _cts;
        readonly object _lifeLock = new();

        public int ListenPort { get; }

        // In-app WebRTC policy (no system changes, live-toggled). The
        // STUN/TURN host/port gate applies here; with TLS inspection ON,
        // port-443 streams additionally get full HTTPS filtering (BlockJS /
        // cookies / CSP, HTTP/2 natively) through the shared MitmPipeline —
        // same policy as the HTTP-proxy channel, no drift.
        public bool BlockWebRtc { get; set; }

        public bool BlockJs { get; set; }

        public bool BlockCookies { get; set; }

        public string SpoofHost { get; set; } = "";

        // HTTPS inspection master switch for SOCKS TLS on port 443. When
        // true (and MitmCa usable), a sniffed TLS ClientHello is terminated
        // with a per-host leaf from the local CA, filtered decrypted, and
        // re-encrypted toward the origin through Tor (origins validated
        // fail-closed, OCSP via Tor). Non-TLS bytes keep the blind path.
        public bool MitmEnabled { get; set; }

        public MitmCaManager? MitmCa { get; set; }

        // Manual user blocklist (live provider; null = no list). Enforced on
        // the SOCKS-requested host AND the TLS SNI (domain-fronting cover).
        public Func<string[]>? BlockedDomainsProvider { get; set; }

        bool IsBlocked(string? host)
        {
            try
            {
                var p = BlockedDomainsProvider;
                if (p == null) return false;
                string[] list;
                try { list = p(); } catch { return false; }
                return ContentFilter.IsBlockedDomain(host, list);
            }
            catch { return false; }
        }

        MitmSessionOptions SocksSessionOptions(string host, int port, string tlsTarget) => new()
        {
            BlockJs = BlockJs,
            BlockWebRtc = BlockWebRtc,
            BlockCookies = BlockCookies,
            SpoofHost = SpoofHost,
            ConnectHost = host,
            ConnectPort = port,
            TlsTarget = tlsTarget,
            BlockedDomains = BlockedDomainsProvider,
            OnRelayed = (h, p, mode, sni) =>
            {
                try { Relayed?.Invoke(this, new RelayEventArgs { Host = h, Port = p, Mode = mode, Sni = sni }); }
                catch { }
            },
            SocksDial = (h, p, ct) => SocksUpstream.ConnectWithRetryAsync(
                _upstreamHost, _upstreamPort, h, p, s => SocksConnectAsync(s, h, p, ct), ct),
            AuthenticateUpstream = (tls, target, ct) => MitmPipeline.AuthenticateUpstreamAsync(
                tls, target,
                (h, p, c) => SocksUpstream.ConnectWithRetryAsync(
                    _upstreamHost, _upstreamPort, h, p, s => SocksConnectAsync(s, h, p, c), c),
                null, ct),
        };

        public event EventHandler<RelayEventArgs>? Relayed;

        public SocksRelay(string upstreamHost, int upstreamPort, int listenPort)
        {
            _upstreamHost = upstreamHost;
            _upstreamPort = upstreamPort;
            ListenPort = listenPort;
        }

        public void Start()
        {
            // Idempotent: bridge-tier escalation calls Start once per tier;
            // a second Start must reuse the bound listener, not throw 10048.
            // Locked vs Dispose (same shape as HttpToSocksBridge).
            TcpListener listener;
            CancellationToken token;
            lock (_lifeLock)
            {
                if (_cts != null && !_cts.IsCancellationRequested) return;
                try { _cts?.Dispose(); } catch { }
                _cts = new CancellationTokenSource();
                listener = _listener = new TcpListener(IPAddress.Loopback, ListenPort);
                token = _cts.Token;
            }
            try { listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true); } catch { }
            try { listener.Start(); }
            catch { lock (_lifeLock) { if (ReferenceEquals(_listener, listener)) _listener = null; } throw; }
            _ = AcceptLoop(listener, token);
        }

        async Task AcceptLoop(TcpListener listener, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(ct); }
                catch { break; }
                bool admitted;
                try { admitted = await _gate.WaitAsync(0, ct); }
                catch { try { client.Dispose(); } catch { } break; }
                if (!admitted) { try { client.Dispose(); } catch { } continue; }
                _ = HandleAndReleaseAsync(client, ct);
            }
        }

        async Task HandleAndReleaseAsync(TcpClient client, CancellationToken ct)
        {
            try { await HandleClientAsync(client, ct); }
            finally { try { _gate.Release(); } catch { } }
        }

        async Task HandleClientAsync(TcpClient client, CancellationToken ct)
        {
            using (client)
            {
                NetworkStream stream;
                try { stream = client.GetStream(); }
                catch { return; }
                // Timeout covers the handshake only; the relay pump below stays untimed.
                using var hsTimeout = new CancellationTokenSource(HandshakeTimeout);
                using var hsCts = CancellationTokenSource.CreateLinkedTokenSource(ct, hsTimeout.Token);
                var hs = hsCts.Token;
                try
                {

                    var head = new byte[2];
                    if (!await TryReadExactAsync(stream, head, hs)) return;
                    if (head[0] != 0x05 || head[1] == 0) { client.Close(); return; }
                    var methods = new byte[head[1]];
                    if (!await TryReadExactAsync(stream, methods, hs)) return;
                    var ok = false;
                    foreach (var m in methods) if (m == 0x00) { ok = true; break; }
                    if (!ok)
                    {
                        await stream.WriteAsync(new byte[] { 0x05, 0xFF }, hs);
                        return;
                    }
                    await stream.WriteAsync(new byte[] { 0x05, 0x00 }, hs);

                    var req = new byte[4];
                    if (!await TryReadExactAsync(stream, req, hs)) return;
                    if (req[0] != 0x05 || req[1] != 0x01)
                    {
                        await stream.WriteAsync(new byte[] { 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, hs);
                        return;
                    }
                    string host;
                    if (req[3] == 0x01)
                    {
                        var ip = new byte[4];
                        if (!await TryReadExactAsync(stream, ip, hs)) return;
                        host = $"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}";
                    }
                    else if (req[3] == 0x03)
                    {
                        var lb = new byte[1];
                        if (!await TryReadExactAsync(stream, lb, hs)) return;
                        var hb = new byte[lb[0]];
                        if (hb.Length == 0) { client.Close(); return; }
                        if (!await TryReadExactAsync(stream, hb, hs)) return;
                        host = Encoding.ASCII.GetString(hb);
                    }
                    else if (req[3] == 0x04)
                    {
                        var ip = new byte[16];
                        if (!await TryReadExactAsync(stream, ip, hs)) return;
                        host = new IPAddress(ip).ToString();
                    }
                    else
                    {
                        await stream.WriteAsync(new byte[] { 0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, hs);
                        return;
                    }
                    var pb = new byte[2];
                    if (!await TryReadExactAsync(stream, pb, hs)) return;
                    var port = (pb[0] << 8) | pb[1];

                    // User blocklist first (explicit user intent): refuse
                    // before any upstream work — no circuit spent, no leak.
                    if (IsBlocked(host))
                    {
                        try { await stream.WriteAsync(new byte[] { 0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, hs); }
                        catch { }
                        try { Relayed?.Invoke(this, new RelayEventArgs { Host = host, Port = port, Mode = "BLOCKED-DOMAIN" }); }
                        catch { }
                        return;
                    }

                    if (BlockWebRtc && ContentFilter.IsWebRtcTarget(host, port))
                    {
                        // 0x02 = connection not allowed by ruleset (policy
                        // block, distinct from 0x01 upstream failure).
                        try { await stream.WriteAsync(new byte[] { 0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, hs); }
                        catch { }
                        try { Relayed?.Invoke(this, new RelayEventArgs { Host = host, Port = port, Mode = "BLOCKED-RTC" }); }
                        catch { }
                        return;
                    }

                    var upstream = await SocksUpstream.ConnectWithRetryAsync(
                        _upstreamHost, _upstreamPort, host, port,
                        s => SocksConnectAsync(s, host, port, hs), hs);
                    if (upstream == null)
                    {
                        try { await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, hs); }
                        catch { }
                        return;
                    }
                    using (upstream)
                    {
                        await stream.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, hs);
                        // Port-443 TLS inspection: same decrypted policy as
                        // the HTTP-proxy channel (BlockJS / cookies / CSP,
                        // blocklist, HTTP/2 natively). Everything else —
                        // and any TLS that can't be issued — pumps blind.
                        if (MitmEnabled && MitmCa != null && port == 443)
                        {
                            await HandleSocksTlsAsync(stream, client, upstream, host, port, hs, ct);
                            return;
                        }
                        try { Relayed?.Invoke(this, new RelayEventArgs { Host = host, Port = port, Mode = "SOCKS" }); }
                        catch { }
                        await StreamRelay.PumpBoth(stream, client.Client, upstream.GetStream(), upstream.Client, ct);
                    }
                }
                catch
                {

                }
            }
        }

        // Post-handshake TLS inspection for SOCKS port-443 streams. Peeks the
        // client's first bytes: a TLS ClientHello is terminated with a
        // per-host leaf and run through the shared inspection pipeline
        // (fail-closed origin validation, decrypted filtering, native H2);
        // anything else — or an unissuable leaf — falls back to the blind
        // pump with the peeked bytes forwarded verbatim. Inspection is
        // skipped, never weakened, on any failure.
        async Task HandleSocksTlsAsync(NetworkStream clientStream, TcpClient client,
            TcpClient upstream, string host, int port,
            CancellationToken hs, CancellationToken ct)
        {
            var prefix = await ReadTlsPrefixAsync(clientStream, ct);
            if (prefix == null) return; // engine stopping: exit silently
            var socksStream = upstream.GetStream();
            if (prefix.Length > 0 && prefix[0] == 0x16 && MitmCa != null)
            {
                string sni = "";
                try { sni = HttpToSocksBridge.TryParseSni(prefix, prefix.Length); } catch { }
                // SNI cover: a SOCKS host that passes but a blocked SNI must
                // still fail closed (domain-fronting shape).
                if (IsBlocked(host)
                    || (!string.IsNullOrWhiteSpace(sni) && IsBlocked(ContentFilter.NormalizeHost(sni))))
                {
                    try { Relayed?.Invoke(this, new RelayEventArgs { Host = host, Port = port, Mode = "BLOCKED-DOMAIN", Sni = sni ?? "" }); }
                    catch { }
                    return;
                }
                X509Certificate2? leaf = null;
                try { leaf = MitmCa.GetLeafCertificate(host); } catch { leaf = null; }
                if (leaf != null)
                {
                    var tlsTarget = !string.IsNullOrWhiteSpace(sni) ? sni.Trim() : host;
                    bool handled = true;
                    try
                    {
                        handled = await MitmPipeline.RunInspectedTunnelAsync(clientStream, client.Client,
                            upstream, MitmCa, host, port, prefix, sni ?? "",
                            SocksSessionOptions(host, port, tlsTarget), ct);
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { }
                    if (handled) return;
                    // else fall through to the blind path with buffered bytes
                }
                // else fall through to the blind path with buffered bytes
            }
            if (prefix.Length > 0)
            {
                try { await socksStream.WriteAsync(prefix, ct); } catch { return; }
            }
            try { Relayed?.Invoke(this, new RelayEventArgs { Host = host, Port = port, Mode = "SOCKS" }); }
            catch { }
            await StreamRelay.PumpBoth(clientStream, client.Client, socksStream, upstream.Client, ct);
        }

        // Reads the start of the client's post-handshake bytes for
        // inspection routing. Null ONLY on engine shutdown (caller exits
        // silently); empty array on timeout/EOF (caller takes blind path).
        static async Task<byte[]?> ReadTlsPrefixAsync(NetworkStream client, CancellationToken ct)
        {
            try
            {
                using var ms = new MemoryStream();
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
                var tmp = ArrayPool<byte>.Shared.Rent(8192);
                try
                {
                    while (ms.Length < 7)
                    {
                        int n;
                        try { n = await client.ReadAsync(tmp.AsMemory(0, 8192), linked.Token); }
                        catch (OperationCanceledException)
                        {
                            if (ct.IsCancellationRequested) return null;
                            break;
                        }
                        catch { break; }
                        if (n <= 0) break;
                        ms.Write(tmp, 0, Math.Min(n, 16384 - (int)ms.Length));
                        if (ms.Length >= 16384) break;
                    }
                }
                finally { ArrayPool<byte>.Shared.Return(tmp); }
                return ms.ToArray();
            }
            catch (OperationCanceledException)
            {
                if (ct.IsCancellationRequested) throw;
                return Array.Empty<byte>();
            }
            catch { return Array.Empty<byte>(); }
        }

        public static async Task<bool> SocksConnectAsync(NetworkStream s, string host, int port, CancellationToken ct)
        {
            await s.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, ct);
            var resp = new byte[2];
            if (!await TryReadExactAsync(s, resp, ct)) return false;
            if (resp[0] != 0x05 || resp[1] != 0x00) return false;

            var req = HttpToSocksBridge.BuildSocksConnectRequest(host, port);
            if (req == null) return false;

            await s.WriteAsync(req, ct);
            var head = new byte[4];
            if (!await TryReadExactAsync(s, head, ct)) return false;
            if (head[1] != 0x00) return false;

            int addrLen = head[3] switch
            {
                0x01 => 4,
                0x04 => 16,
                0x03 => (await TryReadOneByteAsync(s, ct) is (true, var b) ? b : -1),
                _ => -1
            };
            if (addrLen < 0) return false;
            var skip = new byte[addrLen + 2];
            if (!await TryReadExactAsync(s, skip, ct)) return false;
            return true;
        }

        static async Task<(bool ok, int value)> TryReadOneByteAsync(NetworkStream s, CancellationToken ct)
        {
            var b = new byte[1];
            if (!await TryReadExactAsync(s, b, ct)) return (false, 0);
            return (true, b[0]);
        }

        // False on graceful EOF (routine for probes/half-closes), never throws it as IOException noise.
        static async Task<bool> TryReadExactAsync(NetworkStream s, byte[] buffer, CancellationToken ct)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read;
                try { read = await s.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), ct); }
                catch (OperationCanceledException) { throw; }
                catch { return false; }
                if (read <= 0) return false;
                offset += read;
            }
            return true;
        }

        public void Dispose()
        {
            lock (_lifeLock)
            {
                try { _cts?.Cancel(); } catch { }
                try { _listener?.Stop(); } catch { }
                // Full reset so the next Start rebinds cleanly (no stale CTS).
                try { _cts?.Dispose(); } catch { }
                _cts = null;
                _listener = null;
            }
        }
    }
}