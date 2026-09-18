using System;
using System.Buffers;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{

    public class RelayEventArgs : EventArgs
    {
        public string Host { get; init; } = "";
        public int Port { get; init; }
        public string Mode { get; init; } = "";
        public string SpoofedHost { get; init; } = "";
        public string Sni { get; init; } = "";
    }

    public class HttpToSocksBridge : IDisposable
    {
        // Loopback has no auth: capped handlers, handshake timeout, untimed pump.
        // Cap is headroom, not a target: long-lived streams (SSE, WebSockets,
        // pooled keep-alives) hold slots for their whole life, so a busy
        // browser farm can pin hundreds; refusing past the cap drops new
        // loads outright. Per-pump cost is two pooled 80 KB buffers.
        const int MaxConcurrent = 512;
        static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(20);
        readonly SemaphoreSlim _gate = new(MaxConcurrent, MaxConcurrent);

        readonly string _socksHost;
        readonly int _socksPort;
        TcpListener? _listener;
        CancellationTokenSource? _cts;
        readonly object _lifeLock = new();

        public string SpoofHost { get; set; } = "";

        // In-app content policy (live-toggled, read per connection so Config
        // applies without a restart).
        public bool BlockJs { get; set; }

        public bool BlockWebRtc { get; set; }

        public bool BlockCookies { get; set; }

        // HTTPS inspection master switch. When true (and MitmCa usable),
        // CONNECT-tunneled TLS is terminated with a per-host leaf from the
        // local CA, filtered as decrypted HTTP/1.1, and re-encrypted toward
        // the origin through Tor. Origins are validated fail-closed.
        public bool MitmEnabled { get; set; }

        public MitmCaManager? MitmCa { get; set; }

        // Manual user blocklist (live provider; null = no list). Enforced on
        // CONNECT authorities, plain-HTTP hosts, and inside inspected
        // tunnels (via MitmSessionOptions). Set once by the engine; the
        // delegate reads a live snapshot so Config edits apply instantly.
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

        public event EventHandler<RelayEventArgs>? Relayed;

        void OnRelayed(string host, int port, string mode, string spoofedHost = "", string sni = "")
        {
            try { Relayed?.Invoke(this, new RelayEventArgs { Host = host, Port = port, Mode = mode, SpoofedHost = spoofedHost, Sni = sni }); }
            catch { }
        }

        public static string ApplyHostSpoof(ref string[] lines, string spoofHost)
        {
            if (string.IsNullOrWhiteSpace(spoofHost)) return "";
            var spoof = spoofHost.Trim();
            var end = Array.IndexOf(lines, "");
            if (end < 0) end = lines.Length;
            for (var i = 1; i < end; i++)
            {
                var line = lines[i];
                var colon = line.IndexOf(':');
                if (colon > 0 && line.Substring(0, colon).Trim().Equals("host", StringComparison.OrdinalIgnoreCase))
                {
                    lines[i] = "Host: " + spoof;
                    return spoof;
                }
            }

            var grown = new string[lines.Length + 1];
            grown[0] = lines[0];
            grown[1] = "Host: " + spoof;
            Array.Copy(lines, 1, grown, 2, lines.Length - 1);
            lines = grown;
            return spoof;
        }

        // Single-transaction enforcement for the filtered plain-HTTP path:
        // rewrite (or add) "Connection: close" so neither the origin nor the
        // client attempts keep-alive reuse past the one filtered exchange.
        static void ForceConnectionClose(ref string[] lines)
        {
            try
            {
                var end = Array.IndexOf(lines, "");
                if (end < 0) end = lines.Length;
                for (var i = 1; i < end; i++)
                {
                    var colon = lines[i].IndexOf(':');
                    if (colon > 0 && lines[i].Substring(0, colon).Trim().Equals("connection", StringComparison.OrdinalIgnoreCase))
                    {
                        lines[i] = "Connection: close";
                        return;
                    }
                }
                var grown = new string[lines.Length + 1];
                var insertAt = end < 0 ? lines.Length : end;
                Array.Copy(lines, 0, grown, 0, insertAt);
                grown[insertAt] = "Connection: close";
                Array.Copy(lines, insertAt, grown, insertAt + 1, lines.Length - insertAt);
                lines = grown;
            }
            catch { }
        }

        // Pipelined second-request detector for the filtered plain-HTTP path:
        // extraBody should be a POST body, not another "GET / ... HTTP/1.1".
        static bool LooksLikePipelinedRequest(byte[] extra)
        {
            try
            {
                if (extra == null || extra.Length < 16) return false;
                var n = Math.Min(extra.Length, 512);
                var s = Encoding.Latin1.GetString(extra, 0, n);
                var lf = s.IndexOf('\n');
                var first = (lf >= 0 ? s.Substring(0, lf) : s).Trim();
                if (first.Length < 10 || first.Length > 512) return false;
                var methods = new[] { "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT " };
                foreach (var m in methods)
                {
                    if (first.StartsWith(m, StringComparison.OrdinalIgnoreCase) &&
                        first.IndexOf("HTTP/", StringComparison.OrdinalIgnoreCase) >= 0)
                        return true;
                }
                return false;
            }
            catch { return false; }
        }

        public int ListenPort { get; }

        public HttpToSocksBridge(string socksHost, int socksPort, int listenPort = 9080)
        {
            _socksHost = socksHost;
            _socksPort = socksPort;
            ListenPort = listenPort;
        }

        public void Start()
        {
            // Idempotent (see SocksRelay): tier escalation must not 10048.
            // Locked vs Dispose: an ungated exit teardown racing a gated
            // start must not leak a bound listener or resurrect one post-exit.
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

        // Saturation signal: refusals used to be silent, so a full gate
        // looked exactly like "the internet is down for some apps".
        // Throttled to one log line per 5 minutes; the running total stays
        // readable via GateDropCount.
        public event EventHandler<string>? Warned;

        long _gateDrops;
        long _lastGateWarnTicks;
        public long GateDropCount { get { try { return Interlocked.Read(ref _gateDrops); } catch { return 0; } } }

        void NoteGateDrop()
        {
            try
            {
                var n = Interlocked.Increment(ref _gateDrops);
                var now = DateTime.UtcNow.Ticks;
                var last = Interlocked.Read(ref _lastGateWarnTicks);
                if (now - last > TimeSpan.FromMinutes(5).Ticks &&
                    Interlocked.CompareExchange(ref _lastGateWarnTicks, now, last) == last)
                {
                    try { Warned?.Invoke(this,
                        $"Relay on port {ListenPort} is saturated ({n} connection(s) refused at the concurrency cap). " +
                        "Idle streams are reaped automatically; if this persists, an app is holding hundreds of connections open."); }
                    catch { }
                }
            }
            catch { }
        }

        async Task AcceptLoop(TcpListener listener, CancellationToken ct)
        {
            // A transient accept blip must not kill the listener forever
            // (that wedged ALL new app connections until restart); a
            // permanently broken listener must not hot-spin either.
            var acceptFails = 0;
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(ct); }
                catch (OperationCanceledException) { break; }
                catch
                {
                    if (++acceptFails > 20)
                    {
                        try { Warned?.Invoke(this,
                            $"Relay listener on port {ListenPort} stopped after repeated accept failures — toggle routing to recover."); }
                        catch { }
                        break;
                    }
                    try { await Task.Delay(250, ct); } catch { break; }
                    continue;
                }
                acceptFails = 0;
                bool admitted;
                try { admitted = await _gate.WaitAsync(0, ct); }
                catch { try { client.Dispose(); } catch { } break; }
                if (!admitted) { NoteGateDrop(); try { client.Dispose(); } catch { } continue; }
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
                using var hsTimeout = new CancellationTokenSource(HandshakeTimeout);
                using var hsCts = CancellationTokenSource.CreateLinkedTokenSource(ct, hsTimeout.Token);
                var hs = hsCts.Token;
                try
                {
                    var stream = client.GetStream();
                    var (headerText, extra) = await ReadHeadersAsync(stream, hs);
                    if (headerText.Length == 0) return;

                    var firstLine = headerText.Split("\r\n")[0];
                    var parts = firstLine.Split(' ');
                    if (parts.Length < 2)
                    {
                        // Malformed request line: explicit 400, not a silent
                        // drop (the app gets an instant error, not a hang).
                        var badLine = Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
                        await ReplyAsync(stream, badLine, ct);
                        return;
                    }

                    var method = parts[0];
                    var target = parts[1];

                    if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
                    {
                        await HandleConnect(stream, client.Client, target, extra, hs, ct);
                    }
                    else
                    {
                        await HandlePlainHttp(stream, client.Client, method, target, headerText, extra, hs, ct);
                    }
                }
                catch
                {

                }
            }
        }

        // Header framing lives in Http1Plumbing (single implementation shared
        // with the translators); these are thin local aliases.
        Task<(string text, byte[] extra)> ReadHeadersAsync(Stream stream, CancellationToken ct) =>
            Http1Plumbing.ReadHeadersAsync(stream, ct);

        static Task<(string text, byte[] extra)> ReadUpstreamHeadersAsync(Stream stream, CancellationToken ct) =>
            Http1Plumbing.ReadHeadersAsync(stream, ct);

        static bool IsInterim1xx(string[] lines) => Http1Plumbing.IsInterim1xx(lines);

        async Task HandleConnect(NetworkStream clientStream, Socket clientSocket, string target, byte[] preface, CancellationToken hs, CancellationToken ct)
        {
            // Authority-form may hold a bracketed IPv6 literal: split at the
            // last colon, and only when the suffix is a numeric port — and,
            // when unbracketed, only with a single colon (a bare "::1" is a
            // literal host, not host ":" port 1; CONNECT normally brackets).
            var host = target.Trim();
            var port = 443;
            var hostPart = host;
            var colon = host.LastIndexOf(':');
            if (colon >= 0 && host.Length - colon - 1 <= 5 &&
                int.TryParse(host.Substring(colon + 1), out var parsedPort) &&
                parsedPort is > 0 and <= 65535)
            {
                bool splitOk;
                if (host[0] == '[')
                    splitOk = colon > 0 && host[colon - 1] == ']';
                else
                    splitOk = host.IndexOf(':') == colon;
                if (splitOk)
                {
                    hostPart = host.Substring(0, colon);
                    port = parsedPort;
                }
            }
            host = hostPart.Trim().Trim('[', ']').Trim();
            if (host.Length == 0)
            {
                var badHost = Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
                await ReplyAsync(clientStream, badHost, ct);
                return;
            }

            // Deterministic local failure: an unencodable host can never
            // succeed — refuse now (400) instead of burning the 5-attempt /
            // ~14s retry budget and answering late.
            if (BuildSocksConnectRequest(host, port) == null)
            {
                var badTarget = Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
                await ReplyAsync(clientStream, badTarget, ct);
                OnRelayed(host, port, "BAD-TARGET");
                return;
            }

            // User blocklist first (explicit user intent beats everything):
            // refuse before any upstream work — no Tor circuit is spent and
            // nothing leaks.
            if (IsBlocked(host))
            {
                try { await clientStream.WriteAsync(ContentFilter.BuildBlockedResponse("Domain blocked by PTor (Blocked Domains)"), hs); }
                catch { }
                OnRelayed(host, port, "BLOCKED-DOMAIN");
                return;
            }

            // Proxy-layer WebRTC gate (applies with or without inspection):
            // refuse TURN/STUN-over-TCP relay before any upstream work.
            if (BlockWebRtc && ContentFilter.IsWebRtcTarget(host, port))
            {
                try { await clientStream.WriteAsync(ContentFilter.BuildBlockedResponse("WebRTC (STUN/TURN) blocked by PTor"), hs); }
                catch { }
                OnRelayed(host, port, "BLOCKED-RTC");
                return;
            }

            // SNI cover BEFORE spending a circuit: when the client already
            // pipelined its ClientHello with the CONNECT, a blocked SNI must
            // fail closed without dialing Tor at all (no ClientHello bytes
            // reach an exit). When the preface holds no hello yet, the
            // post-dial sniff below still covers fronting — that dial is
            // unavoidable (we need the client's bytes to know the SNI).
            try
            {
                if (preface.Length > 0 && preface[0] == 0x16)
                {
                    var earlySni = TryParseSni(preface, preface.Length);
                    if (!string.IsNullOrWhiteSpace(earlySni) && IsBlocked(ContentFilter.NormalizeHost(earlySni)))
                    {
                        // Pre-200: the client still waits for a status, so
                        // refuse with the blocked page (was a silent close).
                        await ReplyAsync(clientStream, ContentFilter.BuildBlockedResponse("Domain blocked by PTor (Blocked Domains)"), ct);
                        OnRelayed(host, port, "BLOCKED-DOMAIN", "", earlySni);
                        return;
                    }
                }
            }
            catch { }
            using var socksClient = await SocksUpstream.ConnectWithRetryAsync(
                _socksHost, _socksPort, host, port,
                s => Socks5Connect(s, host, port, hs), hs);
            if (socksClient == null)
            {
                var fail = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
                await ReplyAsync(clientStream, fail, ct);
                return;
            }
            var socksStream = socksClient.GetStream();

            var ok = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
            if (!await ReplyAsync(clientStream, ok, ct)) return;

            // Inspection branch: TLS gets terminated + filtered + re-encrypted
            // (see method notes). Non-TLS CONNECT bytes (rare: plain-HTTP over
            // CONNECT, PROXY-protocol chatter) keep the legacy blind path.
            // Leaf-issuance failure fails OPEN to the blind path: connectivity
            // via Tor is preserved and the client still validates the origin
            // directly — inspection is skipped, never weakened.
            if (MitmEnabled && MitmCa != null)
            {
                var prefix = await ReadClientHelloPrefixAsync(clientStream, preface, ct);
                if (prefix != null && prefix.Length > 0 && prefix[0] == 0x16)
                {
                    var sni = TryParseSni(prefix, prefix.Length);
                    X509Certificate2 leaf;
                    try { leaf = MitmCa.GetLeafCertificate(host); }
                    catch { leaf = null!; }
                    if (leaf != null)
                    {
                        await HandleConnectMitmAsync(clientStream, clientSocket,
                            socksClient, host, port, prefix, sni, ct);
                        return;
                    }
                    // else fall through to blind path with the buffered bytes
                    // forwarded verbatim below.
                }
                await HandleConnectBlindAsync(clientStream, clientSocket, socksStream,
                    socksClient.Client, host, port, prefix ?? preface, ct);
                return;
            }

            // Legacy blind path (inspection off): blocked-SNI bytes must never
            // reach the exit. Check the pipelined hello BEFORE forwarding
            // (the pre-dial check above already refused blocked ones — this
            // re-check keeps the invariant local so future edits can't
            // reintroduce a write-before-check).
            if (preface.Length > 0)
            {
                var preSni = "";
                try { preSni = TryParseSni(preface, preface.Length); } catch { }
                if (!string.IsNullOrWhiteSpace(preSni) && IsBlocked(ContentFilter.NormalizeHost(preSni)))
                {
                    // Pre-200 like the check above: refuse with the blocked
                    // page (was a silent close on an already-dialed circuit).
                    await ReplyAsync(clientStream, ContentFilter.BuildBlockedResponse("Domain blocked by PTor (Blocked Domains)"), ct);
                    OnRelayed(host, port, "BLOCKED-DOMAIN", "", preSni);
                    return;
                }
                try { await socksStream.WriteAsync(preface, hs); } catch { return; }
                if (!string.IsNullOrEmpty(preSni))
                {
                    OnRelayed(host, port, "CONNECT", "", preSni);
                    await StreamRelay.PumpBoth(clientStream, clientSocket, socksStream, socksClient.Client, ct);
                    return;
                }
            }
            var (plainSni, probe) = await PeekSniAsync(clientStream, hs);
            if (!string.IsNullOrWhiteSpace(plainSni) && IsBlocked(ContentFilter.NormalizeHost(plainSni)))
            {
                OnRelayed(host, port, "BLOCKED-DOMAIN", "", plainSni);
                return;
            }
            if (probe.Length > 0)
            {
                try { await socksStream.WriteAsync(probe, hs); } catch { return; }
            }
            OnRelayed(host, port, "CONNECT", "", plainSni);

            await StreamRelay.PumpBoth(clientStream, clientSocket, socksStream, socksClient.Client, ct);
        }

        // Blind CONNECT with already-buffered client bytes (inspection off or
        // non-TLS / leaf-failure fallback): forward them verbatim, sniff SNI
        // for the log when the buffer didn't hold a ClientHello, then pump.
        async Task HandleConnectBlindAsync(NetworkStream clientStream, Socket clientSocket,
            NetworkStream socksStream, Socket upstreamSocket,
            string host, int port, byte[] buffered, CancellationToken ct)
        {
            // Blocked-SNI bytes must never reach the exit: check the buffered
            // hello BEFORE forwarding it upstream (fail closed, no write).
            string sni = "";
            try { sni = TryParseSni(buffered, buffered.Length); } catch { }
            if (!string.IsNullOrWhiteSpace(sni) && IsBlocked(ContentFilter.NormalizeHost(sni)))
            {
                OnRelayed(host, port, "BLOCKED-DOMAIN", "", sni ?? "");
                return;
            }
            if (buffered.Length > 0)
            {
                try { await socksStream.WriteAsync(buffered, ct); } catch { return; }
            }
            if (string.IsNullOrEmpty(sni))
            {
                // Peek without forwarding: a blocked SNI in this probe must
                // never reach the exit either.
                byte[] probe = Array.Empty<byte>();
                try { (sni, probe) = await PeekSniAsync(clientStream, ct); }
                catch { }
                if (!string.IsNullOrWhiteSpace(sni) && IsBlocked(ContentFilter.NormalizeHost(sni)))
                {
                    OnRelayed(host, port, "BLOCKED-DOMAIN", "", sni ?? "");
                    return;
                }
                if (probe.Length > 0)
                {
                    try { await socksStream.WriteAsync(probe, ct); } catch { return; }
                }
            }
            // Same SNI cover as the legacy path: a blocked SNI fails closed
            // even when the CONNECT authority itself was allowed. The 200 was
            // already sent, so just close (no further pump) and log.
            if (!string.IsNullOrWhiteSpace(sni) && IsBlocked(ContentFilter.NormalizeHost(sni)))
            {
                OnRelayed(host, port, "BLOCKED-DOMAIN", "", sni ?? "");
                return;
            }
            OnRelayed(host, port, "CONNECT", "", sni ?? "");
            await StreamRelay.PumpBoth(clientStream, clientSocket, socksStream, upstreamSocket, ct);
        }

        // Reads the start of the client's TLS handshake for inspection
        // routing. Returns null ONLY on engine shutdown (caller must exit
        // silently); empty array on timeout/EOF (caller takes blind path).
        static async Task<byte[]?> ReadClientHelloPrefixAsync(NetworkStream client, byte[] preface, CancellationToken ct)
        {
            try
            {
                using var ms = new MemoryStream();
                if (preface.Length > 0) ms.Write(preface, 0, Math.Min(preface.Length, 16384));
                if (ms.Length >= 7) return ms.ToArray();
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
                if (ct.IsCancellationRequested) return null;
                return Array.Empty<byte>();
            }
            catch { return preface; }
        }

        // TCP dial toward the origin through Tor's SOCKS (shared by the
        // CONNECT path and the H2H1 translator's per-request connections).
        internal Task<TcpClient?> DialUpstreamAsync(string host, int port, CancellationToken ct) =>
            SocksUpstream.ConnectWithRetryAsync(_socksHost, _socksPort, host, port,
                s => Socks5Connect(s, host, port, ct), ct);

        // Status text only: ref assignment is atomic; a stale read just shows
        // the previous error line. No Volatile/lock needed (and ref-passing a
        // volatile field only raises CS0420).
        string _lastUpstreamErr = "";

        // Origin TLS + validation, fail-closed. Shared by CONNECT MITM and
        // translators so every decrypted leg enforces the same guarantees;
        // the single implementation lives in MitmPipeline (also reused by the
        // SOCKS relay's TLS inspection) — this stays a thin wrapper so the
        // last upstream error remains observable for status lines.
        internal Task<bool> AuthenticateUpstreamAsync(SslStream tls, string targetHost, CancellationToken ct) =>
            MitmPipeline.AuthenticateUpstreamAsync(tls, targetHost,
                (h, p, c) => DialUpstreamAsync(h, p, c),
                s => { try { Interlocked.Exchange(ref _lastUpstreamErr, s ?? ""); } catch { } }, ct);

        MitmSessionOptions SessionOptions(string host, int port, string tlsTarget) => new()
        {
            BlockJs = BlockJs,
            BlockWebRtc = BlockWebRtc,
            BlockCookies = BlockCookies,
            SpoofHost = SpoofHost,
            ConnectHost = host,
            ConnectPort = port,
            TlsTarget = tlsTarget,
            BlockedDomains = BlockedDomainsProvider,
            OnRelayed = (h, p, mode, sni) => OnRelayed(h, p, mode, "", sni),
            SocksDial = (h, p, ct) => DialUpstreamAsync(h, p, ct),
            AuthenticateUpstream = (tls, target, ct) => AuthenticateUpstreamAsync(tls, target, ct),
        };

        // Full HTTPS inspection for one CONNECT tunnel. The single
        // implementation lives in MitmPipeline (shared with the SOCKS
        // relay's TLS inspection); this only builds the session options.
        // Leaf-issuance failure falls back to the blind pump (connectivity
        // via Tor preserved; the client still validates the origin directly
        // — inspection skipped, never weakened).
        async Task HandleConnectMitmAsync(NetworkStream clientStream, Socket clientSocket,
            TcpClient socksClient, string host, int port,
            byte[] helloPrefix, string sni, CancellationToken ct)
        {
            var tlsTarget = !string.IsNullOrWhiteSpace(sni) ? sni.Trim() : host;
            var handled = await MitmPipeline.RunInspectedTunnelAsync(clientStream, clientSocket,
                socksClient, MitmCa!, host, port, helloPrefix, sni,
                SessionOptions(host, port, tlsTarget), ct);
            if (!handled)
            {
                NetworkStream socksStream;
                try { socksStream = socksClient.GetStream(); }
                catch { return; }
                await HandleConnectBlindAsync(clientStream, clientSocket, socksStream,
                    socksClient.Client, host, port, helloPrefix, ct);
            }
        }

        // (Decrypted-session runners now live in MitmPipeline — shared with
        // the SOCKS relay's TLS inspection. Small framing helpers live in
        // Http1Plumbing; host matching in ContentFilter.)

        static async Task<string> SniffSniAsync(NetworkStream client, NetworkStream socks, CancellationToken ct)
        {
            // Legacy helper kept for compatibility: reads one probe, forwards
            // it, returns the SNI. Prefer PeekSniAsync (no forward) so a
            // blocked SNI never reaches the exit.
            var (sni, probe) = await PeekSniAsync(client, ct);
            if (probe.Length > 0)
            {
                try { await socks.WriteAsync(probe, ct); } catch { return ""; }
            }
            return sni;
        }

        // Reads one client probe WITHOUT forwarding it: the caller
        // block-checks the SNI first and only relays the bytes when allowed.
        static async Task<(string sni, byte[] bytes)> PeekSniAsync(NetworkStream client, CancellationToken ct)
        {
            var probe = ArrayPool<byte>.Shared.Rent(16384);
            try
            {
                int n;
                try
                {
                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
                    n = await client.ReadAsync(probe.AsMemory(0, 16384), linked.Token);
                }
                catch (OperationCanceledException)
                {
                    if (ct.IsCancellationRequested) throw;
                    return ("", Array.Empty<byte>());
                }
                catch { return ("", Array.Empty<byte>()); }
                if (n <= 0) return ("", Array.Empty<byte>());
                var sni = "";
                try { sni = TryParseSni(probe, n); } catch { }
                var out_ = new byte[n];
                Buffer.BlockCopy(probe, 0, out_, 0, n);
                return (sni ?? "", out_);
            }
            finally { ArrayPool<byte>.Shared.Return(probe); }
        }

        public static string TryParseSni(byte[] buf, int len)
        {
            try
            {
                if (buf == null || len < 6 || len > buf.Length) return "";
                if (buf[0] != 0x16) return "";
                int recLen = (buf[3] << 8) | buf[4];
                if (recLen + 5 > len) return "";
                int p = 5;
                if (buf[p] != 0x01) return "";
                p += 6 + 32;
                if (p >= len) return "";
                int sidLen = buf[p++];
                p += sidLen;
                if (p + 2 > len) return "";
                int csLen = (buf[p] << 8) | buf[p + 1];
                p += 2 + csLen;
                if (p + 1 > len) return "";
                int compLen = buf[p++];
                p += compLen;
                if (p + 2 > len) return "";
                int extTotal = (buf[p] << 8) | buf[p + 1];
                p += 2;
                int extEnd = p + extTotal;
                while (p + 4 <= extEnd && p + 4 <= len)
                {
                    int type = (buf[p] << 8) | buf[p + 1];
                    int elen = (buf[p + 2] << 8) | buf[p + 3];
                    p += 4;
                    if (type == 0)
                    {
                        if (p + 2 > len) return "";
                        int listLen = (buf[p] << 8) | buf[p + 1];
                        p += 2;
                        int listEnd = Math.Min(p + listLen, len);
                        while (p + 3 <= listEnd)
                        {
                            int nameType = buf[p];
                            int nameLen = (buf[p + 1] << 8) | buf[p + 2];
                            p += 3;
                            if (p + nameLen > listEnd) return "";
                            if (nameType == 0)
                                return Encoding.ASCII.GetString(buf, p, nameLen);
                            p += nameLen;
                        }
                        return "";
                    }
                    p += elen;
                }
                return "";
            }
            catch { return ""; }
        }

        async Task HandlePlainHttp(NetworkStream clientStream, Socket clientSocket, string method, string target, string headerText, byte[] extraBody, CancellationToken hs, CancellationToken ct)
        {

            Uri uri;
            try { uri = new Uri(target); }
            catch
            {
                // Origin-form / garbage targeting a proxy port: explicit 400,
                // not a silent drop (and never forwarded upstream).
                var bad = Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
                try { await clientStream.WriteAsync(bad, hs); } catch { }
                return;
            }
            // In-app request policy (plain-HTTP only: CONNECT has no path and
            // SOCKS has no URL, so .js paths can only be judged here).
            if (IsBlocked(uri.Host))
            {
                try { await clientStream.WriteAsync(ContentFilter.BuildBlockedResponse("Domain blocked by PTor (Blocked Domains)"), hs); }
                catch { }
                OnRelayed(uri.Host, uri.Port, "BLOCKED-DOMAIN");
                return;
            }
            if (BlockWebRtc && ContentFilter.IsWebRtcTarget(uri.Host, uri.Port))
            {
                try { await clientStream.WriteAsync(ContentFilter.BuildBlockedResponse("WebRTC (STUN/TURN) blocked by PTor"), hs); }
                catch { }
                OnRelayed(uri.Host, uri.Port, "BLOCKED-RTC");
                return;
            }
            if (BlockJs && ContentFilter.IsJsRequestPath(uri.PathAndQuery))
            {
                try { await clientStream.WriteAsync(ContentFilter.BuildBlockedResponse("JavaScript file blocked by PTor (BlockJS)"), hs); }
                catch { }
                OnRelayed(uri.Host, uri.Port, "BLOCKED-JS");
                return;
            }
            using var socksClient = await SocksUpstream.ConnectWithRetryAsync(
                _socksHost, _socksPort, uri.Host, uri.Port,
                s => Socks5Connect(s, uri.Host, uri.Port, hs), hs);
            if (socksClient == null)
            {
                var fail = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
                await ReplyAsync(clientStream, fail, ct);
                return;
            }
            var socksStream = socksClient.GetStream();

            var lines = headerText.Split("\r\n");
            lines[0] = $"{method} {uri.PathAndQuery} HTTP/1.1";
            var spoofed = ApplyHostSpoof(ref lines, SpoofHost);
            ContentFilter.RemoveProxyHopHeaders(ref lines);
            if (BlockCookies) ContentFilter.RemoveRequestCookies(ref lines);
            // Filtered path is single-transaction only (see below): force
            // Connection: close so no second keep-alive request can slip
            // past the filter via the post-response blind pump.
            var filtering = BlockJs || BlockWebRtc || BlockCookies;
            if (filtering) ForceConnectionClose(ref lines);
            var rewritten = string.Join("\r\n", lines);
            var bytes = Encoding.Latin1.GetBytes(rewritten);
            await socksStream.WriteAsync(bytes, hs);
            // Body bytes that arrived with the headers go out verbatim next —
            // the pump only sees what arrives after this point. On the
            // filtered path a pipelined second request hiding in extraBody
            // would bypass the request filter entirely (and could smuggle
            // Proxy-Authorization to the origin): fail closed instead.
            if (extraBody.Length > 0)
            {
                if (filtering && LooksLikePipelinedRequest(extraBody))
                {
                    try { await clientStream.WriteAsync(ContentFilter.BuildBlockedResponse("Pipelined request blocked by PTor (single-transaction filter)"), hs); }
                    catch { }
                    OnRelayed(uri.Host, uri.Port, "BLOCKED-PIPELINE");
                    return;
                }
                try { await socksStream.WriteAsync(extraBody, hs); }
                catch
                {
                    var gone = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
                    await ReplyAsync(clientStream, gone, ct);
                    return;
                }
            }

            // Fast path: no content policy — blind pump as before (zero
            // behavior/perf change when all toggles are off).
            if (!BlockJs && !BlockWebRtc && !BlockCookies)
            {
                OnRelayed(uri.Host, uri.Port, method, spoofed);
                await StreamRelay.PumpBoth(clientStream, clientSocket, socksStream, socksClient.Client, ct);
                return;
            }

            // Filtered path: peek at upstream response headers to enforce
            // MIME blocks + inject CSP on HTML. Body bytes are never
            // rewritten (gzip-safe): only headers change, so Content-Length
            // stays valid. HTTPS never reaches here (CONNECT tunnels bytes).
            // Uses ct (not hs): TTFB over fresh Tor circuits routinely
            // exceeds the 20s handshake budget; the gate cap bounds hangs.
            string respText;
            byte[] respExtra;
            try { (respText, respExtra) = await ReadUpstreamHeadersAsync(socksStream, ct); }
            catch (OperationCanceledException) { return; }
            if (respText.Length == 0)
            {
                // Upstream went away without headers (Tor circuit died
                // mid-flight): explicit 502, not a bare FIN — the app
                // fails fast instead of reporting an empty reply / hang.
                var empty = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
                await ReplyAsync(clientStream, empty, ct);
                return;
            }
            var respLines = respText.Split("\r\n");
            // Forward interim 1xx (100 Continue etc.) verbatim, then read the
            // final headers — otherwise POSTs with Expect: 100-continue break.
            // 101 Switching Protocols (plain-HTTP WebSocket) falls through to
            // the MIME/CSP checks below, which leave it untouched (no
            // Content-Type match) and pump the upgraded stream.
            for (var guard = 0; guard < 5 && IsInterim1xx(respLines); guard++)
            {
                try
                {
                    await clientStream.WriteAsync(Encoding.Latin1.GetBytes(respText), ct);
                    if (respExtra.Length > 0) await clientStream.WriteAsync(respExtra, ct);
                }
                catch { return; }
                try { (respText, respExtra) = await ReadUpstreamHeadersAsync(socksStream, ct); }
                catch (OperationCanceledException) { return; }
                if (respText.Length == 0)
                {
                    var empty1xx = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
                    await ReplyAsync(clientStream, empty1xx, ct);
                    return;
                }
                respLines = respText.Split("\r\n");
            }
            var respType = ContentFilter.GetHeaderValue(respLines, "Content-Type");
            if (BlockWebRtc && ContentFilter.IsSdpContentType(respType))
            {
                try { await clientStream.WriteAsync(ContentFilter.BuildBlockedResponse("WebRTC signaling (SDP) blocked by PTor"), ct); }
                catch { }
                OnRelayed(uri.Host, uri.Port, "BLOCKED-RTC");
                return;
            }
            if (BlockJs && ContentFilter.IsJsContentType(respType))
            {
                try { await clientStream.WriteAsync(ContentFilter.BuildBlockedResponse("JavaScript response blocked by PTor (BlockJS)"), ct); }
                catch { }
                OnRelayed(uri.Host, uri.Port, "BLOCKED-JS");
                return;
            }
            if (BlockJs && ContentFilter.IsHtmlContentType(respType))
                ContentFilter.TryInjectJsBlockCsp(ref respLines);
            if (BlockCookies) ContentFilter.RemoveResponseCookies(ref respLines);
            // Single-transaction guarantee: the post-response PumpBoth only
            // pumps bodies — force close so a pipelined second request cannot
            // reuse this connection unfiltered.
            ForceConnectionClose(ref respLines);
            var outHeader = string.Join("\r\n", respLines);
            try
            {
                await clientStream.WriteAsync(Encoding.Latin1.GetBytes(outHeader), ct);
                if (respExtra.Length > 0) await clientStream.WriteAsync(respExtra, ct);
            }
            catch { return; }

            OnRelayed(uri.Host, uri.Port, method, spoofed);

            await StreamRelay.PumpBoth(clientStream, clientSocket, socksStream, socksClient.Client, ct);
        }

        static async Task<bool> Socks5Connect(NetworkStream s, string host, int port, CancellationToken ct)
        {

            await s.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, ct);
            var resp = new byte[2];
            if (!await TryReadExact(s, resp, ct)) return false;
            if (resp[0] != 0x05 || resp[1] != 0x00) return false;

            var req = BuildSocksConnectRequest(host, port);
            if (req == null) return false;

            await s.WriteAsync(req, ct);
            var head = new byte[4];
            if (!await TryReadExact(s, head, ct)) return false;
            if (head[1] != 0x00) return false;

            int addrLen = head[3] switch
            {
                0x01 => 4,
                0x04 => 16,
                0x03 => (await TryReadOneByte(s, ct) is (true, var b) ? b : -1),
                _ => -1
            };
            if (addrLen < 0) return false;
            var skip = new byte[addrLen + 2];
            if (!await TryReadExact(s, skip, ct)) return false;
            return true;
        }

        static async Task<(bool ok, int value)> TryReadOneByte(NetworkStream s, CancellationToken ct)
        {
            var b = new byte[1];
            if (!await TryReadExact(s, b, ct)) return (false, 0);
            return (true, b[0]);
        }

        // SOCKS5 address encoding: IP literals use ATYP 0x01/0x04, names use
        // ATYP 0x03 with punycode ASCII (IDN-safe). Returns null when the host
        // cannot be encoded (fail closed — caller treats as connect failure).
        internal static byte[]? BuildSocksConnectRequest(string host, int port)
        {
            try
            {
                var h = (host ?? "").Trim().Trim('[', ']').Trim();
                if (h.Length == 0 || port is <= 0 or > 65535) return null;
                // Strip a trailing dot (FQDN form) for lookup stability.
                h = h.TrimEnd('.');
                if (h.Length == 0) return null;
                if (System.Net.IPAddress.TryParse(h, out var ip))
                {
                    var raw = ip.GetAddressBytes();
                    if (raw.Length == 4)
                    {
                        var req = new byte[4 + 4 + 2];
                        req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01;
                        Buffer.BlockCopy(raw, 0, req, 4, 4);
                        req[8] = (byte)(port >> 8); req[9] = (byte)(port & 0xFF);
                        return req;
                    }
                    if (raw.Length == 16)
                    {
                        var req = new byte[4 + 16 + 2];
                        req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x04;
                        Buffer.BlockCopy(raw, 0, req, 4, 16);
                        req[20] = (byte)(port >> 8); req[21] = (byte)(port & 0xFF);
                        return req;
                    }
                    return null;
                }
                string ascii;
                try { ascii = new System.Globalization.IdnMapping().GetAscii(h); }
                catch { return null; }
                if (ascii.Length == 0 || ascii.Length > 255) return null;
                var hostBytes = Encoding.ASCII.GetBytes(ascii);
                var out_ = new byte[7 + hostBytes.Length];
                out_[0] = 0x05; out_[1] = 0x01; out_[2] = 0x00; out_[3] = 0x03;
                out_[4] = (byte)hostBytes.Length;
                Buffer.BlockCopy(hostBytes, 0, out_, 5, hostBytes.Length);
                out_[5 + hostBytes.Length] = (byte)(port >> 8);
                out_[6 + hostBytes.Length] = (byte)(port & 0xFF);
                return out_;
            }
            catch { return null; }
        }

        // Verdict replies (502/400/blocked/200) use a fresh short budget
        // linked to the engine token, never hs: after the ~14s Tor retry
        // loop hs is usually expired, and writing the verdict on it turns
        // a deliverable error into a bare FIN — the app hangs with no
        // error instead of failing fast.
        static async Task<bool> ReplyAsync(NetworkStream stream, byte[] bytes, CancellationToken engineCt)
        {
            try
            {
                using var rcts = CancellationTokenSource.CreateLinkedTokenSource(engineCt);
                try { rcts.CancelAfter(TimeSpan.FromSeconds(5)); } catch { }
                await stream.WriteAsync(bytes, rcts.Token);
                return true;
            }
            catch { return false; }
        }

        // False on graceful EOF (routine for probes/half-closes), never IOException noise.
        static async Task<bool> TryReadExact(NetworkStream s, byte[] buffer, CancellationToken ct)
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