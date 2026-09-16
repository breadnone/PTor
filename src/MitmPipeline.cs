using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{
    // Shared HTTPS-inspection pipeline: upstream-TLS validation plus the
    // decrypted session runners (native HTTP/2 relay, HTTP/1.1 filter loop,
    // translators). Extracted from HttpToSocksBridge so the SOCKS relay can
    // inspect TLS on port 443 with byte-identical policy — one
    // implementation, no drift between the HTTP-proxy and SOCKS channels.
    //
    // Fail-closed throughout: invalid origins, revoked certs, malformed
    // framing, and blocked policy targets all tear the tunnel down (with a
    // clean 403/502 in the negotiated protocol), never a silent bypass.
    static class MitmPipeline
    {
        // Stream wrapper that replays buffered handshake bytes before live
        // reads, so SslStream sees the full ClientHello we already peeked at.
        internal sealed class PrefixedStream : Stream
        {
            readonly Stream _inner;
            readonly byte[] _prefix;
            int _pos;

            public PrefixedStream(Stream inner, byte[] prefix)
            {
                _inner = inner;
                _prefix = prefix ?? Array.Empty<byte>();
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => true;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }
            public override bool CanTimeout => _inner.CanTimeout;
            public override int ReadTimeout
            {
                get { try { return _inner.ReadTimeout; } catch { return -1; } }
                set { try { _inner.ReadTimeout = value; } catch { } }
            }
            public override int WriteTimeout
            {
                get { try { return _inner.WriteTimeout; } catch { return -1; } }
                set { try { _inner.WriteTimeout = value; } catch { } }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (_pos < _prefix.Length)
                {
                    var n = Math.Min(count, _prefix.Length - _pos);
                    Buffer.BlockCopy(_prefix, _pos, buffer, offset, n);
                    _pos += n;
                    return n;
                }
                return _inner.Read(buffer, offset, count);
            }

            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
            {
                if (_pos < _prefix.Length)
                {
                    var n = Math.Min(buffer.Length, _prefix.Length - _pos);
                    _prefix.AsSpan(_pos, n).CopyTo(buffer.Span);
                    _pos += n;
                    return n;
                }
                return await _inner.ReadAsync(buffer, ct);
            }

            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
                => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();

            public override void Write(byte[] buffer, int offset, int count) =>
                _inner.Write(buffer, offset, count);

            public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) =>
                _inner.WriteAsync(buffer, ct);

            public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
                _inner.WriteAsync(buffer, offset, count, ct);

            public override void Flush() { try { _inner.Flush(); } catch { } }
            public override Task FlushAsync(CancellationToken ct) { try { return _inner.FlushAsync(ct); } catch { return Task.CompletedTask; } }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
        }

        internal static string AlpnName(SslApplicationProtocol p)
        {
            try
            {
                if (p == SslApplicationProtocol.Http2) return "h2";
                if (p == SslApplicationProtocol.Http11) return "http/1.1";
                var s = p.ToString();
                return string.IsNullOrEmpty(s) ? "http/1.1" : s;
            }
            catch { return "http/1.1"; }
        }

        // Origin TLS + validation, fail-closed (single implementation for
        // both relays): chain + expiry + hostname against the system roots,
        // TLS 1.2+, ALPN [h2, http/1.1], OCSP revocation fetched THROUGH Tor
        // (MitmOcsp soft-fail: only verified REVOKED fails). Framework-level
        // revocation stays NoCheck so no fetch can leak direct.
        internal static async Task<bool> AuthenticateUpstreamAsync(
            SslStream tls, string targetHost,
            Func<string, int, CancellationToken, Task<TcpClient?>> dialTor,
            Action<string>? noteErr,
            CancellationToken ct)
        {
            X509Certificate2? leafCopy = null;
            X509Certificate2? issuerCopy = null;
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(30));
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = targetHost,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ApplicationProtocols = new List<SslApplicationProtocol>
                    {
                        SslApplicationProtocol.Http2,
                        SslApplicationProtocol.Http11,
                    },
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                    AllowRenegotiation = false,
                    RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                    {
                        if (errors != SslPolicyErrors.None)
                        {
                            try { noteErr?.Invoke(errors.ToString()); } catch { }
                            return false; // fail CLOSED: no click-through, no downgrade
                        }
                        try
                        {
                            if (cert != null)
                                leafCopy = new X509Certificate2(cert.GetRawCertData());
                            if (chain?.ChainElements != null && chain.ChainElements.Count > 1)
                                issuerCopy = new X509Certificate2(
                                    chain.ChainElements[1].Certificate.GetRawCertData());
                        }
                        catch { }
                        return true;
                    },
                }, cts.Token);

                if (leafCopy != null && issuerCopy != null)
                {
                    try
                    {
                        using var ocspCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        ocspCts.CancelAfter(TimeSpan.FromSeconds(15));
                        if (await MitmOcsp.IsRevokedByTorAsync(leafCopy, issuerCopy, dialTor, ocspCts.Token))
                        {
                            try { noteErr?.Invoke("Revoked (OCSP via Tor)"); } catch { }
                            return false;
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { }
                }
                return true;
            }
            catch (Exception ex)
            {
                try { noteErr?.Invoke(ex.GetType().Name); } catch { }
                return false;
            }
            finally
            {
                try { leafCopy?.Dispose(); } catch { }
                try { issuerCopy?.Dispose(); } catch { }
            }
        }

        // Full HTTPS inspection for one tunnel. Returns true when the tunnel
        // was handled (inspected, or failed with a clean in-protocol error).
        // Returns false ONLY when no leaf could be issued — the caller must
        // then fall back to the blind pump with helloPrefix forwarded
        // verbatim (connectivity preserved; inspection skipped, never
        // weakened). Security notes:
        // - Client side presents a per-host leaf from the LOCAL CA (the user
        //   installed its public cert; the private key never leaves the user
        //   CNG store).
        // - Upstream side re-encrypts to the REAL origin through Tor and is
        //   validated fail-closed (AuthenticateUpstreamAsync).
        // - ALPN offers [h2, http/1.1] on BOTH legs; each leg speaks whatever
        //   IT negotiated (H2H2 relay, H1H1 loop, or a translator) — the
        //   tunnel is never force-downgraded.
        internal static async Task<bool> RunInspectedTunnelAsync(
            Stream clientStream, Socket clientSocket, TcpClient upstreamTcp,
            MitmCaManager ca, string host, int port,
            byte[] helloPrefix, string sni, MitmSessionOptions opt, CancellationToken ct)
        {
            // SNI cover at the inspected-tunnel entry: the CONNECT/SOCKS
            // authority already passed, but a blocked SNI (domain-fronting
            // shape) must still fail closed before any TLS is terminated.
            // Closes without upstream use; mirrors the blind-path checks.
            try
            {
                if (opt.IsBlocked(host) ||
                    (!string.IsNullOrWhiteSpace(sni) && opt.IsBlocked(ContentFilter.NormalizeHost(sni))))
                {
                    opt.Relay("BLOCKED-DOMAIN");
                    return true;
                }
            }
            catch { }
            var upstreamSocket = upstreamTcp.Client;
            NetworkStream upstreamNet;
            try { upstreamNet = upstreamTcp.GetStream(); }
            catch { return true; }

            X509Certificate2 leaf;
            try { leaf = ca.GetLeafCertificate(host); }
            catch { return false; }

            using var replay = new PrefixedStream(clientStream, helloPrefix);
            using var clientTls = new SslStream(replay, false);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(15));
                await clientTls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = leaf,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ApplicationProtocols = new List<SslApplicationProtocol>
                    {
                        SslApplicationProtocol.Http2,
                        SslApplicationProtocol.Http11,
                    },
                    ClientCertificateRequired = false,
                    EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                    AllowRenegotiation = false,
                }, cts.Token);
            }
            catch { opt.Relay("MITM-FAIL"); return true; }

            // Upstream SNI: prefer what the client actually sent (virtual
            // hosting correctness); fall back to the tunnel authority.
            var tlsTarget = !string.IsNullOrWhiteSpace(sni) ? sni.Trim() : host;
            using var upstreamTls = new SslStream(upstreamNet, false);
            var authed = false;
            try
            {
                if (opt.AuthenticateUpstream != null)
                    authed = await opt.AuthenticateUpstream(upstreamTls, tlsTarget, ct);
            }
            catch (OperationCanceledException) { throw; }
            catch { authed = false; }
            if (!authed)
            {
                opt.Relay("MITM-FAIL");
                var clientAlpnEarly = AlpnName(clientTls.NegotiatedApplicationProtocol);
                if (clientAlpnEarly == "h2")
                {
                    // h2 framing must not receive h1 bytes: clean h2 502.
                    try { await MitmHttp2Relay.SendUpstreamFailureAsync(clientTls, "Origin certificate invalid (fail-closed).", ct); }
                    catch { }
                }
                else
                {
                    try
                    {
                        var gone = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
                        await clientTls.WriteAsync(gone, ct);
                    }
                    catch { }
                }
                return true;
            }

            var clientAlpn = AlpnName(clientTls.NegotiatedApplicationProtocol);
            var upAlpn = AlpnName(upstreamTls.NegotiatedApplicationProtocol);
            opt.Relay("MITM-" + clientAlpn + "+" + upAlpn);
            try
            {
                if (clientAlpn == "h2" && upAlpn == "h2")
                    await MitmHttp2Relay.RunAsync(clientTls, upstreamTls, opt, ct);
                else if (clientAlpn != "h2" && upAlpn != "h2")
                    await RunDecryptedH1Async(clientTls, upstreamTls, clientSocket, upstreamSocket, opt, ct);
                else if (clientAlpn == "h2")
                    await MitmHttp2Relay.RunH2ToH1Async(clientTls, opt, ct);
                else
                    await MitmHttp2Relay.RunH1ToH2Async(clientTls, opt, ct);
            }
            catch (OperationCanceledException) { throw; }
            catch { }
            return true;
        }

        // Decrypted HTTP/1.1 request/response filter loop (keep-alive aware).
        // Bodies stream by framing (never buffered whole); only headers are
        // inspected/rewritten, so gzip/video/downloads pass through intact.
        internal static async Task RunDecryptedH1Async(SslStream clientTls, SslStream upstreamTls,
            Socket clientSocket, Socket upstreamSocket,
            MitmSessionOptions opt, CancellationToken ct)
        {
            var connectHost = opt.ConnectHost;
            var connectPort = opt.ConnectPort;
            const int MaxTransactions = 100;
            for (var i = 0; i < MaxTransactions; i++)
            {
                string reqText;
                byte[] reqExtra;
                try { (reqText, reqExtra) = await Http1Plumbing.ReadHeadersAsync(clientTls, ct); }
                catch (OperationCanceledException) { return; }
                catch { return; }
                if (reqText.Length == 0) return;
                var reqLines = reqText.Split("\r\n");
                var rp = (reqLines[0] ?? "").Split(' ');
                if (rp.Length < 3) return; // fail closed on garbage
                var method = rp[0];
                if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase)) return; // no nested tunnels
                var rawTarget = rp.Length > 1 ? rp[1] : "/";
                ContentFilter.NormalizeRequestTarget(ref reqLines, connectHost);
                var reqHostFull = ContentFilter.GetHeaderValue(reqLines, "Host") ?? connectHost;
                var reqHostOnly = ContentFilter.NormalizeHost(reqHostFull);

                if (opt.IsBlocked(reqHostOnly) || opt.IsBlocked(connectHost))
                {
                    try { await clientTls.WriteAsync(ContentFilter.BuildBlockedResponse("Domain blocked by PTor (Blocked Domains)"), ct); } catch { }
                    opt.Relay("BLOCKED-DOMAIN");
                    return;
                }
                if (opt.BlockWebRtc && ContentFilter.IsWebRtcTarget(reqHostOnly, connectPort))
                {
                    try { await clientTls.WriteAsync(ContentFilter.BuildBlockedResponse("WebRTC (STUN/TURN) blocked by PTor"), ct); } catch { }
                    opt.Relay("BLOCKED-RTC");
                    return;
                }
                if (opt.BlockJs && ContentFilter.IsJsRequestPath(PathOfTarget(rawTarget)))
                {
                    try { await clientTls.WriteAsync(ContentFilter.BuildBlockedResponse("JavaScript file blocked by PTor (BlockJS)"), ct); } catch { }
                    opt.Relay("BLOCKED-JS");
                    return;
                }
                ContentFilter.RemoveProxyHopHeaders(ref reqLines);
                // No 100-continue dance on this leg: the filter loop is
                // half-duplex (request body fully forwarded before the
                // response is read), so a client waiting for "100 Continue"
                // before sending its body would deadlock against us waiting
                // for that body. Sending the body outright is always valid
                // HTTP; the bandwidth optimization is negligible here.
                ContentFilter.RemoveHeadersByName(ref reqLines, "Expect");
                if (opt.BlockCookies) ContentFilter.RemoveRequestCookies(ref reqLines);
                if (!string.IsNullOrWhiteSpace(opt.SpoofHost))
                    HttpToSocksBridge.ApplyHostSpoof(ref reqLines, opt.SpoofHost);
                try
                {
                    await WriteHeadersAndExtraAsync(upstreamTls, reqLines, reqExtra, ct);
                }
                catch { return; }
                if (!await ForwardMessageBodyAsync(clientTls, upstreamTls, reqLines, method, -1, ct)) return;

                // Response headers (forward interim 1xx, then filter final).
                string respText;
                byte[] respExtra;
                try { (respText, respExtra) = await Http1Plumbing.ReadHeadersAsync(upstreamTls, ct); }
                catch (OperationCanceledException) { return; }
                catch { return; }
                if (respText.Length == 0) return;
                var respLines = respText.Split("\r\n");
                for (var guard = 0; guard < 5 && Http1Plumbing.IsInterim1xx(respLines); guard++)
                {
                    try
                    {
                        await WriteTextAndExtraAsync(clientTls, respText, respExtra, ct);
                    }
                    catch { return; }
                    try { (respText, respExtra) = await Http1Plumbing.ReadHeadersAsync(upstreamTls, ct); }
                    catch (OperationCanceledException) { return; }
                    catch { return; }
                    if (respText.Length == 0) return;
                    respLines = respText.Split("\r\n");
                }
                var status = ContentFilter.TryGetStatusCode(respLines);
                var reqClose = ContentFilter.HasConnectionClose(reqLines);
                var respClose = ContentFilter.HasConnectionClose(respLines);
                if (status == 101)
                {
                    // Upgraded (e.g. wss): handshake honored policy already;
                    // frames pump opaquely on the decrypted legs.
                    if (opt.BlockCookies) ContentFilter.RemoveResponseCookies(ref respLines);
                    try { await WriteTextAndExtraAsync(clientTls, JoinLines(respLines), respExtra, ct); }
                    catch { return; }
                    opt.Relay("MITM-WS");
                    await PumpStreamsBothAsync(clientTls, clientSocket, upstreamTls, upstreamSocket, ct);
                    return;
                }
                var respType = ContentFilter.GetHeaderValue(respLines, "Content-Type");
                if (opt.BlockWebRtc && ContentFilter.IsSdpContentType(respType))
                {
                    try { await clientTls.WriteAsync(ContentFilter.BuildBlockedResponse("WebRTC signaling (SDP) blocked by PTor"), ct); } catch { }
                    opt.Relay("BLOCKED-RTC");
                    return;
                }
                if (opt.BlockJs && ContentFilter.IsJsContentType(respType))
                {
                    try { await clientTls.WriteAsync(ContentFilter.BuildBlockedResponse("JavaScript response blocked by PTor (BlockJS)"), ct); } catch { }
                    opt.Relay("BLOCKED-JS");
                    return;
                }
                if (opt.BlockJs && ContentFilter.IsHtmlContentType(respType))
                    ContentFilter.TryInjectJsBlockCsp(ref respLines);
                if (opt.BlockCookies) ContentFilter.RemoveResponseCookies(ref respLines);
                try { await WriteTextAndExtraAsync(clientTls, JoinLines(respLines), respExtra, ct); }
                catch { return; }
                opt.Relay("MITM");
                var body = await ForwardMessageBodyAsync(upstreamTls, clientTls, respLines, method, status, ct);
                if (!body) return; // EOF-close-delimited done, or error
                if (reqClose || respClose) return;
            }
        }

        static string JoinLines(string[] lines) => string.Join("\r\n", lines);

        static string PathOfTarget(string target)
        {
            try
            {
                if (string.IsNullOrEmpty(target)) return "/";
                if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                    || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    return new Uri(target).PathAndQuery;
                return target;
            }
            catch { return target ?? "/"; }
        }

        static async Task WriteHeadersAndExtraAsync(SslStream to, string[] lines, byte[] extra, CancellationToken ct)
        {
            var bytes = Encoding.Latin1.GetBytes(JoinLines(lines));
            await to.WriteAsync(bytes, ct);
            if (extra.Length > 0) await to.WriteAsync(extra, ct);
        }

        static async Task WriteTextAndExtraAsync(SslStream to, string text, byte[] extra, CancellationToken ct)
        {
            await to.WriteAsync(Encoding.Latin1.GetBytes(text), ct);
            if (extra.Length > 0) await to.WriteAsync(extra, ct);
        }

        // Forwards one message body per RFC 9112 framing. Returns false when
        // the connection is over (close-delimited EOF consumed, or any error:
        // caller must close both legs — fail closed, never desync framing).
        static async Task<bool> ForwardMessageBodyAsync(Stream from, Stream to,
            string[] headers, string method, int statusCode, CancellationToken ct)
        {
            try
            {
                if (statusCode >= 0)
                {
                    // Response framing.
                    if (ContentFilter.IsNoBodyResponse(statusCode, method)) return true;
                }
                else
                {
                    // Request framing: body only with explicit length signals.
                    var reqTe = ContentFilter.GetHeaderValue(headers, "Transfer-Encoding") ?? "";
                    var reqCl = ContentFilter.GetHeaderValue(headers, "Content-Length");
                    var hasBody = reqTe.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0
                        || (reqCl != null && long.TryParse(reqCl.Trim(), out var rl) && rl > 0);
                    if (!hasBody) return true;
                }
                var te = ContentFilter.GetHeaderValue(headers, "Transfer-Encoding") ?? "";
                if (te.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0)
                    return await ForwardChunkedBodyAsync(from, to, ct);
                var cl = ContentFilter.GetHeaderValue(headers, "Content-Length");
                if (cl != null && long.TryParse(cl.Trim(), out var len))
                {
                    if (len <= 0) return true;
                    // No upper cap: bodies stream through a fixed 80 KB buffer,
                    // so multi-GB downloads pass through with flat memory. A
                    // lying length fails closed below (short body) or surfaces
                    // as a framing error on the next message (long body).
                    return await ForwardFixedBodyAsync(from, to, len, ct);
                }
                if (statusCode >= 0)
                {
                    // Close-delimited response body: pump until upstream EOF.
                    await PumpOneWayAsync(from, to, ct);
                    return false;
                }
                return true;
            }
            catch (OperationCanceledException) { throw; }
            catch { return false; }
        }

        static async Task<bool> ForwardFixedBodyAsync(Stream from, Stream to, long len, CancellationToken ct)
        {
            var buf = ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                var left = len;
                while (left > 0)
                {
                    var want = (int)Math.Min(buf.Length, left);
                    int n;
                    try { n = await from.ReadAsync(buf.AsMemory(0, want), ct); }
                    catch (OperationCanceledException) { throw; }
                    catch { return false; }
                    if (n <= 0) return false;
                    try { await to.WriteAsync(buf.AsMemory(0, n), ct); }
                    catch { return false; }
                    left -= n;
                }
                return true;
            }
            finally { ArrayPool<byte>.Shared.Return(buf); }
        }

        static async Task<string?> ReadAsciiLineAsync(Stream s, int maxLen, CancellationToken ct)
        {
            var ms = new MemoryStream();
            var one = new byte[1];
            while (ms.Length < maxLen)
            {
                int n;
                try { n = await s.ReadAsync(one.AsMemory(0, 1), ct); }
                catch (OperationCanceledException) { throw; }
                catch { return null; }
                if (n <= 0) return ms.Length == 0 ? null : Encoding.ASCII.GetString(ms.ToArray());
                ms.WriteByte(one[0]);
                var len = (int)ms.Length;
                if (len >= 2)
                {
                    var buf = ms.GetBuffer();
                    if (buf[len - 2] == '\r' && buf[len - 1] == '\n')
                        return Encoding.ASCII.GetString(buf, 0, len - 2);
                }
            }
            return null; // overlong: fail closed
        }

        static async Task<bool> ForwardChunkedBodyAsync(Stream from, Stream to, CancellationToken ct)
        {
            while (true)
            {
                var line = await ReadAsciiLineAsync(from, 16384, ct);
                if (line == null) return false;
                try { await to.WriteAsync(Encoding.ASCII.GetBytes(line + "\r\n"), ct); }
                catch { return false; }
                var semi = line.IndexOf(';');
                var sizePart = (semi >= 0 ? line.Substring(0, semi) : line).Trim();
                if (!int.TryParse(sizePart, System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture, out var size) || size < 0)
                    return false;
                if (size == 0)
                {
                    // Trailers, then final CRLF.
                    while (true)
                    {
                        var t = await ReadAsciiLineAsync(from, 16384, ct);
                        if (t == null) return false;
                        try { await to.WriteAsync(Encoding.ASCII.GetBytes(t + "\r\n"), ct); }
                        catch { return false; }
                        if (t.Length == 0) return true;
                    }
                }
                if (!await ForwardFixedBodyAsync(from, to, size, ct)) return false;
                var crlf = new byte[2];
                if (!await TryReadExactStreamAsync(from, crlf, ct)) return false;
                if (crlf[0] != '\r' || crlf[1] != '\n') return false;
                try { await to.WriteAsync(crlf, ct); }
                catch { return false; }
            }
        }

        static async Task<bool> TryReadExactStreamAsync(Stream s, byte[] buffer, CancellationToken ct)
        {
            var off = 0;
            while (off < buffer.Length)
            {
                int n;
                try { n = await s.ReadAsync(buffer.AsMemory(off, buffer.Length - off), ct); }
                catch (OperationCanceledException) { throw; }
                catch { return false; }
                if (n <= 0) return false;
                off += n;
            }
            return true;
        }

        static async Task PumpOneWayAsync(Stream from, Stream to, CancellationToken ct)
        {
            var buf = ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                while (true)
                {
                    int n;
                    try { n = await from.ReadAsync(buf.AsMemory(0, 81920), ct); }
                    catch { break; }
                    if (n <= 0) break;
                    try { await to.WriteAsync(buf.AsMemory(0, n), ct); }
                    catch { break; }
                }
            }
            finally { ArrayPool<byte>.Shared.Return(buf); }
        }

        // Blind bidirectional pump for decrypted-but-upgraded streams (e.g.
        // WebSocket frames after 101): same graceful-EOF discipline as
        // StreamRelay.PumpBoth, generalized from NetworkStream to Stream.
        static async Task PumpStreamsBothAsync(Stream a, Socket aSocket, Stream b, Socket bSocket, CancellationToken ct)
        {
            async Task<bool> Copy(Stream from, Stream to)
            {
                var buf = ArrayPool<byte>.Shared.Rent(81920);
                try
                {
                    while (true)
                    {
                        int n;
                        try { n = await from.ReadAsync(buf.AsMemory(0, 81920), ct); }
                        catch { return false; }
                        if (n <= 0) return true;
                        try { await to.WriteAsync(buf.AsMemory(0, n), ct); }
                        catch { return false; }
                    }
                }
                finally { ArrayPool<byte>.Shared.Return(buf); }
            }

            var t1 = Copy(a, b);
            var t2 = Copy(b, a);
            var completed = await Task.WhenAny(t1, t2);
            bool graceful;
            try { graceful = completed.Result; } catch { graceful = false; }
            if (!graceful || ct.IsCancellationRequested) return;
            var stillRunning = ReferenceEquals(completed, t1) ? t2 : t1;
            var finishedInto = ReferenceEquals(completed, t1) ? bSocket : aSocket;
            try { finishedInto.Shutdown(SocketShutdown.Send); } catch { }
            try { await stillRunning; } catch { }
        }
    }
}
