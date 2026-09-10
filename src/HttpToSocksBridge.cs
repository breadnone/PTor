using System;
using System.Buffers;
using System.IO;
using System.Net;
using System.Net.Sockets;
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
        const int MaxConcurrent = 256;
        static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(20);
        readonly SemaphoreSlim _gate = new(MaxConcurrent, MaxConcurrent);

        readonly string _socksHost;
        readonly int _socksPort;
        TcpListener? _listener;
        CancellationTokenSource? _cts;

        public string SpoofHost { get; set; } = "";

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
            if (_cts != null && !_cts.IsCancellationRequested) return;
            try { _cts?.Dispose(); } catch { }
            _cts = new CancellationTokenSource();
            _listener = new TcpListener(IPAddress.Loopback, ListenPort);

            try { _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true); } catch { }
            _listener.Start();
            _ = AcceptLoop(_cts.Token);
        }

        async Task AcceptLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await _listener!.AcceptTcpClientAsync(ct); }
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
                    if (parts.Length < 2) return;

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

        // Returns headers decoded once + any bytes already read past the
        // terminator (pipelined body / pre-200 bytes), forwarded verbatim by
        // the caller. The old code decoded the whole buffer per chunk (O(n^2))
        // and allocated a fresh chunk per connection; the chunk here is
        // pooled and the terminator scan is byte-level (no decode).
        async Task<(string text, byte[] extra)> ReadHeadersAsync(NetworkStream stream, CancellationToken ct)
        {
            var chunk = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                using var ms = new MemoryStream();
                while (true)
                {
                    var read = await stream.ReadAsync(chunk.AsMemory(0, 8192), ct);
                    if (read <= 0) break;
                    ms.Write(chunk, 0, read);
                    if (ms.Length > 64 * 1024) break;
                    if (FindHeaderEnd(ms) is int end)
                    {
                        var buf = ms.GetBuffer();
                        var text = Encoding.Latin1.GetString(buf, 0, end);
                        var extraLen = (int)ms.Length - end;
                        var extra = Array.Empty<byte>();
                        if (extraLen > 0)
                        {
                            extra = new byte[extraLen];
                            Buffer.BlockCopy(buf, end, extra, 0, extraLen);
                        }
                        return (text, extra);
                    }
                }
                if (ms.Length == 0) return ("", Array.Empty<byte>());
                return (Encoding.Latin1.GetString(ms.ToArray()), Array.Empty<byte>());
            }
            finally { ArrayPool<byte>.Shared.Return(chunk); }
        }

        // Index just past the first \r\n\r\n, or null. Byte scan: no decode.
        static int? FindHeaderEnd(MemoryStream ms)
        {
            try
            {
                var buf = ms.GetBuffer();
                var len = (int)ms.Length;
                for (var i = 0; i + 3 < len; i++)
                {
                    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
                        return i + 4;
                }
                return null;
            }
            catch { return null; }
        }

        async Task HandleConnect(NetworkStream clientStream, Socket clientSocket, string target, byte[] preface, CancellationToken hs, CancellationToken ct)
        {
            // Authority-form may hold a bracketed IPv6 literal: split at the
            // last colon, and only when the suffix is a numeric port.
            var host = target.Trim();
            var port = 443;
            var hostPart = host;
            var colon = host.LastIndexOf(':');
            if (colon >= 0 && host.Length - colon - 1 <= 5 &&
                int.TryParse(host.Substring(colon + 1), out var parsedPort) &&
                parsedPort is > 0 and <= 65535)
            {
                if (host[0] != '[' || (colon > 0 && host[colon - 1] == ']'))
                {
                    hostPart = host.Substring(0, colon);
                    port = parsedPort;
                }
            }
            host = hostPart.Trim().Trim('[', ']').Trim();
            if (host.Length == 0) return;

            using var socksClient = await SocksUpstream.ConnectWithRetryAsync(
                _socksHost, _socksPort, host, port,
                s => Socks5Connect(s, host, port, hs), hs);
            if (socksClient == null)
            {
                var fail = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
                await clientStream.WriteAsync(fail, hs);
                return;
            }
            var socksStream = socksClient.GetStream();

            var ok = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
            await clientStream.WriteAsync(ok, hs);

            // Bytes the client pipelined before the 200 (rare, but legal):
            // forward them instead of dropping, then sniff what follows.
            if (preface.Length > 0)
            {
                try { await socksStream.WriteAsync(preface, hs); } catch { return; }
            }
            var sni = await SniffSniAsync(clientStream, socksStream, hs);
            OnRelayed(host, port, "CONNECT", "", sni);

            await StreamRelay.PumpBoth(clientStream, clientSocket, socksStream, socksClient.Client, ct);
        }

        static async Task<string> SniffSniAsync(NetworkStream client, NetworkStream socks, CancellationToken ct)
        {
            // Pooled: one 16 KB buffer per CONNECT adds up under load.
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
                    return "";
                }
                catch { return ""; }
                if (n <= 0) return "";
                try { await socks.WriteAsync(probe.AsMemory(0, n), ct); }
                catch { return ""; }
                return TryParseSni(probe, n);
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
            using var socksClient = await SocksUpstream.ConnectWithRetryAsync(
                _socksHost, _socksPort, uri.Host, uri.Port,
                s => Socks5Connect(s, uri.Host, uri.Port, hs), hs);
            if (socksClient == null)
            {
                var fail = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
                await clientStream.WriteAsync(fail, hs);
                return;
            }
            var socksStream = socksClient.GetStream();

            var lines = headerText.Split("\r\n");
            lines[0] = $"{method} {uri.PathAndQuery} HTTP/1.1";
            var spoofed = ApplyHostSpoof(ref lines, SpoofHost);
            var rewritten = string.Join("\r\n", lines);
            var bytes = Encoding.Latin1.GetBytes(rewritten);
            await socksStream.WriteAsync(bytes, hs);
            // Body bytes that arrived with the headers go out verbatim next —
            // the pump only sees what arrives after this point.
            if (extraBody.Length > 0)
            {
                try { await socksStream.WriteAsync(extraBody, hs); }
                catch
                {
                    var gone = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
                    try { await clientStream.WriteAsync(gone, hs); } catch { }
                    return;
                }
            }

            OnRelayed(uri.Host, uri.Port, method, spoofed);

            await StreamRelay.PumpBoth(clientStream, clientSocket, socksStream, socksClient.Client, ct);
        }

        static async Task<bool> Socks5Connect(NetworkStream s, string host, int port, CancellationToken ct)
        {

            await s.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, ct);
            var resp = new byte[2];
            if (!await TryReadExact(s, resp, ct)) return false;
            if (resp[0] != 0x05 || resp[1] != 0x00) return false;

            var hostBytes = Encoding.Latin1.GetBytes(host);
            var req = new byte[7 + hostBytes.Length];
            req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03;
            req[4] = (byte)hostBytes.Length;
            Buffer.BlockCopy(hostBytes, 0, req, 5, hostBytes.Length);
            req[5 + hostBytes.Length] = (byte)(port >> 8);
            req[6 + hostBytes.Length] = (byte)(port & 0xFF);

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
            try { _cts?.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }
            // Full reset so the next Start rebinds cleanly (no stale CTS).
            try { _cts?.Dispose(); } catch { }
            _cts = null;
            _listener = null;
        }
    }
}