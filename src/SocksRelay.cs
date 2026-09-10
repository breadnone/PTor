using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{

    static class SocksUpstream
    {
        public static async Task<TcpClient?> ConnectWithRetryAsync(
            string socksHost, int socksPort,
            string targetHost, int targetPort,
            Func<NetworkStream, Task<bool>> handshake,
            CancellationToken ct)
        {
            static void Drop(TcpClient? c) { try { c?.Dispose(); } catch { } }

            var tcp = new TcpClient();
            try
            {
                await tcp.ConnectAsync(socksHost, socksPort, ct);
            }
                catch (OperationCanceledException) { Drop(tcp); throw; }
                catch { Drop(tcp); return null; }

            // 4 attempts over ~6s; rotations need 5-20s to rebuild circuits.
            for (var attempt = 1; attempt <= 4; attempt++)
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
                if (attempt < 4)
                    await Task.Delay(attempt == 1 ? 500 : attempt == 2 ? 1500 : 4000, ct);
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
        const int MaxConcurrent = 256;
        static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(20);
        readonly SemaphoreSlim _gate = new(MaxConcurrent, MaxConcurrent);

        readonly string _upstreamHost;
        readonly int _upstreamPort;
        TcpListener? _listener;
        CancellationTokenSource? _cts;

        public int ListenPort { get; }

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

                    // In-app blocklist: refuse locally, never open upstream.
                    if (!System.Net.IPAddress.TryParse(host, out _) && AdBlockStore.Instance.IsBlocked(host))
                    {
                        try { await stream.WriteAsync(new byte[] { 0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, hs); }
                        catch { }
                        try { Relayed?.Invoke(this, new RelayEventArgs { Host = host, Port = port, Mode = "BLOCKED" }); }
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

        public static async Task<bool> SocksConnectAsync(NetworkStream s, string host, int port, CancellationToken ct)
        {
            await s.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, ct);
            var resp = new byte[2];
            if (!await TryReadExactAsync(s, resp, ct)) return false;
            if (resp[0] != 0x05 || resp[1] != 0x00) return false;

            var hostBytes = Encoding.ASCII.GetBytes(host);
            var req = new byte[7 + hostBytes.Length];
            req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03;
            req[4] = (byte)hostBytes.Length;
            Buffer.BlockCopy(hostBytes, 0, req, 5, hostBytes.Length);
            req[5 + hostBytes.Length] = (byte)(port >> 8);
            req[6 + hostBytes.Length] = (byte)(port & 0xFF);

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
            try { _cts?.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }
            // Full reset so the next Start rebinds cleanly (no stale CTS).
            try { _cts?.Dispose(); } catch { }
            _cts = null;
            _listener = null;
        }
    }
}