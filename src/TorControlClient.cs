using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{

    public class TorControlClient : IDisposable
    {
        readonly string _host;
        readonly int _port;
        readonly string? _cookiePath;
        TcpClient? _client;
        NetworkStream? _stream;
        readonly SemaphoreSlim _lock = new(1, 1);

        // Every control reply is bounded: an accepted-but-silent control
        // port (wedged tor) previously hung reads forever, pinning whatever
        // held the lifecycle gate and freezing the whole app.
        const int CommandTimeoutMs = 15000;

        // Set once a cookie is ever read (lets timeouts distinguish slow tor from missing cookie).
        public bool CookieSeen { get; private set; }

        public TorControlClient(string host, int port, string? cookiePath = null)
        {
            _host = host;
            _port = port;
            _cookiePath = cookiePath;
        }

        public async Task<bool> ConnectAsync(int timeoutMs = 3000)
        {
            // Never stack clients: bootstrap retries share one instance; orphans leak sockets.
            DisposeCurrent();
            try
            {
                var client = new TcpClient();
                _client = client;
                using var cts = new CancellationTokenSource(timeoutMs);
                try
                {
                    await client.ConnectAsync(_host, _port, cts.Token);
                }
                catch (OperationCanceledException)
                {
                    return false;
                }

                _stream = client.GetStream();

                // Cookie re-read every attempt (regenerated per tor process); missing = retry, not fail.
                string authLine = "AUTHENTICATE\r\n";
                if (!string.IsNullOrEmpty(_cookiePath))
                {
                    var cookieHex = TryReadCookieHex(_cookiePath);
                    if (cookieHex == null) { DisposeCurrent(); return false; }
                    CookieSeen = true;
                    authLine = "AUTHENTICATE " + cookieHex + "\r\n";
                }

                using (var opCts = new CancellationTokenSource(CommandTimeoutMs))
                {
                    var reply = await SendRawAsync(authLine, opCts.Token);
                    if (!reply.StartsWith("250"))
                    {
                        DisposeCurrent();
                        return false;
                    }
                }
                return true;
            }
            catch
            {
                DisposeCurrent();
                return false;
            }
        }

        public bool IsConnected => _client?.Connected == true;

        public async Task<bool> NewIdentityAsync()
        {
            var reply = await SendCommandAsync("SIGNAL NEWNYM");
            return reply.StartsWith("250");
        }

        public async Task<string> GetCountryAsync(string ip)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(ip)) return "??";
                var clean = ip.Trim();
                foreach (var c in clean)
                {
                    if (!(char.IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' || c == ':'))
                        return "??";
                }
                if (clean.Length > 45) return "??";
                var reply = await SendCommandAsync("GETINFO ip-to-country/" + clean);

                var idx = reply.LastIndexOf('=');
                if (idx < 0) return "??";
                var code = "";
                for (var i = idx + 1; i < reply.Length && code.Length < 2; i++)
                {
                    if (char.IsLetter(reply[i])) code += char.ToUpperInvariant(reply[i]);
                    else break;
                }
                return code.Length == 2 ? code : "??";
            }
            catch { return "??"; }
        }

        public async Task<bool> HeartbeatAsync()
        {
            var reply = await SendCommandAsync("GETINFO network-liveness");
            return reply.Contains("network-liveness=up") || reply.StartsWith("250");
        }

        public async Task<int> GetBootstrapPercentAsync()
        {
            var reply = await SendCommandAsync("GETINFO status/bootstrap-phase");
            var idx = reply.IndexOf("PROGRESS=", StringComparison.Ordinal);
            if (idx < 0) return -1;
            var rest = reply[(idx + "PROGRESS=".Length)..];
            var end = 0;
            while (end < rest.Length && char.IsDigit(rest[end])) end++;
            return end > 0 && int.TryParse(rest[..end], out var v) ? v : -1;
        }

        async Task<string> SendCommandAsync(string command)
        {
            // A stop-path dispose racing in-flight ticks must read as "not
            // connected", never escape. The wait itself is bounded so a stuck
            // holder can't wedge callers; timeout degrades to "not connected".
            bool entered;
            try { entered = await _lock.WaitAsync(CommandTimeoutMs); }
            catch (ObjectDisposedException) { return "515 Not connected"; }
            if (!entered) return "515 Busy";
            try
            {
                if (!IsConnected) return "515 Not connected";
                using var opCts = new CancellationTokenSource(CommandTimeoutMs);
                return await SendRawAsync(command + "\r\n", opCts.Token);
            }
            catch (Exception ex)
            {
                return "515 " + ex.Message;
            }
            finally
            {
                try { _lock.Release(); } catch { }
            }
        }

        async Task<string> SendRawAsync(string command, CancellationToken ct)
        {
            var bytes = Encoding.ASCII.GetBytes(command);
            await _stream!.WriteAsync(bytes, ct);

            var buffer = new byte[4096];
            var sb = new StringBuilder();

            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var read = await _stream.ReadAsync(buffer, ct);
                if (read <= 0) break;
                sb.Append(Encoding.ASCII.GetString(buffer, 0, read));
                var s = sb.ToString();
                if (s.EndsWith("\r\n") &&
                    (s.Contains("\r\n250 ") || s.StartsWith("250 ") || s.Contains("\r\n5") || s.StartsWith("5")))
                    break;
            }
            return sb.ToString();
        }

        static string? TryReadCookieHex(string path)
        {
            try
            {
                // 32 bytes; short reads/sharing violations mean "retry next attempt".
                var bytes = File.ReadAllBytes(path);
                if (bytes == null || bytes.Length != 32) return null;
                return Convert.ToHexString(bytes);
            }
            catch { return null; }
        }

        void DisposeCurrent()
        {
            try { _stream?.Dispose(); } catch { }
            _stream = null;
            try { _client?.Dispose(); } catch { }
            _client = null;
        }

        public void Dispose()
        {
            DisposeCurrent();
            try { _lock?.Dispose(); } catch { }
        }
    }
}
