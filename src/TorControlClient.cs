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
                    DisposeCurrent();
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
                    var stream = _stream;
                    if (stream == null) { DisposeCurrent(); return false; }
                    var reply = await SendRawAsync(stream, authLine, opCts.Token);
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
            // NOTE: a "down" reply is still "250-network-liveness=down...250 OK",
            // so StartsWith("250") alone is vacuous — only an explicit "=up" counts.
            return reply.Contains("network-liveness=up");
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

        // Raw GETINFO circuit-status reply (multi-line "250+circuit-status=").
        // Public so the Config dialog can offer "use current circuit" without
        // a new socket. Never throws: failures read as empty string.
        public async Task<string> GetCircuitStatusAsync()
        {
            try { return await SendCommandAsync("GETINFO circuit-status"); }
            catch { return ""; }
        }

        // Parses a circuit-status reply into the fingerprints of the best
        // live circuit: prefers the LONGEST BUILT GENERAL circuit (the data
        // path — a 3-hop one fills entry+middle+exit), falls back to the
        // longest BUILT circuit with >= 1 hop. Returns (entry, middle, exit)
        // as "$FP" tokens, or nulls when none found. Pure + never throws
        // (unit-testable without a tor connection). First-match used to win,
        // which often picked a 1-hop directory circuit and left the middle /
        // exit boxes empty ("use current circuit fills only the 1st box").
        public static (string? entry, string? middle, string? exit) ParseLiveCircuitNodes(string? reply)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(reply)) return (null, null, null);
                List<string>? bestGeneral = null;
                List<string>? bestFallback = null;
                foreach (var rawLine in reply.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var line = rawLine.Trim();
                    if (line.StartsWith("250", StringComparison.Ordinal)) continue;
                    // Format: "<id> <STATUS> <path> [PURPOSE=...] ..."
                    var parts = line.Split(new[] { ' ' }, 4, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 3) continue;
                    if (!parts[0].All(char.IsDigit)) continue;
                    var status = parts[1];
                    if (!status.Equals("BUILT", StringComparison.OrdinalIgnoreCase)) continue;
                    var path = parts[2];
                    if (string.IsNullOrWhiteSpace(path)) continue;
                    var hops = path.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(h => NormalizeCircuitHop(h))
                        .Where(h => h != null)
                        .Select(h => h!)
                        .ToList();
                    if (hops.Count == 0) continue;
                    var isGeneral = line.IndexOf("PURPOSE=GENERAL", StringComparison.OrdinalIgnoreCase) >= 0;
                    if (isGeneral)
                    {
                        if (bestGeneral == null || hops.Count > bestGeneral.Count)
                            bestGeneral = hops;
                    }
                    else if (bestFallback == null || hops.Count > bestFallback.Count)
                    {
                        bestFallback = hops;
                    }
                }
                if (bestGeneral != null) return SplitHops(bestGeneral);
                if (bestFallback != null) return SplitHops(bestFallback);
                return (null, null, null);
            }
            catch { return (null, null, null); }
        }

        static (string? entry, string? middle, string? exit) SplitHops(List<string> hops)
        {
            try
            {
                if (hops.Count == 1) return (hops[0], null, null);
                if (hops.Count == 2) return (hops[0], null, hops[1]);
                // 3+ hops: entry = first, exit = last, middle = middle hop(s).
                // Pin takes a single middle token; join extras comma-separated
                // by the caller (here: keep first middle, torrc allows one list).
                var middle = hops.Count == 3 ? hops[1] : string.Join(",", hops.Skip(1).Take(hops.Count - 2));
                return (hops[0], middle, hops[^1]);
            }
            catch { return (null, null, null); }
        }

        // A circuit path hop looks like "$FP=name", "$FP~name", or bare
        // "$FP". Returns the normalized "$FP" (uppercase), or null when the
        // hop is not a fingerprint (e.g. a nickname-only path, which torrc
        // also accepts but we prefer the stable fingerprint form).
        static string? NormalizeCircuitHop(string hop)
        {
            try
            {
                var h = hop.Trim().Trim('"');
                if (h.Length == 0) return null;
                if (!h.StartsWith("$")) return null;
                var body = h.Substring(1);
                var sep = body.IndexOfAny(new[] { '=', '~' });
                var fp = sep >= 0 ? body.Substring(0, sep) : body;
                if (fp.Length != 40) return null;
                foreach (var c in fp)
                    if (!Uri.IsHexDigit(c)) return null;
                return "$" + fp.ToUpperInvariant();
            }
            catch { return null; }
        }

        public async Task<(string? entry, string? middle, string? exit)> GetLiveCircuitNodesAsync()
        {
            try
            {
                var reply = await GetCircuitStatusAsync();
                return ParseLiveCircuitNodes(reply);
            }
            catch { return (null, null, null); }
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
                var stream = _stream;
                var client = _client;
                if (client == null || stream == null || !client.Connected) return "515 Not connected";
                using var opCts = new CancellationTokenSource(CommandTimeoutMs);
                return await SendRawAsync(stream, command + "\r\n", opCts.Token);
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

        async Task<string> SendRawAsync(NetworkStream stream, string command, CancellationToken ct)
        {
            var bytes = Encoding.ASCII.GetBytes(command);
            await stream.WriteAsync(bytes, ct);

            var buffer = new byte[4096];
            var sb = new StringBuilder();

            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var read = await stream.ReadAsync(buffer, ct);
                if (read <= 0) break;
                sb.Append(Encoding.ASCII.GetString(buffer, 0, read));
                var s = sb.ToString();
                // Tor control framing: replies terminate with "250 <text>\r\n"
                // (or "250\r\n"), errors with "5XX <text>\r\n". Data lines in
                // multi-line replies (e.g. "5 BUILT ...") must NOT terminate
                // the read — require the 3-digit code + separator form.
                if (s.EndsWith("\r\n") && IsFinalControlReply(s))
                    break;
            }
            return sb.ToString();
        }

        static bool IsFinalControlReply(string s)
        {
            try
            {
                // Final line forms: "\r\n250 ...", "250 ..." (single line),
                // "\r\n5XX ..." / "5XX ..." (errors). Continuation lines use
                // "250-..." / "5XX-..." and must not terminate.
                if (s.StartsWith("250 ", StringComparison.Ordinal) || s.StartsWith("250\r\n", StringComparison.Ordinal))
                    return true;
                if (s.Length >= 3 && s[0] == '5' && char.IsDigit(s[1]) && char.IsDigit(s[2]) &&
                    (s.Length == 3 || s[3] == ' ' || s[3] == '\r' || s[3] == '\n'))
                    return true;
                var idx = s.LastIndexOf("\r\n250 ", StringComparison.Ordinal);
                if (idx >= 0) return true;
                if (s.Contains("\r\n250\r\n", StringComparison.Ordinal)) return true;
                // Error terminator: \r\n + 5 + digit + digit + (space | \r | end).
                for (var i = s.IndexOf("\r\n5", StringComparison.Ordinal); i >= 0; i = s.IndexOf("\r\n5", i + 1, StringComparison.Ordinal))
                {
                    if (i + 4 < s.Length && char.IsDigit(s[i + 3]) && char.IsDigit(s[i + 4]))
                    {
                        var after = i + 5 < s.Length ? s[i + 5] : ' ';
                        if (after == ' ' || after == '\r' || after == '\n') return true;
                    }
                    else if (i + 4 >= s.Length)
                    {
                        // Trailing partial — keep reading.
                        return false;
                    }
                }
                return false;
            }
            catch { return false; }
        }

        static string? TryReadCookieHex(string path)
        {
            try
            {
                // 32 bytes; short reads/sharing violations mean "retry next attempt".
                // Capped: a planted/bloated file must not be slurped into memory.
                var bytes = SafeFiles.ReadAllBytesCapped(path, 1024);
                if (bytes == null || bytes.Length != 32) return null;
                return Convert.ToHexString(bytes);
            }
            catch { return null; }
        }

        void DisposeCurrent()
        {
            // Lock-free by design: an in-flight SendCommandAsync holds its own
            // stream/client refs and fails as "515 ..." when we close beneath
            // it (fail-closed, never a leak). Taking _lock here would park the
            // stop path behind a wedged 15s command. Capture-then-null keeps
            // the race safe: a command that grabbed the refs before the null
            // just aborts; one arriving after sees "Not connected".
            NetworkStream? s;
            TcpClient? c;
            try { s = _stream; _stream = null; } catch { s = null; }
            try { c = _client; _client = null; } catch { c = null; }
            try { s?.Dispose(); } catch { }
            try { c?.Dispose(); } catch { }
        }

        public void Dispose()
        {
            DisposeCurrent();
            // Never dispose _lock: an in-flight SendCommandAsync may be
            // parked in WaitAsync and disposing its semaphore throws inside
            // that waiter. One undisposed semaphore per client is harmless
            // (finalizer reclaims); aborting the connection is what matters.
        }
    }
}
