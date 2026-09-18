using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{

    // obfs4-style (TCP) preflight: mirrors the Snowflake preflight idea for
    // IP-pinned transports. A dead/blocked bundled bridge otherwise burns a
    // full tor launch + bootstrap timeout (minutes) only to log the classic
    //   "Proxy Client: unable to connect OR connection (handshaking (proxy))
    //    ... (general SOCKS server failure)"
    // and move on. A direct TCP dial answers the reachable question in
    // seconds BEFORE tor is launched for that line: unreachable candidates
    // are skipped fast (health-benched like any failure), reachable ones
    // still go through the full tor bootstrap (TCP-open is necessary, not
    // sufficient — wrong cert/DPI can still fail the obfs4 handshake).
    //
    // Runs pre-routing only (never under an active Divert filter: probes run
    // in the PTor process, which the filter drops like any foreign traffic,
    // lying that every bridge is dead). Callers must skip it while
    // enforcement is active.
    static class Obfs4Preflight
    {
        // "obfs4 1.2.3.4:5678 FP ..." / "obfs4 [2001:db8::1]:443 FP ..." ->
        // (host, port). Null when unparseable. Never throws.
        internal static (string host, int port)? TryParseEndpoint(string? bridgeLine)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(bridgeLine)) return null;
                var parts = bridgeLine.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) return null;
                var hostPort = parts[1].Trim();
                if (hostPort.Length == 0) return null;
                string host;
                int port;
                if (hostPort.StartsWith("["))
                {
                    var close = hostPort.IndexOf(']');
                    if (close <= 1 || close + 2 >= hostPort.Length || hostPort[close + 1] != ':')
                        return null;
                    host = hostPort.Substring(1, close - 1).Trim();
                    if (!int.TryParse(hostPort.Substring(close + 2), out port))
                        return null;
                }
                else
                {
                    // Single-colon host:port only. Bare IPv6 literals never
                    // appear in obfs4 bridge lines; multi-colon without
                    // brackets is unparseable (fail open: no preflight).
                    if (hostPort.IndexOf(':') < 0 || hostPort.IndexOf(':') != hostPort.LastIndexOf(':'))
                        return null;
                    var colon = hostPort.LastIndexOf(':');
                    host = hostPort.Substring(0, colon).Trim();
                    if (!int.TryParse(hostPort.Substring(colon + 1), out port))
                        return null;
                }
                host = host.Trim().Trim('.');
                if (host.Length == 0 || port <= 0 || port > 65535) return null;
                return (host, port);
            }
            catch { return null; }
        }

        // Documentation/test ranges (RFC 5737 + RFC 3849) must never count: Snowflake
        // placeholder lines (192.0.2.x) live here, and the bridge directory
        // answers with 2001:db8::/32 placeholders when it has no real bridge
        // for the requester's network. Null preflight for them
        // (fail open — the transport path decides). Never throws.
        internal static bool IsDocumentationIp(string host)
        {
            try
            {
                if (host.StartsWith("192.0.2.", StringComparison.Ordinal)
                    || host.StartsWith("198.51.100.", StringComparison.Ordinal)
                    || host.StartsWith("203.0.113.", StringComparison.Ordinal))
                    return true;
                var h = host.Trim().Trim('[', ']').Trim();
                return h.StartsWith("2001:db8", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        internal static string CacheKey(string? bridgeLine)
        {
            try
            {
                var ep = TryParseEndpoint(bridgeLine);
                return ep == null
                    ? (bridgeLine ?? "").Trim().ToLowerInvariant()
                    : ep.Value.host.ToLowerInvariant() + ":" + ep.Value.port;
            }
            catch { return Guid.NewGuid().ToString("N"); }
        }

        // One TCP dial with a bounded timeout. Thin I/O wrapper; logic lives
        // in CheckAsync. Never returns true on cancel (throws instead so a
        // stop stays a stop, not a "bridge dead" verdict).
        internal static async Task<bool> TryTcpConnectAsync(
            string host, int port, TimeSpan timeout, CancellationToken ct)
        {
            TcpClient? client = null;
            try
            {
                client = new TcpClient();
                using var timeoutCts = new CancellationTokenSource(timeout);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
                await client.ConnectAsync(host, port, linked.Token);
                return client.Connected;
            }
            catch (OperationCanceledException) { throw; }
            catch { return false; }
            finally { try { client?.Dispose(); } catch { } }
        }

        // Decision core. tcpProbe injectable (tests fake it; real path passes
        // TryTcpConnectAsync). Never throws, except OperationCanceledException
        // (stop requested) which propagates.
        internal static async Task<(bool ok, string reason)> CheckAsync(
            string host, int port,
            Func<string, int, TimeSpan, CancellationToken, Task<bool>> tcpProbe,
            TimeSpan timeout,
            CancellationToken ct)
        {
            try
            {
                bool open;
                try { open = await tcpProbe(host, port, timeout, ct); }
                catch (OperationCanceledException) { throw; }
                catch { open = false; }
                if (open) return (true, "ok");
                return (false,
                    $"TCP connect to {host}:{port} failed (bridge down, IP:port blocked, or a firewall is stopping the helper — " +
                    "allow tor.exe + lyrebird.exe outbound if one prompts)");
            }
            catch (OperationCanceledException) { throw; }
            catch { return (false, "preflight failed"); }
        }
    }
}
