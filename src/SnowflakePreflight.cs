using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{

    // Snowflake rendezvous needs, from the HELPER process: working system
    // DNS (broker fronts + STUN hostnames) and direct UDP (STUN + WebRTC).
    // When either is missing tor sits at 10% for the whole bootstrap timeout
    // (7 minutes) with zero log evidence. This preflight measures both in
    // ~seconds BEFORE tor is launched for a snowflake line: fail fast with
    // the true cause (or skip the candidate) instead of stalling blind.
    //
    // Runs pre-routing only (never under an active Divert filter: our own
    // probe packets would be dropped like any foreign traffic, lying that
    // UDP is dead). Callers must skip it while enforcement is active.
    static class SnowflakePreflight
    {
        public const int DefaultStunPort = 3478;

        // "ice=stun:a:3478,stun:b" -> [(a,3478),(b,3478)]. Never throws.
        internal static List<(string host, int port)> ParseIceServers(string? bridgeLine)
        {
            var out_ = new List<(string host, int port)>();
            try
            {
                if (string.IsNullOrWhiteSpace(bridgeLine)) return out_;
                foreach (var tok in bridgeLine.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!tok.StartsWith("ice=", StringComparison.OrdinalIgnoreCase)) continue;
                    var val = tok.Substring(4);
                    foreach (var item in val.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        var s = item.Trim();
                        if (s.StartsWith("stun:", StringComparison.OrdinalIgnoreCase)) s = s.Substring(5);
                        var q = s.IndexOf('?');
                        if (q >= 0) s = s.Substring(0, q);
                        if (s.Length == 0) continue;
                        var host = s;
                        var port = DefaultStunPort;
                        var colon = s.LastIndexOf(':');
                        // Host with explicit port. A bare IPv6 literal
                        // ("::1") holds several colons and no brackets: only
                        // split a bracketed host or a single-colon host:port.
                        // (Bare literals never appear in snowflake ice lists;
                        // bracketed ones do.)
                        if (colon >= 0 && (s.StartsWith("[") || s.IndexOf(':') == colon))
                        {
                            var after = s.Substring(colon + 1);
                            if (int.TryParse(after, out var p) && p > 0 && p <= 65535)
                            {
                                host = s.Substring(0, colon).Trim('[', ']', ' ');
                                port = p;
                            }
                        }
                        host = host.Trim();
                        if (host.Length == 0) continue;
                        if (!out_.Any(e => e.host.Equals(host, StringComparison.OrdinalIgnoreCase) && e.port == port))
                            out_.Add((host, port));
                    }
                }
            }
            catch { }
            return out_;
        }

        // "fronts=a,b" / "front=a" values from the bridge line. Never throws.
        internal static List<string> ParseFronts(string? bridgeLine)
        {
            var out_ = new List<string>();
            try
            {
                if (string.IsNullOrWhiteSpace(bridgeLine)) return out_;
                foreach (var tok in bridgeLine.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string? val = null;
                    if (tok.StartsWith("fronts=", StringComparison.OrdinalIgnoreCase)) val = tok.Substring(7);
                    else if (tok.StartsWith("front=", StringComparison.OrdinalIgnoreCase)) val = tok.Substring(6);
                    if (val == null) continue;
                    foreach (var h in val.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        var host = h.Trim().Trim('[', ']');
                        if (host.Length == 0) continue;
                        if (!out_.Any(e => e.Equals(host, StringComparison.OrdinalIgnoreCase)))
                            out_.Add(host);
                    }
                }
            }
            catch { }
            return out_;
        }

        // Cache key so one preflight verdict covers every line sharing the
        // same helper infra (bundled lines are identical). Never throws.
        internal static string CacheKey(string? bridgeLine)
        {
            try
            {
                var ice = ParseIceServers(bridgeLine)
                    .Select(e => e.host.ToLowerInvariant() + ":" + e.port).OrderBy(x => x);
                var fronts = ParseFronts(bridgeLine)
                    .Select(h => h.ToLowerInvariant()).OrderBy(x => x);
                return "ice=" + string.Join(",", ice) + "|fronts=" + string.Join(",", fronts);
            }
            catch { return Guid.NewGuid().ToString("N"); }
        }

        // Minimal RFC 5389 binding request (no auth, no fingerprint).
        internal static byte[] BuildStunBindingRequest(byte[] txId)
        {
            var req = new byte[20];
            req[0] = 0x00; req[1] = 0x01; // Binding Request
            req[2] = 0x00; req[3] = 0x00; // length 0
            req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42; // magic cookie
            Buffer.BlockCopy(txId, 0, req, 8, Math.Min(12, txId.Length));
            return req;
        }

        internal static bool IsStunBindingResponse(byte[] buf, int len, byte[] txId)
        {
            try
            {
                if (buf == null || len < 20 || len > buf.Length) return false;
                if (buf[0] != 0x01 || buf[1] != 0x01) return false; // Binding Success
                if (buf[4] != 0x21 || buf[5] != 0x12 || buf[6] != 0xA4 || buf[7] != 0x42) return false;
                for (var i = 0; i < 12; i++)
                    if (buf[8 + i] != txId[i]) return false;
                return true;
            }
            catch { return false; }
        }

        // One UDP STUN round-trip, IPv4 preferred (broken-v6-path false
        // negatives help nobody). Thin I/O wrapper; logic lives in CheckAsync.
        internal static async Task<bool> UdpStunProbeAsync(string host, int port, TimeSpan timeout, CancellationToken ct)
        {
            UdpClient? udp = null;
            try
            {
                IPAddress[] addrs;
                try { addrs = await Dns.GetHostAddressesAsync(host, ct); }
                catch { return false; }
                if (addrs == null || addrs.Length == 0) return false;
                var ordered = addrs.OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).ToArray();
                var txId = new byte[12];
                try { System.Security.Cryptography.RandomNumberGenerator.Fill(txId); }
                catch { new Random().NextBytes(txId); }
                var req = BuildStunBindingRequest(txId);
                using var timeoutCts = new CancellationTokenSource(timeout);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
                var lct = linked.Token;
                foreach (var addr in ordered.Take(2))
                {
                    try
                    {
                        udp?.Dispose();
                        udp = new UdpClient(addr.AddressFamily);
                        try { udp.Client.ReceiveTimeout = (int)Math.Min(timeout.TotalMilliseconds, int.MaxValue); } catch { }
                        await udp.SendAsync(req, req.Length, new IPEndPoint(addr, port));
                        var res = await udp.ReceiveAsync(lct);
                        if (res.Buffer != null && IsStunBindingResponse(res.Buffer, res.Buffer.Length, txId))
                            return true;
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { }
                }
                return false;
            }
            catch (OperationCanceledException) { throw; }
            catch { return false; }
            finally { try { udp?.Dispose(); } catch { } }
        }

        internal static async Task<bool> DnsResolvesAsync(string host, CancellationToken ct)
        {
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(host, ct);
                return addrs != null && addrs.Length > 0;
            }
            catch { return false; }
        }

        // True when a (false, reason) verdict is DETERMINISTIC death rather
        // than "couldn't tell": tor would log the same verdict after
        // minutes ("broker failure ... lookup ...", "stuck at 10%"), so
        // launching tor only burns the full bootstrap budget and callers
        // should skip the candidate immediately. DNS death (no broker/STUN
        // name resolves — Snowflake has nothing to talk to) and UDP death
        // (no STUN reply anywhere — WebRTC rendezvous needs direct UDP)
        // both qualify. Any other false reason stays inconclusive and
        // deserves the full rendezvous attempt. Never throws.
        internal static bool IsHardFailure(string? reason)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(reason)) return false;
                var r = reason.Trim();
                return r.StartsWith("no broker/STUN hostname resolves", StringComparison.Ordinal)
                    || r.StartsWith("no STUN reply over UDP", StringComparison.Ordinal);
            }
            catch { return false; }
        }

        // Decision core. udpProbe/dnsCheck injectable (tests fake them; real
        // path passes UdpStunProbeAsync/DnsResolvesAsync). First success wins;
        // budget caps the whole check. Never throws (false + reason).
        internal static async Task<(bool ok, string reason)> CheckAsync(
            IEnumerable<(string host, int port)> iceServers,
            IEnumerable<string> frontHosts,
            Func<string, int, TimeSpan, CancellationToken, Task<bool>> udpProbe,
            Func<string, CancellationToken, Task<bool>> dnsCheck,
            TimeSpan budget,
            CancellationToken ct)
        {
            try
            {
                var ice = (iceServers ?? Enumerable.Empty<(string host, int port)>())
                    .Where(e => !string.IsNullOrWhiteSpace(e.host)).Take(4).ToList();
                var fronts = (frontHosts ?? Enumerable.Empty<string>())
                    .Where(h => !string.IsNullOrWhiteSpace(h)).Take(4).ToList();
                using var budgetCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                budgetCts.CancelAfter(budget);
                var bct = budgetCts.Token;

                // DNS first: without names nothing else can even start.
                var names = ice.Select(e => e.host).Concat(fronts).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                if (names.Count > 0)
                {
                    var dnsTasks = names.Select(h => SafeDns(dnsCheck, h, bct)).ToArray();
                    var dnsResults = await Task.WhenAll(dnsTasks);
                    if (!dnsResults.Any(r => r))
                        return (false, "no broker/STUN hostname resolves (system DNS is broken or those hosts are blocked)");
                }

                // UDP STUN: any single success proves a usable path.
                if (ice.Count > 0)
                {
                    var udpTasks = ice.Select(e => SafeUdp(udpProbe, e.host, e.port, bct)).ToArray();
                    var udpResults = await Task.WhenAll(udpTasks);
                    if (!udpResults.Any(r => r))
                        return (false, "no STUN reply over UDP (direct UDP looks blocked — Snowflake cannot connect without it)");
                }
                return (true, "ok");
            }
            catch (OperationCanceledException) { throw; }
            catch { return (false, "preflight failed"); }
        }

        static async Task<bool> SafeDns(Func<string, CancellationToken, Task<bool>> f, string h, CancellationToken ct)
        {
            try { return await f(h, ct); } catch (OperationCanceledException) { throw; } catch { return false; }
        }

        static async Task<bool> SafeUdp(Func<string, int, TimeSpan, CancellationToken, Task<bool>> f,
            string h, int p, CancellationToken ct)
        {
            // Per-server slice so one blackhole doesn't eat the budget.
            try { return await f(h, p, TimeSpan.FromSeconds(4), ct); } catch (OperationCanceledException) { throw; } catch { return false; }
        }
    }
}
