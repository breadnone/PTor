using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{

    // Outcome of a bridge-directory fetch. Never throws by construction:
    // every failure reads as zero Lines plus a human Error.
    public sealed record BridgeFetchResult(List<string> Lines, string? Error);

    // Automatic bridge supply — no manual paste, no stale bundled file.
    //
    // YES, Tor has a public API for this: the rdsys HTTPS distributor at
    // https://bridges.torproject.org/bridges?transport=<obfs4|webtunnel>
    // hands out a few fresh bridges per requesting network with NO account
    // and NO captcha (captchas were removed when rdsys replaced BridgeDB in
    // Sep 2024) — the same source Tor Browser's "get bridges" page uses.
    // It is rate-limited per network (a couple of lines per request), which
    // is all a client needs.
    //
    // Snowflake is the exception that proves the rule: Tor's directory does
    // NOT distribute it (?transport=snowflake answers an error page) —
    // because Snowflake needs no per-user bridges. Its "bridge line" is
    // static rendezvous config (broker front URL + STUN servers, dummy
    // 192.0.2.x IP), identical for every user on earth — Tor Browser ships
    // the same constant built in. The canonical live copy of that constant
    // is published by Tor itself at
    // https://bridges.torproject.org/moat/circumvention/builtin (JSON,
    // "snowflake" array), which is what FetchBuiltinSnowflakeAsync reads —
    // so even Snowflake refreshes from Tor directly instead of rotting in
    // a bundled file.
    //
    // The fetch uses the SYSTEM-default proxy on purpose (never a forced
    // direct socket, never Tor explicitly): with routing ON it transparently
    // rides the Tor proxy; with routing OFF it goes out direct. Forcing
    // direct would break the routing-ON case under lockdown, and routing
    // through Tor explicitly is impossible at fetch time when Tor is down
    // (the bridges are needed precisely to START Tor).
    //
    // Consequence: on a network that blocks bridges.torproject.org the
    // fetch fails and the bundled/manual path remains (the error says so).
    // Fetched lines go through the same BridgeConfigEngine validation as
    // pasted lines; documentation-IP placeholders are dropped for IP-pinned
    // transports (the directory answers with those when it has no real
    // bridge for the requester) but KEPT for Snowflake (dummy IPs by
    // design). Pure parsing is split out (Parse* methods) so it stays
    // unit-testable without network.
    public static class BridgeFetcher
    {
        public const string DirectoryBaseUrl = "https://bridges.torproject.org/bridges?transport=";

        // Canonical live Snowflake rendezvous config (static, same for all
        // users — see class comment). JSON object with a "snowflake" array.
        public const string CircumventionBuiltinUrl =
            "https://bridges.torproject.org/moat/circumvention/builtin";

        public static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(25);

        // Start-time refresh budget: a censored network must not stall Tor
        // startup on a fetch that was always going to fail — one quick try,
        // then the bundled fallback. The dialog fetch uses the full timeout.
        public static readonly TimeSpan StartRefreshTimeout = TimeSpan.FromSeconds(8);

        // The directory page is a few KB in practice: anything this big is
        // not ours and must not be slurped into memory.
        const long MaxDirectoryBytes = 512 * 1024;

        // Transports the HTTPS distributor actually hands out per network.
        public static bool IsDirectoryTransport(string? transport)
        {
            try
            {
                return string.Equals(transport, "obfs4", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(transport, "webtunnel", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        public static string DirectoryUrlFor(string transport) =>
            DirectoryBaseUrl + (transport ?? "").Trim().ToLowerInvariant();

        public static HttpClient CreateClient(TimeSpan? timeoutOverride = null)
        {
            var client = new HttpClient { Timeout = timeoutOverride ?? FetchTimeout };
            try { client.DefaultRequestHeaders.UserAgent.ParseAdd("PTor/bridge-fetch"); } catch { }
            return client;
        }

        public static Task<BridgeFetchResult> FetchWebTunnelAsync(
            HttpClient client, CancellationToken ct = default) =>
            FetchTransportAsync(client, "webtunnel", ct);

        public static async Task<BridgeFetchResult> FetchTransportAsync(
            HttpClient client, string transport, CancellationToken ct = default)
        {
            try
            {
                transport = (transport ?? "").Trim().ToLowerInvariant();
                if (client == null)
                    return Fail("no HTTP client.");
                if (!IsDirectoryTransport(transport))
                    return Fail($"Tor's bridge directory does not distribute '{transport}' bridges per network.");
                string html;
                try
                {
                    using var resp = await client.GetAsync(DirectoryUrlFor(transport), ct);
                    if (!resp.IsSuccessStatusCode)
                        return Fail($"Tor's bridge directory answered HTTP {(int)resp.StatusCode} — " +
                            "it may be blocked on this network. Retry later or switch mode.");
                    var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
                    if (bytes == null || bytes.Length == 0 || bytes.Length > MaxDirectoryBytes)
                        return Fail("Tor's bridge directory returned an unexpected response — " +
                            "retry later or switch mode.");
                    html = System.Text.Encoding.UTF8.GetString(bytes);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (OperationCanceledException)
                {
                    return Fail("Timed out reaching bridges.torproject.org — it may be blocked on this " +
                        "network. Retry later or switch mode.");
                }
                catch (HttpRequestException ex)
                {
                    return Fail("Could not reach bridges.torproject.org (" + ShortError(ex) + ") — " +
                        "it may be blocked on this network. Retry later or switch mode.");
                }
                catch (Exception ex)
                {
                    return Fail("Bridge fetch failed (" + ex.GetType().Name + ") — " +
                        "retry later or switch mode.");
                }

                var parsed = ParseBridgelinesHtml(html);
                if (parsed.Count == 0)
                    return Fail("Tor's bridge directory returned no bridge lines (rate-limited or empty " +
                        "for your network right now) — wait a few minutes and retry, or switch mode.");

                return SelectUsable(parsed, transport, dropPlaceholders: true);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                return Fail("Bridge fetch failed (" + ex.GetType().Name + ").");
            }
        }

        // Live Snowflake rendezvous config from Tor's published builtin set
        // (same static lines for every user — no per-network distribution
        // exists). Documentation IPs are KEPT here (dummy by design).
        // Never throws (failures read as Error); honors cancellation.
        public static async Task<BridgeFetchResult> FetchBuiltinSnowflakeAsync(
            HttpClient client, CancellationToken ct = default)
        {
            try
            {
                if (client == null)
                    return Fail("no HTTP client.");
                string json;
                try
                {
                    using var resp = await client.GetAsync(CircumventionBuiltinUrl, ct);
                    if (!resp.IsSuccessStatusCode)
                        return Fail($"Tor's directory answered HTTP {(int)resp.StatusCode} — " +
                            "it may be blocked on this network.");
                    var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
                    if (bytes == null || bytes.Length == 0 || bytes.Length > MaxDirectoryBytes)
                        return Fail("Tor's directory returned an unexpected response.");
                    json = System.Text.Encoding.UTF8.GetString(bytes);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (OperationCanceledException)
                {
                    return Fail("Timed out reaching bridges.torproject.org — it may be blocked on this network.");
                }
                catch (HttpRequestException ex)
                {
                    return Fail("Could not reach bridges.torproject.org (" + ShortError(ex) + ") — " +
                        "it may be blocked on this network.");
                }
                catch (Exception ex)
                {
                    return Fail("Snowflake refresh failed (" + ex.GetType().Name + ").");
                }

                var parsed = ParseBuiltinSnowflakeJson(json);
                if (parsed.Count == 0)
                    return Fail("Tor's directory returned no Snowflake config — retry later.");
                return SelectUsable(parsed, "snowflake", dropPlaceholders: false);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                return Fail("Snowflake refresh failed (" + ex.GetType().Name + ").");
            }
        }

        // Shared tail: validate like pasted lines, keep the requested
        // transport only, optionally drop documentation-IP placeholders.
        // Pure apart from the validators (which never throw). Never throws.
        static BridgeFetchResult SelectUsable(List<string> parsed, string transport, bool dropPlaceholders)
        {
            try
            {
                var usable = FilterUsable(parsed, transport, dropPlaceholders,
                    out var placeholders, out var wrongTransport);
                if (usable.Count == 0)
                {
                    if (placeholders > 0)
                        return Fail("Tor's directory only had placeholder bridges for your network right now " +
                            "(none usable) — retry in a few minutes or switch mode.");
                    if (wrongTransport > 0)
                        return Fail($"Tor's directory returned no {transport} lines for your network right now — " +
                            "retry later or switch mode.");
                    return Fail("Tor's directory returned lines PTor cannot use — retry later or switch mode.");
                }
                return new BridgeFetchResult(usable, null);
            }
            catch (Exception ex)
            {
                return Fail("Bridge fetch failed (" + ex.GetType().Name + ").");
            }
        }

        // Shared filter: validate like pasted lines, keep the requested
        // transport only, optionally drop documentation-IP placeholders
        // (Snowflake keeps its dummy IPs by design). Used by fetches and by
        // the auto-cache loader so both agree on what "usable" means. Pure,
        // never throws.
        internal static List<string> FilterUsable(
            List<string> parsed, string transport, bool dropPlaceholders,
            out int placeholders, out int wrongTransport)
        {
            var usable = new List<string>();
            placeholders = 0;
            wrongTransport = 0;
            try
            {
                List<string> ok;
                try { ok = BridgeConfigEngine.ValidateCustomLines(parsed).ok; }
                catch { ok = new List<string>(); }
                foreach (var line in ok)
                {
                    if (!string.Equals(BridgeConfigEngine.TransportOfLine(line),
                            transport, StringComparison.OrdinalIgnoreCase))
                    { wrongTransport++; continue; }
                    if (dropPlaceholders)
                    {
                        (string host, int port)? ep = null;
                        try { ep = Obfs4Preflight.TryParseEndpoint(line); } catch { }
                        if (ep != null)
                        {
                            bool doc = false;
                            try { doc = Obfs4Preflight.IsDocumentationIp(ep.Value.host); } catch { }
                            if (doc) { placeholders++; continue; }
                        }
                    }
                    usable.Add(line);
                    if (usable.Count >= BridgeConfigEngine.MaxBridgeLines) break;
                }
            }
            catch { }
            return usable;
        }

        static BridgeFetchResult Fail(string error)
        {
            try { return new BridgeFetchResult(new List<string>(), error); }
            catch { return new BridgeFetchResult(new List<string>(), "Bridge fetch failed."); }
        }

        static string ShortError(Exception ex)
        {
            try
            {
                var m = (ex?.Message ?? "").Replace('\r', ' ').Replace('\n', ' ').Trim();
                return m.Length <= 160 ? m : m.Substring(0, 160) + "…";
            }
            catch { return "network error"; }
        }

        // Extracts bridge lines from the directory's #bridgelines div
        // (lines separated by <br/> tags, HTML-escaped). Pure, never throws.
        public static List<string> ParseBridgelinesHtml(string? html)
        {
            var out_ = new List<string>();
            try
            {
                if (string.IsNullOrEmpty(html)) return out_;
                var idx = html.IndexOf("id=\"bridgelines\"", StringComparison.OrdinalIgnoreCase);
                if (idx < 0)
                {
                    // Fallback: some distributors answer plain text (one
                    // bridge per line). Only accept lines that already look
                    // like bridges so an error page never becomes config.
                    foreach (var raw in html.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
                    {
                        var t = WebUtility.HtmlDecode(raw ?? "").Trim();
                        if (t.Length == 0) continue;
                        if (LooksLikeBridgeLine(t)) out_.Add(StripBridgePrefix(t));
                        if (out_.Count >= BridgeConfigEngine.MaxBridgeLines) break;
                    }
                    return out_;
                }
                var divStart = html.IndexOf('>', idx);
                if (divStart < 0) return out_;
                var divEnd = html.IndexOf("</div>", divStart, StringComparison.OrdinalIgnoreCase);
                if (divEnd < 0) divEnd = Math.Min(html.Length, divStart + 32768);
                var inner = html.Substring(divStart + 1, divEnd - divStart - 1);
                try { inner = Regex.Replace(inner, @"<\s*br\s*/?\s*>", "\n", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)); }
                catch { inner = inner.Replace("<br/>", "\n").Replace("<br>", "\n").Replace("<br />", "\n"); }
                try { inner = Regex.Replace(inner, @"<[^>]*>", "", RegexOptions.None, TimeSpan.FromSeconds(2)); }
                catch { }
                foreach (var raw in inner.Split('\n'))
                {
                    var line = WebUtility.HtmlDecode(raw ?? "").Trim();
                    if (line.Length == 0) continue;
                    line = StripBridgePrefix(line);
                    if (line.Length == 0) continue;
                    out_.Add(line);
                    if (out_.Count >= BridgeConfigEngine.MaxBridgeLines) break;
                }
            }
            catch { }
            return out_;
        }

        // Reads the "snowflake" array from a circumvention/builtin JSON
        // document. Pure, never throws (garbage reads as empty).
        public static List<string> ParseBuiltinSnowflakeJson(string? json)
        {
            var out_ = new List<string>();
            try
            {
                if (string.IsNullOrWhiteSpace(json)) return out_;
                if (json.Length > MaxDirectoryBytes) return out_;
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind != JsonValueKind.Object) return out_;
                if (!doc.RootElement.TryGetProperty("snowflake", out var arr)) return out_;
                if (arr.ValueKind != JsonValueKind.Array) return out_;
                foreach (var el in arr.EnumerateArray())
                {
                    try
                    {
                        if (el.ValueKind != JsonValueKind.String) continue;
                        var line = (el.GetString() ?? "").Trim();
                        if (line.Length == 0) continue;
                        out_.Add(StripBridgePrefix(line));
                        if (out_.Count >= BridgeConfigEngine.MaxBridgeLines) break;
                    }
                    catch { }
                }
            }
            catch { }
            return out_;
        }

        static string StripBridgePrefix(string line)
        {
            try
            {
                var t = (line ?? "").Trim();
                if (t.StartsWith("Bridge ", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("Bridge\t", StringComparison.OrdinalIgnoreCase))
                    t = t.Substring(6).Trim();
                return t;
            }
            catch { return (line ?? "").Trim(); }
        }

        // Cheap pre-filter for the plain-text fallback so an HTML error
        // page can never flow into bridge config unvalidated (the real
        // validation still happens in ValidateCustomLines afterwards).
        static bool LooksLikeBridgeLine(string line)
        {
            try
            {
                var t = StripBridgePrefix(line);
                var sp = t.IndexOfAny(new[] { ' ', '\t' });
                if (sp <= 0) return false;
                var head = t.Substring(0, sp);
                return head.Equals("obfs4", StringComparison.OrdinalIgnoreCase)
                    || head.Equals("snowflake", StringComparison.OrdinalIgnoreCase)
                    || head.Equals("webtunnel", StringComparison.OrdinalIgnoreCase)
                    || head.Equals("conjure", StringComparison.OrdinalIgnoreCase)
                    || head.Equals("meek_lite", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }
    }
}
