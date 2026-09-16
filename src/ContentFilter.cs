using System;
using System.Collections.Generic;
using System.Text;

namespace PTor
{
    // Proxy content policy enforced by PTor's own relays.
    // - Plain-HTTP: request-path + response-MIME blocks, CSP injection,
    //   cookie stripping — no system changes.
    // - HTTPS: same policy applies INSIDE the TLS inspection channel when
    //   MitmEnabled (local CA in CurrentUser\Root; origins still validated
    //   fail-closed, egress still via Tor). Without inspection, CONNECT
    //   bodies stay opaque and only the host/port gate applies.
    // - WebRTC UDP never reaches TCP proxies at all; full UDP capture
    //   needs Tor-only lockdown (packet layer), which is a separate toggle.
    public static class ContentFilter
    {
        public const string JsBlockCsp = "script-src 'none'; object-src 'none'; base-uri 'none'";

        static readonly HashSet<string> JsMime = new(StringComparer.OrdinalIgnoreCase)
        {
            "application/javascript",
            "application/x-javascript",
            "application/ecmascript",
            "application/x-ecmascript",
            "application/js",
            "text/javascript",
            "text/ecmascript",
            "text/jscript",
            "text/livescript",
            "text/js",
        };

        static readonly HashSet<string> HtmlMime = new(StringComparer.OrdinalIgnoreCase)
        {
            "text/html",
            "application/xhtml+xml",
        };

        // IANA STUN (3478/udp+tcp, 5349/tls) + the de-facto ranges browsers
        // actually dial over TCP when UDP is unavailable: Google 19302-19309,
        // plus common TURN/TLS alternates. Blocking these ports at the proxy
        // kills TURN-over-TCP without touching normal web ports.
        static readonly HashSet<int> WebRtcPorts = new()
        {
            3478, 3479, 3480, 5349, 5350, 5351,
            19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309,
            8801, 8802,
        };

        public static bool IsJsRequestPath(string? pathAndQuery)
        {
            try
            {
                if (string.IsNullOrEmpty(pathAndQuery)) return false;
                var path = pathAndQuery.Trim();
                if (path.Length == 0) return false;
                // Best-effort percent-decode so %2Ejs / %6As evasions still
                // match (failure = match against the raw form, never allow).
                try
                {
                    var decoded = Uri.UnescapeDataString(path);
                    if (!string.IsNullOrEmpty(decoded)) path = decoded;
                }
                catch { }
                // Trailing slashes ("…/app.js/") must not dodge the match.
                path = path.TrimEnd('/');
                if (path.Length == 0) return false;
                // Per-segment match (each segment cut at its own matrix/query
                // params) so "/app.js/extra" and "/x;id=1/app.mjs" still hit,
                // while a mid-path ";param" never truncates later segments.
                foreach (var seg in path.Split('/'))
                {
                    if (string.IsNullOrEmpty(seg)) continue;
                    var s = seg;
                    var cut = s.IndexOfAny(new[] { ';', '?', '#' });
                    if (cut >= 0) s = s.Substring(0, cut);
                    s = s.Trim();
                    if (s.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
                        || s.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase)
                        || s.EndsWith(".cjs", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                return false;
            }
            catch { return false; }
        }

        static string BaseMime(string? contentType)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(contentType)) return "";
                var v = contentType.Trim();
                var semi = v.IndexOf(';');
                if (semi >= 0) v = v.Substring(0, semi);
                return v.Trim().ToLowerInvariant();
            }
            catch { return ""; }
        }

        public static bool IsJsContentType(string? contentType) =>
            JsMime.Contains(BaseMime(contentType));

        public static bool IsHtmlContentType(string? contentType) =>
            HtmlMime.Contains(BaseMime(contentType));

        public static bool IsSdpContentType(string? contentType) =>
            string.Equals(BaseMime(contentType), "application/sdp", StringComparison.Ordinal);

        public static bool IsWebRtcPort(int port) => WebRtcPorts.Contains(port);

        public static bool IsWebRtcHost(string? host)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(host)) return false;
                var h = host.Trim().Trim('.').ToLowerInvariant();
                if (h.StartsWith("stun.", StringComparison.Ordinal)
                    || h.StartsWith("turn.", StringComparison.Ordinal)
                    || h.StartsWith("stuns.", StringComparison.Ordinal)
                    || h.StartsWith("turns.", StringComparison.Ordinal))
                    return true;
                if (h.Contains(".stun.", StringComparison.Ordinal)
                    || h.Contains(".turn.", StringComparison.Ordinal))
                    return true;
                return false;
            }
            catch { return false; }
        }

        public static bool IsWebRtcTarget(string? host, int port)
        {
            try
            {
                if (port > 0 && IsWebRtcPort(port)) return true;
                return IsWebRtcHost(host);
            }
            catch { return false; }
        }

        // Manual user blocklist, enforced at every proxy layer (CONNECT +
        // plain-HTTP + inspected HTTPS + SOCKS + Tor-DNS). Exact host or any
        // subdomain matches ("example.com" covers "a.example.com", never the
        // reverse). Port/bracket/case-insensitive. Null/empty list = allow.
        public static bool IsBlockedDomain(string? host, System.Collections.Generic.IEnumerable<string>? blocklist)
        {
            try
            {
                if (blocklist == null) return false;
                var h = NormalizeHost(host);
                if (h.Length == 0) return false;
                foreach (var raw in blocklist)
                {
                    if (string.IsNullOrWhiteSpace(raw)) continue;
                    var d = NormalizeHost(raw);
                    if (d.Length == 0) continue;
                    if (h.Equals(d, StringComparison.Ordinal) || h.EndsWith("." + d, StringComparison.Ordinal))
                        return true;
                }
                return false;
            }
            catch { return false; }
        }

        // Lowercase ASCII (punycode) hostname without port/brackets/trailing
        // dot. IDN-safe: both the query host and the blocklist entry go
        // through IdnMapping, so "münchen.de" and "xn--mnchen-3ya.de" compare
        // equal and neither form can dodge the blocklist. Never throws.
        public static string NormalizeHost(string? host)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(host)) return "";
                var h = host.Trim();
                if (h.StartsWith("[", StringComparison.Ordinal))
                {
                    var close = h.IndexOf(']');
                    if (close > 0) h = h.Substring(1, close - 1);
                    else h = h.Trim('[', ']');
                    return ToAscii(h.Trim());
                }
                // Strip a single :port suffix (one colon only — anything else
                // is garbage or a bare IPv6 literal, returned as-is lowercased).
                var first = h.IndexOf(':');
                var last = h.LastIndexOf(':');
                if (first > 0 && first == last) h = h.Substring(0, first);
                return ToAscii(h.Trim().Trim('.'));
            }
            catch { return ""; }
        }

        static string ToAscii(string h)
        {
            try
            {
                if (string.IsNullOrEmpty(h)) return "";
                h = h.ToLowerInvariant();
                // IP literals / single labels pass through; only dotted names
                // with non-ASCII need punycode. GetAscii throws on invalid —
                // fall back to the lowercased form (fail-closed: match raw).
                var needIdn = false;
                foreach (var c in h)
                    if (c > 127) { needIdn = true; break; }
                if (!needIdn) return h;
                try { return new System.Globalization.IdnMapping().GetAscii(h).ToLowerInvariant(); }
                catch { return h; }
            }
            catch { return ""; }
        }

        public static string? GetHeaderValue(string[] lines, string name)
        {
            try
            {
                if (lines == null || lines.Length == 0) return null;
                var end = Array.IndexOf(lines, "");
                if (end < 0) end = lines.Length;
                for (var i = 1; i < end; i++)
                {
                    var line = lines[i];
                    var colon = line.IndexOf(':');
                    if (colon <= 0) continue;
                    if (line.Substring(0, colon).Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
                        return line.Substring(colon + 1).Trim();
                }
                return null;
            }
            catch { return null; }
        }

        // Insert (or leave) a restrictive CSP on an HTTP response header
        // block. Multiple CSP headers intersect (both must pass), so adding
        // ours alongside an existing permissive one still blocks scripts.
        // Returns true when a header was inserted.
        public static bool TryInjectJsBlockCsp(ref string[] lines)
        {
            try
            {
                if (lines == null || lines.Length == 0) return false;
                var existing = GetHeaderValue(lines, "Content-Security-Policy");
                if (!string.IsNullOrEmpty(existing)
                    && existing.IndexOf("script-src", StringComparison.OrdinalIgnoreCase) >= 0
                    && existing.IndexOf("'none'", StringComparison.OrdinalIgnoreCase) >= 0)
                    return false; // already restrictive enough
                var end = Array.IndexOf(lines, "");
                if (end < 0) end = lines.Length;
                var grown = new string[lines.Length + 1];
                Array.Copy(lines, 0, grown, 0, end);
                grown[end] = "Content-Security-Policy: " + JsBlockCsp;
                Array.Copy(lines, end, grown, end + 1, lines.Length - end);
                lines = grown;
                return true;
            }
            catch { return false; }
        }

        // Drop all headers with one of the given names (case-insensitive).
        // Returns the number removed. Used for Cookie/Set-Cookie stripping
        // and for proxy hop-by-hop headers that must never reach origins.
        // RFC 7230 obs-fold continuations (lines starting with SP/HT that
        // belong to the previous header) are dropped together with their
        // parent — otherwise a folded "Cookie:" would leave its value lines
        // behind as orphan headers.
        public static int RemoveHeadersByName(ref string[] lines, params string[] names)
        {
            try
            {
                if (lines == null || lines.Length < 2 || names == null || names.Length == 0) return 0;
                var end = Array.IndexOf(lines, "");
                if (end < 0) end = lines.Length;
                var keep = new List<string>(end + 1) { lines[0] };
                var removed = 0;
                var droppingFold = false;
                for (var i = 1; i < end; i++)
                {
                    var line = lines[i];
                    if (droppingFold && line.Length > 0 && (line[0] == ' ' || line[0] == '\t'))
                    {
                        removed++;
                        continue;
                    }
                    droppingFold = false;
                    var colon = line.IndexOf(':');
                    var drop = false;
                    if (colon > 0)
                    {
                        var name = line.Substring(0, colon).Trim();
                        foreach (var n in names)
                        {
                            if (name.Equals(n, StringComparison.OrdinalIgnoreCase)) { drop = true; break; }
                        }
                    }
                    if (drop) { removed++; droppingFold = true; }
                    else keep.Add(line);
                }
                for (var i = end; i < lines.Length; i++) keep.Add(lines[i]);
                if (removed > 0) lines = keep.ToArray();
                return removed;
            }
            catch { return 0; }
        }

        // BlockCookies request side: never send stored cookies upstream.
        public static bool RemoveRequestCookies(ref string[] lines) =>
            RemoveHeadersByName(ref lines, "Cookie", "Cookie2") > 0;

        // BlockCookies response side: never let origins set cookies.
        public static bool RemoveResponseCookies(ref string[] lines) =>
            RemoveHeadersByName(ref lines, "Set-Cookie", "Set-Cookie2") > 0;

        // Proxy hop headers must not leak to origins (or back).
        public static void RemoveProxyHopHeaders(ref string[] lines) =>
            RemoveHeadersByName(ref lines, "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate");

        public static bool HasConnectionClose(string[] lines)
        {
            try
            {
                var v = GetHeaderValue(lines, "Connection");
                return v != null && v.IndexOf("close", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            catch { return false; }
        }

        public static bool IsUpgradeToWebSocket(string[] lines)
        {
            try
            {
                var up = GetHeaderValue(lines, "Upgrade");
                return up != null && up.IndexOf("websocket", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            catch { return false; }
        }

        public static int TryGetStatusCode(string[] lines)
        {
            try
            {
                if (lines == null || lines.Length == 0) return -1;
                var sp = (lines[0] ?? "").Split(' ');
                if (sp.Length < 2 || !sp[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)) return -1;
                return int.TryParse(sp[1], out var code) ? code : -1;
            }
            catch { return -1; }
        }

        public static bool IsNoBodyResponse(int statusCode, string method)
        {
            try
            {
                if (statusCode is >= 100 and <= 199) return true;
                if (statusCode == 204 || statusCode == 304) return true;
                return string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        // Absolute-form inside an inspected channel (proxy-in-proxy) ->
        // origin-form for the origin server.
        public static void NormalizeRequestTarget(ref string[] lines, string fallbackHost)
        {
            try
            {
                if (lines == null || lines.Length == 0) return;
                var parts = (lines[0] ?? "").Split(' ');
                if (parts.Length < 3) return;
                var target = parts[1];
                if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                    || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    var uri = new Uri(target);
                    lines[0] = parts[0] + " " + uri.PathAndQuery + " " + parts[2];
                }
            }
            catch { }
        }

        public static byte[] BuildBlockedResponse(string reason)
        {
            try
            {
                var body = "Blocked by PTor content policy: " + (reason ?? "blocked") + "\n";
                var bodyBytes = Encoding.ASCII.GetBytes(body);
                var head = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: "
                    + bodyBytes.Length + "\r\nConnection: close\r\n\r\n";
                var headBytes = Encoding.ASCII.GetBytes(head);
                var out_ = new byte[headBytes.Length + bodyBytes.Length];
                Buffer.BlockCopy(headBytes, 0, out_, 0, headBytes.Length);
                Buffer.BlockCopy(bodyBytes, 0, out_, headBytes.Length, bodyBytes.Length);
                return out_;
            }
            catch
            {
                return Encoding.ASCII.GetBytes("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
            }
        }
    }
}
