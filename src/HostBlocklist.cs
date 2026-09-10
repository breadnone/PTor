using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace PTor
{

    // Filter-list download + parse + in-memory store.
    //
    // HARD RULE: PTor NEVER touches the OS hosts file (no reads-for-apply,
    // no writes, no elevated helpers). Blocking is enforced 100% inside
    // PTor's own data path (DnsForwarder + SOCKS/HTTP relays + own HTTP
    // client) via AdBlockStore. The only hosts-file interaction left is a
    // READ-ONLY check that warns about a stale section left by older PTor
    // versions (which did write it) — removal, if the user wants it, is a
    // manual admin edit, never done by this app.
    public static class HostBlocklist
    {
        // Markers of the section pre-in-app versions used to manage.
        // Kept for READ-ONLY legacy detection only.
        public const string BeginMarker = "# >>> PTor-Blocklist BEGIN";
        public const string EndMarker = "# <<< PTor-Blocklist END";

        // Hard cap: a hostile 100 MB list of unique short names must not eat
        // gigabytes of RAM. Overflow counts as skipped (visible in status).
        public const int MaxHosts = 1_000_000;

        // Untrusted file input + nested quantifiers: 2s regex timeout, lines over budget count as skipped.
        static readonly Regex HostRx = new(
            @"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(2));

        public record ParseResult(
            HashSet<string> Hosts, int FilesRead, List<string> MissingFiles,
            int SkippedUnsupported, int SkippedWildcard, int AllowedExceptions,
            HashSet<string> AllowedHosts);

        public static ParseResult ParseFiles(IEnumerable<string> paths)
        {
            var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var missing = new List<string>();
            int files = 0, skipped = 0, wildcards = 0;

            foreach (var path in paths ?? Enumerable.Empty<string>())
            {
                // Streamed line-by-line: an 80k-domain list never sits in
                // memory twice (no string[] of the whole file). Only the
                // dedup HashSet below is inherently resident.
                IEnumerable<string> lines;
                try { lines = File.ReadLines(path); files++; }
                catch { missing.Add(path); continue; }

                // Per-file local sets: a file that fails mid-stream contributes
                // nothing (no half-applied truncations), and is marked.
                var fileHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var fileAllowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                int fileSkipped = 0, fileWildcards = 0;

                // Cumulative timeout budget: a fully-hostile file must still terminate fast.
                int timeouts = 0;
                try
                {
                    foreach (var raw in lines)
                    {
                        var line = raw.Trim();
                    if (line.Length == 0 || line[0] == '#' || line[0] == '!') continue;
                    var hash = line.IndexOf('#');
                    if (hash >= 0) line = line.TrimEnd().Substring(0, hash).Trim();
                    if (line.Length == 0) continue;

                    // @@ exceptions allow-list: parsed like blocks, subtracted at the end.
                    bool isAllow = false;
                    if (line.StartsWith("@@"))
                    {
                        isAllow = true;
                        line = line.Substring(2).Trim();
                        if (line.Length == 0) { fileSkipped++; continue; }
                    }
                    if (line.StartsWith("||"))
                    {
                        var body = line.Substring(2);
                        var cut = body.IndexOfAny(new[] { '^', '|', '/' });
                        line = cut >= 0 ? body.Substring(0, cut) : body;
                    }
                    else if (line.StartsWith("|"))
                    {
                        line = ExtractAnchoredHost(line);
                        if (line.Length == 0) { fileSkipped++; continue; }
                    }
                    // ABP options ($third-party, $image, ...) are not DNS-significant.
                    var dollar = line.IndexOf('$');
                    if (dollar >= 0) line = line.Substring(0, dollar).Trim();
                    if (line.Length == 0) { fileSkipped++; continue; }

                    var tokens = line.Split(Array.Empty<char>(), StringSplitOptions.RemoveEmptyEntries);
                    if (tokens.Length == 0) continue;

                    if (tokens.Length > 1 && !IsIpLiteral(tokens[0])) { fileSkipped++; continue; }
                    var start = tokens.Length > 1 ? 1 : 0;

                    for (var i = start; i < tokens.Length; i++)
                    {
                        var t = tokens[i].Trim().TrimEnd('.').ToLowerInvariant();
                        if (t.StartsWith("*.")) { fileWildcards++; continue; }
                        if (ProtectedHosts.Contains(t)) { fileSkipped++; continue; }
                        bool ok;
                        try { ok = !IsIpLiteral(t) && HostRx.IsMatch(t); }
                        catch (RegexMatchTimeoutException)
                        {
                            ok = false;
                            if (++timeouts > 25)
                            {
                                fileSkipped++;
                                break;
                            }
                        }
                        if (!ok) { fileSkipped++; continue; }
                        if (!isAllow && hosts.Count + fileHosts.Count >= MaxHosts) { fileSkipped++; continue; }
                        (isAllow ? fileAllowed : fileHosts).Add(t);
                    }
                    if (timeouts > 25) break; // abort budget spent: stop this file
                }
                }
                catch
                {
                    // File vanished/failed mid-stream: discard its partial
                    // contribution and mark it.
                    missing.Add(path + " (unreadable)");
                    continue;
                }
                foreach (var h in fileHosts) hosts.Add(h);
                foreach (var a in fileAllowed) allowed.Add(a);
                skipped += fileSkipped;
                wildcards += fileWildcards;
            }
            hosts.ExceptWith(allowed);
            return new ParseResult(hosts, files, missing, skipped, wildcards, allowed.Count, allowed);
        }

        static string ExtractAnchoredHost(string line)
        {
            try
            {
                var s = line.TrimStart('|').Trim();
                if (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) s = s.Substring(7);
                else if (s.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) s = s.Substring(8);
                var cut = s.IndexOfAny(new[] { '/', '^', '|', '?', '*', '$' });
                s = (cut >= 0 ? s.Substring(0, cut) : s).Trim().TrimEnd('.');
                var colon = s.LastIndexOf(':');
                if (colon > 0 && int.TryParse(s.Substring(colon + 1), out _))
                    s = s.Substring(0, colon);
                return s;
            }
            catch { return ""; }
        }

        static bool IsIpLiteral(string t) => System.Net.IPAddress.TryParse(t, out _);

        // In-memory active count. The OS hosts file is never consulted for
        // enforcement; see HasLegacyHostsSection for the stale-section note.
        public static int GetActiveCount()
        {
            try { return AdBlockStore.Instance.Count; }
            catch { return 0; }
        }

        // READ-ONLY: does a section written by an older PTor version still
        // linger in the OS hosts file? Never writes; informs the user only.
        public static bool HasLegacyHostsSection()
        {
            try
            {
                var path = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "drivers", "etc", "hosts");
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                // Bounded scan: section markers sit near the top or the very
                // end; cap the read so a giant file can't stall the UI.
                const int maxChars = 4 * 1024 * 1024;
                var buf = new char[8192];
                var total = 0;
                var text = new System.Text.StringBuilder(65536);
                int read;
                while (total < maxChars && (read = sr.Read(buf, 0, buf.Length)) > 0)
                {
                    text.Append(buf, 0, read);
                    total += read;
                }
                var s = text.ToString();
                return s.Contains(BeginMarker, StringComparison.Ordinal) &&
                       s.Contains(EndMarker, StringComparison.Ordinal);
            }
            catch { return false; }
        }

        public static readonly string[] DefaultUrls =
        {
            "https://easylist.to/easylist/easyprivacy.txt",
            "https://easylist.to/easylist/easylist.txt",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        };

        public const int CurrentDefaultsVersion = 2;

        // Hostnames that must never be blocked: stock hosts files map these
        // to loopback (blocking them in-app would break loopback-by-name
        // resolution for routed apps).
        static readonly HashSet<string> ProtectedHosts = new(StringComparer.OrdinalIgnoreCase)
        {
            "localhost", "localhost.localdomain", "local", "broadcasthost",
            "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
            "ip6-allnodes", "ip6-allrouters",
        };

        // One-time-per-version merge of new defaults: existing installs pick
        // up added lists; users who deliberately removed one keep it removed
        // (their stamp is already current, so nothing is re-added).
        public static (List<string> merged, int version, List<string> added) EnsureDefaults(
            List<string>? current, int storedVersion)
        {
            var list = (current ?? new List<string>())
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Select(u => u.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var added = new List<string>();
            if (storedVersion < CurrentDefaultsVersion)
            {
                foreach (var d in DefaultUrls)
                    if (!list.Contains(d, StringComparer.OrdinalIgnoreCase))
                    {
                        list.Add(d);
                        added.Add(d);
                    }
                return (list, CurrentDefaultsVersion, added);
            }
            return (list, storedVersion, added);
        }

        public static string DefaultCacheDir()
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PTor", "blocklists");
            Directory.CreateDirectory(dir);
            return dir;
        }

        public static string CachePathFor(string cacheDir, string url)
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            var hash = Convert.ToHexString(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(url ?? ""))).ToLowerInvariant();
            return Path.Combine(cacheDir, "list-" + hash + ".txt");
        }

        // Downloads each URL to its cache file. Verified before promotion:
        // byte count must match Content-Length, and the payload must parse
        // to something sane — otherwise the previous cache stands (an empty
        // reply, a truncated stream, or a captive-portal HTML page must never
        // replace a good cache, let alone wipe blocking). Never throws.
        public static async Task<(List<string> cachedFiles, List<string> notes)> RefreshCacheAsync(
            IEnumerable<string> urls, string cacheDir)
        {
            var cached = new List<string>();
            var notes = new List<string>();
            Directory.CreateDirectory(cacheDir);
            // Direct fetch, no proxy: public lists, and this must also work
            // when the system proxy points at a not-yet-running PTor.
            using var http = new System.Net.Http.HttpClient(
                new System.Net.Http.SocketsHttpHandler { UseProxy = false })
            { Timeout = TimeSpan.FromSeconds(60) };
            foreach (var raw in urls ?? Enumerable.Empty<string>())
            {
                var url = (raw ?? "").Trim();
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                    (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
                {
                    notes.Add("Skipped non-HTTP(S) list URL: " + url);
                    continue;
                }
                var dest = CachePathFor(cacheDir, url);
                var tmp = dest + "." + Guid.NewGuid().ToString("N") + ".part";
                try
                {
                    using var resp = await http.GetAsync(uri, System.Net.Http.HttpCompletionOption.ResponseHeadersRead);
                    resp.EnsureSuccessStatusCode();
                    var len = resp.Content.Headers.ContentLength;
                    if (len.HasValue && len.Value > 100L * 1024 * 1024)
                        throw new InvalidOperationException($"list too large ({len.Value} bytes), refusing");
                    await using var src = await resp.Content.ReadAsStreamAsync();
                    long written = 0;
                    await using (var dst = File.Create(tmp))
                    {
                        var buf = new byte[81920];
                        int read;
                        while ((read = await src.ReadAsync(buf)) > 0)
                        {
                            await dst.WriteAsync(buf.AsMemory(0, read));
                            written += read;
                            if (written > 100L * 1024 * 1024)
                                throw new InvalidOperationException("list exceeded 100 MB mid-download, refusing");
                        }
                    }
                    if (len.HasValue && written != len.Value)
                        throw new IOException($"truncated download ({written} of {len.Value} bytes)");
                    VerifyPayload(tmp, written, url);
                    File.Move(tmp, dest, overwrite: true);
                    cached.Add(dest);
                }
                catch (Exception ex)
                {
                    try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
                    if (File.Exists(dest))
                    {
                        cached.Add(dest);
                        notes.Add($"Using cached copy for {url} (refresh failed: {ex.GetType().Name}).");
                    }
                    else
                    {
                        notes.Add($"Skipped {url} (download failed, no cache: {ex.GetType().Name}).");
                    }
                }
            }
            return (cached, notes);
        }

        // Empty payloads and non-trivial payloads with zero usable hosts are
        // corruption (captive portals, error pages, truncations) — never let
        // them evict a working cache.
        internal static void VerifyPayload(string tmpPath, long bytesRead, string url)
        {
            if (bytesRead <= 0)
                throw new IOException("empty download for " + url);
            ParseResult probe;
            try { probe = ParseFiles(new[] { tmpPath }); }
            catch (Exception ex)
            {
                throw new IOException("unparseable download for " + url + ": " + ex.Message);
            }
            if (bytesRead > 4096 && probe.Hosts.Count == 0 && probe.AllowedExceptions == 0)
                throw new IOException($"download for {url} parsed to zero usable hosts");
        }

        static readonly System.Threading.SemaphoreSlim UpdateGate = new(1, 1);

        // Full pipeline with mutual exclusion: download -> parse -> load
        // into the IN-MEMORY store. No elevation, no hosts-file writes.
        // Returns false (no throw) when another update is already running.
        public static async Task<(bool ok, string message)> UpdateFromUrlsAsync(
            IEnumerable<string> urls, string? cacheDir = null)
        {
            if (!await UpdateGate.WaitAsync(0)) return (false, "Blocklist update already in progress.");
            try
            {
                cacheDir ??= DefaultCacheDir();
                var urlList = urls?.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim()).ToList()
                    ?? new List<string>();
                if (urlList.Count == 0) return (false, "No blocklist URLs configured.");
                var (cached, notes) = await RefreshCacheAsync(urlList, cacheDir);
                if (cached.Count == 0)
                    return (false, "No blocklists available. " + string.Join(" ", notes));
                ParseResult parsed;
                try { parsed = ParseFiles(cached); }
                catch (Exception ex) { return (false, "Blocklist parse failed: " + ex.Message); }
                if (parsed.Hosts.Count == 0)
                    return (false, "No valid hosts parsed from the lists. " + string.Join(" ", notes));
                AdBlockStore.Instance.SetHosts(parsed.Hosts, parsed.FilesRead, parsed.AllowedHosts);
                var extra = notes.Count > 0 ? " " + string.Join(" ", notes) : "";
                var msg = $"Blocked {parsed.Hosts.Count:N0} host(s) in-app from {parsed.FilesRead} list(s). OS hosts file untouched." + extra;
                return (true, msg);
            }
            finally
            {
                try { UpdateGate.Release(); } catch { }
            }
        }

        // Boot path: parse whatever is already cached (no network) and load
        // it into the in-memory store. Never throws, never touches hosts.
        public static (int hosts, int files) LoadCachedIntoStore(IEnumerable<string> urls, string? cacheDir = null)
        {
            try
            {
                cacheDir ??= DefaultCacheDir();
                var cached = (urls ?? Enumerable.Empty<string>())
                    .Where(u => !string.IsNullOrWhiteSpace(u))
                    .Select(u => { try { return CachePathFor(cacheDir, u.Trim()); } catch { return ""; } })
                    .Where(File.Exists)
                    .ToList();
                if (cached.Count == 0) return (0, 0);
                var parsed = ParseFiles(cached);
                if (parsed.Hosts.Count == 0) return (0, cached.Count);
                AdBlockStore.Instance.SetHosts(parsed.Hosts, parsed.FilesRead, parsed.AllowedHosts);
                return (parsed.Hosts.Count, parsed.FilesRead);
            }
            catch { return (0, 0); }
        }

        // Clears the IN-MEMORY blocklist only. Cache files and list URLs are
        // kept; the OS hosts file is never touched.
        public static Task<(bool ok, string message)> ClearAsync()
        {
            AdBlockStore.Instance.Clear();
            return Task.FromResult((true, "In-app blocklist cleared (OS hosts file untouched)."));
        }
    }
}
