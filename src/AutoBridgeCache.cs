using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace PTor
{

    // Last-good AUTOMATIC bridge lines, persisted across runs.
    //
    // Why: the directory is rate-limited and sometimes blocked, and the
    // bundled file rots. Every successful live fetch (at start or via
    // Config → Fetch now) is saved here; the next start uses it when the
    // directory is momentarily unreachable — fully automatic, zero typing,
    // and fresher than the bundle. Order at start: fresh fetch → this
    // cache (when recent) → bundled file.
    //
    // Shape: { transport, lines[], fetchedUtc }. Reads are capped (a
    // planted file must not be slurped); lines are re-validated on load so
    // only usable entries ever come back. Never throws.
    public static class AutoBridgeCache
    {
        public sealed record CachedBridges(string Transport, List<string> Lines, DateTime FetchedUtc);

        // Cached lines older than this are ignored by the engine (directory
        // or bundled file take over); the dialog still shows their age.
        public static readonly TimeSpan MaxAge = TimeSpan.FromDays(7);

        internal const long MaxCacheBytes = 64 * 1024;

        internal static string DefaultPath()
        {
            try
            {
                var dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PTor");
                Directory.CreateDirectory(dir);
                return Path.Combine(dir, "autobridges.json");
            }
            catch { return ""; }
        }

        public static bool IsSupportedTransport(string? transport)
        {
            try
            {
                return string.Equals(transport, "obfs4", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(transport, "webtunnel", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(transport, "snowflake", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        public static void Save(string transport, List<string> lines)
        {
            try
            {
                transport = (transport ?? "").Trim().ToLowerInvariant();
                if (!IsSupportedTransport(transport)) return;
                var clean = new List<string>();
                try
                {
                    foreach (var raw in lines ?? new List<string>())
                    {
                        var t = (raw ?? "").Trim();
                        if (t.Length > 0) clean.Add(t);
                    }
                }
                catch { }
                if (clean.Count == 0) return;
                var path = DefaultPath();
                if (string.IsNullOrEmpty(path)) return;
                var payload = JsonSerializer.Serialize(new
                {
                    transport,
                    lines = clean,
                    fetchedUtc = DateTime.UtcNow.ToString("o")
                });
                SafeFiles.WriteAllTextAtomic(path, payload);
            }
            catch { }
        }

        // Returns the cached entry (any age — callers check IsFresh); null
        // when missing, unreadable, corrupt, or holding nothing usable.
        public static CachedBridges? Load()
        {
            try
            {
                var path = DefaultPath();
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
                var text = SafeFiles.ReadAllTextCapped(path, MaxCacheBytes);
                if (string.IsNullOrWhiteSpace(text)) return null;
                string transport = "";
                var rawLines = new List<string>();
                DateTime fetchedUtc = DateTime.MinValue;
                try
                {
                    using var doc = JsonDocument.Parse(text);
                    var root = doc.RootElement;
                    if (root.ValueKind != JsonValueKind.Object) return null;
                    if (root.TryGetProperty("transport", out var tp) && tp.ValueKind == JsonValueKind.String)
                        transport = (tp.GetString() ?? "").Trim().ToLowerInvariant();
                    if (root.TryGetProperty("lines", out var arr) && arr.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in arr.EnumerateArray())
                        {
                            try
                            {
                                if (el.ValueKind != JsonValueKind.String) continue;
                                var l = (el.GetString() ?? "").Trim();
                                if (l.Length > 0) rawLines.Add(l);
                            }
                            catch { }
                        }
                    }
                    if (root.TryGetProperty("fetchedUtc", out var fu) && fu.ValueKind == JsonValueKind.String)
                    {
                        try { fetchedUtc = DateTime.Parse(fu.GetString() ?? "", null,
                            System.Globalization.DateTimeStyles.RoundtripKind); }
                        catch { fetchedUtc = DateTime.MinValue; }
                    }
                }
                catch { return null; }
                if (!IsSupportedTransport(transport) || rawLines.Count == 0) return null;
                // Snowflake keeps dummy IPs by design; the rest drop doc-IP
                // placeholders — same rule as live fetches.
                var usable = BridgeFetcher.FilterUsable(rawLines, transport,
                    transport != "snowflake", out _, out _);
                if (usable.Count == 0) return null;
                return new CachedBridges(transport, usable, fetchedUtc);
            }
            catch { return null; }
        }

        public static bool IsFresh(CachedBridges? cached, DateTime now)
        {
            try
            {
                if (cached == null || cached.FetchedUtc == DateTime.MinValue) return false;
                var age = now - cached.FetchedUtc;
                return age >= TimeSpan.Zero && age <= MaxAge;
            }
            catch { return false; }
        }

        public static string DescribeAge(CachedBridges? cached, DateTime now)
        {
            try
            {
                if (cached == null) return "none cached";
                if (cached.FetchedUtc == DateTime.MinValue) return "cached (unknown age)";
                var age = now - cached.FetchedUtc;
                if (age < TimeSpan.Zero) return "cached (just now)";
                if (age.TotalHours < 1) return $"cached {(int)age.TotalMinutes}m ago";
                if (age.TotalDays < 1) return $"cached {(int)age.TotalHours}h ago";
                return $"cached {(int)age.TotalDays}d ago";
            }
            catch { return "cache unknown"; }
        }

        public static void Clear()
        {
            try
            {
                var path = DefaultPath();
                if (!string.IsNullOrEmpty(path) && File.Exists(path))
                    try { File.Delete(path); } catch { }
            }
            catch { }
        }
    }
}
