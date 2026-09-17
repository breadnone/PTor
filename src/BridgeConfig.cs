using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PTor
{

    public enum BridgeMode
    {
        Direct = 0,
        Obfs4Default = 1,
        SnowflakeDefault = 2,
        Custom = 3,
        Auto = 4,
    }

    // Exit geography options. Pure + testable.
    public static class TorPathOptions
    {
        static readonly Regex CountryRx = new(
            @"^[A-Za-z]{2}$",
            RegexOptions.Compiled, TimeSpan.FromSeconds(2));

        public static readonly Dictionary<string, string[]> ExitRegions = new(StringComparer.OrdinalIgnoreCase)
        {
            ["North America"] = new[] { "US", "CA", "MX" },
            ["South America"] = new[] { "BR", "AR", "CL", "CO", "PE" },
            ["Western Europe"] = new[] { "DE", "FR", "NL", "GB", "SE", "CH", "AT", "BE", "IE", "FI", "NO", "DK", "ES", "IT", "PT", "GR" },
            ["Central & Eastern Europe"] = new[] { "PL", "CZ", "SK", "HU", "RO", "BG", "UA", "RS", "HR", "RU", "BY", "MD" },
            ["East Asia"] = new[] { "JP", "KR", "TW", "HK", "SG" },
            ["South & Southeast Asia"] = new[] { "IN", "ID", "MY", "TH", "PH", "VN", "SG", "LK", "BD", "NP" },
            ["Oceania & Pacific"] = new[] { "AU", "NZ" },
            ["Middle East"] = new[] { "IL", "AE", "TR", "SA", "QA", "KW", "BH", "OM", "JO", "LB", "IR" },
            ["Africa"] = new[] { "ZA", "NG", "KE", "EG", "GH", "MA" },
            ["Central Asia"] = new[] { "KZ", "UZ", "KG", "TJ", "TM", "AZ", "GE", "AM" },
        };

        // Custom country codes win when any valid ones exist; else the region
        // map; else empty (any country). Never throws.
        public static List<string> ResolveExitCountries(string? region, string? custom)
        {
            try
            {
                var fromCustom = new List<string>();
                foreach (var part in (custom ?? "").Split(new[] { ',', ';', ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var c = part.Trim().ToUpperInvariant();
                    bool ok;
                    try { ok = CountryRx.IsMatch(c); }
                    catch (RegexMatchTimeoutException) { ok = false; }
                    if (ok && !fromCustom.Contains(c)) fromCustom.Add(c);
                }
                if (fromCustom.Count > 0) return fromCustom;
                if (!string.IsNullOrWhiteSpace(region) && ExitRegions.TryGetValue(region.Trim(), out var codes))
                    return new List<string>(codes);
                return new List<string>();
            }
            catch { return new List<string>(); }
        }
    }

    public record BridgeConfig(BridgeMode Mode, List<string> CustomLines)
    {
        public static BridgeConfig DirectOnly() => new(BridgeMode.Direct, new List<string>());
    }

    public record PtDefaults(
        Dictionary<string, string> PluginCommands,
        Dictionary<string, List<string>> Bridges);

    public record ResolvedBridges(
        bool UseBridges,
        List<string> PluginLines,
        List<string> BridgeLines,
        List<string> Errors,
        string Label);

    // Pure bridge logic (only LoadDefaults touches disk): parse defaults, validate lines, resolve torrc bundle.
    public static class BridgeConfigEngine
    {
        public const int MaxBridgeLines = 20;
        public const int MaxLineLength = 2000;

        static readonly Regex TransportLineRx = new(
            @"^(obfs4|snowflake|conjure|webtunnel|meek_lite|obfs3|scramblesuit)\s+\S+.*$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(2));

        static readonly Regex VanillaV4Rx = new(
            @"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}\s+[0-9A-Fa-f]{40}$",
            RegexOptions.Compiled, TimeSpan.FromSeconds(2));

        static readonly Regex VanillaV6Rx = new(
            @"^\[[0-9A-Fa-f:]+\]:\d{1,5}\s+[0-9A-Fa-f]{40}$",
            RegexOptions.Compiled, TimeSpan.FromSeconds(2));

        static readonly Dictionary<string, string> TransportToPlugin = new(StringComparer.OrdinalIgnoreCase)
        {
            ["obfs4"] = "lyrebird",
            ["obfs3"] = "lyrebird",
            ["obfs2"] = "lyrebird",
            ["scramblesuit"] = "lyrebird",
            ["meek_lite"] = "lyrebird",
            ["webtunnel"] = "lyrebird",
            ["snowflake"] = "snowflake",
            ["conjure"] = "conjure",
        };

        public static PtDefaults? LoadDefaults(string ptConfigPath)
        {
            try
            {
                // Capped (~3KB in practice): a bloated file is not ours.
                var text = SafeFiles.ReadAllTextCapped(ptConfigPath, 1024 * 1024);
                if (text == null) return null;
                using var doc = JsonDocument.Parse(text);
                var root = doc.RootElement;
                var plugins = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                var bridges = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                if (root.TryGetProperty("pluggableTransports", out var pt) && pt.ValueKind == JsonValueKind.Object)
                {
                    foreach (var kv in pt.EnumerateObject())
                        if (kv.Value.ValueKind == JsonValueKind.String)
                            plugins[kv.Name] = kv.Value.GetString() ?? "";
                }
                if (root.TryGetProperty("bridges", out var br) && br.ValueKind == JsonValueKind.Object)
                {
                    foreach (var kv in br.EnumerateObject())
                    {
                        var list = new List<string>();
                        if (kv.Value.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var el in kv.Value.EnumerateArray())
                                if (el.ValueKind == JsonValueKind.String)
                                {
                                    var line = (el.GetString() ?? "").Trim();
                                    if (line.Length > 0) list.Add(line);
                                }
                        }
                        bridges[kv.Name] = list;
                    }
                }
                return new PtDefaults(plugins, bridges);
            }
            catch { return null; }
        }

        public static (List<string> ok, List<string> errors) ValidateCustomLines(IEnumerable<string> lines)
        {
            var ok = new List<string>();
            var errors = new List<string>();
            var n = 0;
            foreach (var raw in lines ?? Enumerable.Empty<string>())
            {
                // torrc injection guard: raw (untrimmed) must not contain any
                // line break — Trim() only strips the edges, an embedded
                // "\r\nControlPort ..." would otherwise survive into torrc.
                if (!string.IsNullOrEmpty(raw) && (raw.IndexOfAny(new[] { '\r', '\n' }) >= 0))
                {
                    errors.Add("Rejected bridge line (line breaks are not allowed).");
                    continue;
                }
                var line = (raw ?? "").Trim();
                if (line.Length == 0) continue;
                n++;
                if (n > MaxBridgeLines) { errors.Add($"Too many bridge lines (max {MaxBridgeLines})."); break; }
                if (line.Length > MaxLineLength) { errors.Add("Bridge line too long (max 2000 chars)."); continue; }
                bool valid;
                try
                {
                    valid = TransportLineRx.IsMatch(line) || VanillaV4Rx.IsMatch(line) || VanillaV6Rx.IsMatch(line);
                }
                catch (RegexMatchTimeoutException) { valid = false; }
                if (!valid)
                {
                    errors.Add("Rejected bridge line (must start with a known transport like obfs4/snowflake/conjure, or be IP:port + 40-hex fingerprint): " +
                        (line.Length <= 80 ? line : line.Substring(0, 80) + "…"));
                    continue;
                }
                ok.Add(line);
            }
            return (ok, errors);
        }

        public static string TransportOfLine(string line)
        {
            var sp = line.IndexOfAny(new[] { ' ', '\t' });
            return sp > 0 ? line.Substring(0, sp) : "";
        }

        // Resolve ${pt_path} templates against the real directory, quoting spaced paths.
        public static string ResolvePluginCommand(string template, string ptDir)
        {
            try
            {
                var dir = (ptDir ?? "").Replace("\\", "/").TrimEnd('/') + "/";
                var idx = template.IndexOf("exec ", StringComparison.OrdinalIgnoreCase);
                if (idx < 0) return template.Trim();
                var head = template.Substring(0, idx + "exec ".Length);
                var rest = template.Substring(idx + "exec ".Length).Trim();
                if (rest.Length == 0) return template.Trim();
                var end = rest.IndexOfAny(new[] { ' ', '\t' });
                var binary = end < 0 ? rest : rest.Substring(0, end);
                var args = end < 0 ? "" : rest.Substring(end);
                binary = binary.Replace("${pt_path}", dir).Replace("$pt_path", dir);
                if (binary.IndexOfAny(new[] { ' ', '\t', '"' }) >= 0 && !binary.StartsWith("\""))
                    binary = "\"" + binary.Trim('"') + "\"";
                return (head + binary + args).Trim();
            }
            catch { return (template ?? "").Trim(); }
        }

        public static ResolvedBridges Resolve(BridgeConfig cfg, string ptDir, PtDefaults? defaults)
        {
            cfg ??= BridgeConfig.DirectOnly();
            if (cfg.Mode == BridgeMode.Direct)
                return new ResolvedBridges(false, new List<string>(), new List<string>(), new List<string>(), "direct");

            List<string> wanted;
            string label;
            if (cfg.Mode == BridgeMode.Obfs4Default) { wanted = new List<string> { "obfs4" }; label = "obfs4 bridges"; }
            else if (cfg.Mode == BridgeMode.SnowflakeDefault) { wanted = new List<string> { "snowflake" }; label = "Snowflake"; }
            else
            {
                var (ok, errors) = ValidateCustomLines(cfg.CustomLines);
                if (ok.Count == 0)
                {
                    if (errors.Count == 0) errors.Add("Custom bridge mode selected but no bridge lines pasted.");
                    return new ResolvedBridges(false, new List<string>(), new List<string>(), errors, "custom (invalid)");
                }
                var need = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var line in ok)
                {
                    var t = TransportOfLine(line);
                    if (!string.IsNullOrEmpty(t) && TransportToPlugin.ContainsKey(t)) need.Add(t);
                }
                return Finish(ok, need, "custom", ptDir, defaults);
            }

            // Default modes draw from the bundled pt_config.json.
            if (defaults == null)
                return new ResolvedBridges(false, new List<string>(), new List<string>(),
                    new List<string> { "Bundled bridge defaults are missing or unreadable — paste custom bridge lines instead." },
                    label + " (unavailable)");
            var lines = new List<string>();
            foreach (var t in wanted)
                if (defaults.Bridges.TryGetValue(t, out var bl))
                    lines.AddRange(bl);
            if (lines.Count == 0)
                return new ResolvedBridges(false, new List<string>(), new List<string>(),
                    new List<string> { $"No bundled {label} lines found — paste custom bridge lines instead." },
                    label + " (unavailable)");
            var needDefaults = new HashSet<string>(wanted, StringComparer.OrdinalIgnoreCase);
            return Finish(lines, needDefaults, label, ptDir, defaults);
        }

        // The plugin binary tor will spawn (lyrebird.exe, snowflake-client.exe,
        // ...), resolved from the torrc template. Null when unparseable — the
        // caller then skips the on-disk check (tor's own launch error is the
        // backstop, never a bypass).
        internal static string? PluginBinaryPath(string template, string ptDir)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(template)) return null;
                var idx = template.IndexOf("exec ", StringComparison.OrdinalIgnoreCase);
                if (idx < 0) return null;
                var rest = template.Substring(idx + "exec ".Length).Trim().Trim('"').Trim();
                if (rest.Length == 0) return null;
                var end = rest.IndexOfAny(new[] { ' ', '\t', '"' });
                var binary = (end < 0 ? rest : rest.Substring(0, end)).Trim();
                if (binary.Length == 0) return null;
                // Templates join ${pt_path} directly to the file name (no
                // separator), so the dir needs its trailing slash — same as
                // ResolvePluginCommand, but kept native for File.Exists.
                var dir = (ptDir ?? "").Trim();
                if (dir.Length > 0 && !dir.EndsWith("/") && !dir.EndsWith("\\"))
                    dir += System.IO.Path.DirectorySeparatorChar;
                binary = binary.Replace("${pt_path}", dir).Replace("$pt_path", dir);
                binary = binary.Trim('"').Trim();
                if (binary.IndexOf("${", StringComparison.Ordinal) >= 0) return null;
                return binary;
            }
            catch { return null; }
        }

        static ResolvedBridges Finish(List<string> lines, HashSet<string> needTransports, string label,
            string ptDir, PtDefaults? defaults)
        {
            var errors = new List<string>();
            var plugins = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in needTransports)
            {
                if (!TransportToPlugin.TryGetValue(t, out var pluginKey))
                    continue; // vanilla lines need no plugin
                if (!seen.Add(pluginKey)) continue;
                if (defaults == null || !defaults.PluginCommands.TryGetValue(pluginKey, out var template) ||
                    string.IsNullOrWhiteSpace(template))
                {
                    errors.Add($"No client plugin configured for transport '{t}' — cannot use those bridge lines.");
                    continue;
                }
                // Fail fast on a broken helper mapping (seconds, with the
                // exact cause) instead of launching tor into a hopeless
                // multi-minute bootstrap stall. Two real cases: the binary
                // isn't bundled at all (Snowflake today), or the template
                // points at the WRONG helper (shipped pt_config once mapped
                // snowflake → lyrebird.exe, which doesn't implement it —
                // tor then stalls at 10% with zero useful log).
                var bin = PluginBinaryPath(template, ptDir);
                string binFile = "";
                try { binFile = string.IsNullOrEmpty(bin) ? "" : (Path.GetFileName(bin) ?? ""); } catch { }
                if (!string.IsNullOrEmpty(binFile) &&
                    binFile.IndexOf(pluginKey, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    errors.Add($"Transport plugin for '{t}' is misconfigured (points at {binFile}, which does not implement it) — " +
                        "update PTor to repair tools\\tor\\pluggable_transports\\pt_config.json, or use obfs4 / paste custom obfs4 lines.");
                    continue;
                }
                if (!string.IsNullOrEmpty(bin) && !File.Exists(bin))
                {
                    var file = bin;
                    try { file = Path.GetFileName(bin); } catch { }
                    errors.Add($"Transport '{t}' needs {file} in tools\\tor\\pluggable_transports, but it is not there — " +
                        (string.Equals(file, "snowflake-client.exe", StringComparison.OrdinalIgnoreCase)
                            ? "Snowflake is unavailable in this build (paste custom obfs4 lines or use Automatic/obfs4 instead)."
                            : "reinstall PTor's tools folder or paste custom bridge lines for a bundled transport."));
                    continue;
                }
                plugins.Add(ResolvePluginCommand(template, ptDir));
            }
            if (errors.Count > 0)
                return new ResolvedBridges(false, new List<string>(), new List<string>(), errors, label + " (invalid)");
            return new ResolvedBridges(true, plugins, lines, errors, label);
        }
    }
}
