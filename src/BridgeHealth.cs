using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace PTor
{

    public record BridgeHealthEntry(string Line, int ConsecutiveFailures, DateTime LastTriedUtc, DateTime? DeadSinceUtc);

    // Ranks bridge candidates (untried/living first, dead last) with
    // outcomes persisted across restarts: steady state touches one bridge
    // per start. Keyed by transport+addr so cert rotation keeps history.
    // Start-path only (lifecycle gate held): no locks needed.
    public class BridgeHealthStore
    {
        public const int DeadThreshold = 2;

        readonly Dictionary<string, BridgeHealthEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
        readonly string? _filePath;

        public BridgeHealthStore(string? filePath = null)
        {
            _filePath = filePath;
            Load();
        }

        public static string DefaultPath()
        {
            try
            {
                var dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PTor");
                Directory.CreateDirectory(dir);
                return Path.Combine(dir, "bridge-health.json");
            }
            catch { return ""; }
        }

        public static string KeyOf(string line)
        {
            try
            {
                var parts = (line ?? "").Split(Array.Empty<char>(), StringSplitOptions.RemoveEmptyEntries);
                return parts.Length >= 2 ? parts[0] + " " + parts[1] : (line ?? "").Trim();
            }
            catch { return line ?? ""; }
        }

        // Log-safe: transport + host only, never certs/fingerprints.
        public static string ShortName(string line) => KeyOf(line);

        public List<string> OrderForAttempt(IEnumerable<string> lines)
        {
            var list = (lines ?? Enumerable.Empty<string>())
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .Select(l => l.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            return list
                .OrderBy(l => TierOf(l))
                .ThenBy(l => SecondaryOf(l))
                .ToList();
        }

        // Tiers: 0 untried, 1 last-known-good (freshest first), 2 single
        // failure, 3 benched. Secondary orders within tier (see code).
        int TierOf(string line)
        {
            if (!_entries.TryGetValue(KeyOf(line), out var e)) return 0;
            if (e.DeadSinceUtc != null) return 3;
            return e.ConsecutiveFailures == 0 ? 1 : 2;
        }

        long SecondaryOf(string line)
        {
            if (!_entries.TryGetValue(KeyOf(line), out var e)) return 0;
            var ticks = e.LastTriedUtc.Ticks;
            return TierOf(line) == 1 ? -ticks : ticks;
        }

        public void RecordResult(string line, bool ok)
        {
            try
            {
                var k = KeyOf(line);
                var now = DateTime.UtcNow;
                _entries.TryGetValue(k, out var prev);
                if (ok) { _entries[k] = new BridgeHealthEntry(line, 0, now, null); }
                else
                {
                    var fails = (prev?.ConsecutiveFailures ?? 0) + 1;
                    _entries[k] = new BridgeHealthEntry(line, fails, now,
                        fails >= DeadThreshold ? (prev?.DeadSinceUtc ?? now) : null);
                }
                if (_entries.Count > 200)
                {
                    foreach (var dead in _entries
                        .Where(kv => kv.Value.DeadSinceUtc != null)
                        .OrderBy(kv => kv.Value.LastTriedUtc)
                        .Take(_entries.Count - 200)
                        .Select(kv => kv.Key)
                        .ToList())
                        _entries.Remove(dead);
                }
                Save();
            }
            catch { }
        }

        public IReadOnlyDictionary<string, BridgeHealthEntry> Snapshot() => _entries;

        void Load()
        {
            try
            {
                if (string.IsNullOrEmpty(_filePath) || !File.Exists(_filePath)) return;
                var doc = JsonSerializer.Deserialize<Dictionary<string, BridgeHealthEntry>>(File.ReadAllText(_filePath));
                if (doc == null) return;
                foreach (var kv in doc.Take(200))
                    _entries[kv.Key] = kv.Value;
            }
            catch { }
        }

        void Save()
        {
            try
            {
                if (string.IsNullOrEmpty(_filePath)) return;
                string? dir = Path.GetDirectoryName(_filePath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                // Atomic: crash mid-write must not corrupt ranking history.
                var tmp = _filePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    File.WriteAllText(tmp, JsonSerializer.Serialize(_entries));
                    File.Move(tmp, _filePath, overwrite: true);
                }
                catch
                {
                    try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
                    throw;
                }
            }
            catch { }
        }
    }
}
