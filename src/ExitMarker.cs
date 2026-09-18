using System;
using System.Collections.Generic;
using System.IO;

namespace PTor
{

    // Exit-teardown guard: while one PTor is mid-teardown (proxy half-way
    // restored, tor half-way dead), ANY fresh non-takeover launch — double
    // click, OS relaunch, pending UAC from an old restart — must die
    // silently WITHOUT constructing UI, starting tor, or touching the
    // network. Otherwise the stray copy's auto-start orphans a tor and
    // strands proxy settings at dead ports. Takeover launches
    // (--takeover-from) are legitimate handovers and bypass the block.
    // All file logic takes an explicit directory (unit-testable); the
    // production directory is per-user LocalAppData (always writable,
    // survives elevation boundaries for the same user).
    static class ExitMarker
    {
        public const string FilePrefix = "exit-";
        public const string FileSuffix = ".marker";
        public static readonly TimeSpan FreshFor = TimeSpan.FromSeconds(30);

        public static string DefaultDir()
        {
            try
            {
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "PTor", "exit-guard");
            }
            catch { return Path.GetTempPath(); }
        }

        // Written FIRST in every teardown (all exit/restart paths funnel
        // through FastTeardownForExit). Atomic: a torn (0-byte) marker would
        // parse as not-fresh and let a racing launch through — exactly what
        // the marker exists to prevent. Never throws.
        public static void Write(string? dir = null, int? pid = null)
        {
            try
            {
                var d = dir ?? DefaultDir();
                var p = pid ?? Environment.ProcessId;
                SafeFiles.WriteAllTextAtomic(
                    Path.Combine(d, FilePrefix + p + FileSuffix),
                    p + "|" + DateTime.UtcNow.Ticks);
            }
            catch { }
        }

        // Any fresh marker? Freshness comes from CONTENT ticks (robust
        // against clock moves touching file times).
        public static bool IsFreshBlock(string? dir = null, DateTime? now = null)
        {
            try
            {
                var d = dir ?? DefaultDir();
                if (!Directory.Exists(d)) return false;
                var t = (now ?? DateTime.UtcNow).Ticks;
                foreach (var f in Directory.GetFiles(d, FilePrefix + "*" + FileSuffix))
                {
                    try
                    {
                        var parts = (File.ReadAllText(f) ?? "").Split('|');
                        if (parts.Length == 2 && long.TryParse(parts[1], out var ticks) &&
                            ticks > 0 && t - ticks < FreshFor.Ticks && t - ticks >= -TimeSpan.FromMinutes(5).Ticks)
                            return true;
                    }
                    catch { }
                }
                return false;
            }
            catch { return false; }
        }

        public static List<string> DescribeFresh(string? dir = null, DateTime? now = null)
        {
            var out_ = new List<string>();
            try
            {
                var d = dir ?? DefaultDir();
                if (!Directory.Exists(d)) return out_;
                var t = (now ?? DateTime.UtcNow).Ticks;
                foreach (var f in Directory.GetFiles(d, FilePrefix + "*" + FileSuffix))
                {
                    try
                    {
                        var parts = (File.ReadAllText(f) ?? "").Split('|');
                        if (parts.Length == 2 && long.TryParse(parts[1], out var ticks) &&
                            ticks > 0 && t - ticks < FreshFor.Ticks && t - ticks >= -TimeSpan.FromMinutes(5).Ticks)
                            out_.Add(Path.GetFileName(f) + " (age " + TimeSpan.FromTicks(t - ticks).TotalSeconds.ToString("0") + "s)");
                    }
                    catch { }
                }
            }
            catch { }
            return out_;
        }

        // Primary startup housekeeping: drop all markers (fresh or stale) —
        // we are alive and owned, no teardown is in flight.
        public static void ClearAll(string? dir = null)
        {
            try
            {
                var d = dir ?? DefaultDir();
                if (!Directory.Exists(d)) return;
                foreach (var f in Directory.GetFiles(d, FilePrefix + "*" + FileSuffix))
                {
                    try { File.Delete(f); } catch { }
                }
            }
            catch { }
        }
    }
}
