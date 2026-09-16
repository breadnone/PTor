using System;
using System.Collections.Generic;

namespace PTor
{
    // Thrown when a bootstrap stall happens while the circuit pin is active
    // and the evidence points at (or cannot rule out) the pinned relays.
    // MainWindow catches this specifically to run the unpin -> restart ->
    // re-pin rescue. Inherits TimeoutException so older catch blocks that
    // only know TimeoutException still treat it as a stall.
    public sealed class PinSuspectBootstrapException : TimeoutException
    {
        // Short human-readable evidence, e.g. a tor log snippet or
        // "stalled at 10% for 60s with pin active".
        public string Evidence { get; }

        // True when tor's own log explicitly blamed the pin
        // (StrictNodes / no such router / ...). False means "pinned and
        // stalled, pin cannot be ruled out" — still worth one unpinned
        // probe, but the message must say so honestly.
        public bool HasExplicitPinEvidence { get; }

        public PinSuspectBootstrapException(string message, string evidence, bool explicitEvidence)
            : base(message)
        {
            Evidence = evidence ?? "";
            HasExplicitPinEvidence = explicitEvidence;
        }
    }

    public sealed class PinRescueNeededEventArgs : EventArgs
    {
        public string Reason { get; init; } = "";
        // How many consecutive link-check ladders failed while pinned.
        public int DegradedLadders { get; init; }
    }

    // Pure, unit-testable pin-rescue policy. No I/O, no tor, no UI:
    // TorEngine asks "is this log line pin evidence?", MainWindow asks
    // "should I attempt a rescue now?". Never throws.
    public static class PinAutoRecovery
    {
        // Bootstrap: when pinned, a frozen bootstrap aborts this fast
        // instead of burning the full 180-300s timeout on a dead relay.
        // 90s frozen rides out slow first boots (no cached consensus),
        // slow guards and Snowflake rendezvous; a dead StrictNodes pin
        // still aborts far earlier than the full timeout, and explicit
        // tor-log pin blame aborts immediately without waiting at all.
        // (45s proved too aggressive: healthy-but-slow pinned boots were
        // declared dead and auto-unpinned on every app restart.)
        public const int PinStallFreezeSec = 90;

        // Runtime: link checks run ~every 30s with LinkFailThreshold=3 per
        // ladder (~90s per ladder). Two consecutive degraded ladders while
        // pinned (~3 min of no data) triggers the rescue probe. The third
        // ladder would have force-restarted with the SAME dead pin (an
        // infinite loop) — rescue must fire first.
        public const int RuntimeRescueLadders = 2;

        // Post-bootstrap probe when pinned: bootstrap 100% does NOT prove
        // the pinned exit can carry streams (dead exit still bootstraps).
        public const int PostBootstrapProbeSec = 20;

        // Cooldown between automatic rescues: prevents the start watchdog
        // (15s) + link ladder + user toggles from machine-gunning tor when
        // the whole network is down. One rescue proves the point; if the
        // unpinned probe also fails we keep the user's pin and back off.
        public static readonly TimeSpan RescueCooldown = TimeSpan.FromMinutes(5);

        public static bool IsCooldownElapsed(DateTime lastRescueUtc, DateTime now)
        {
            try
            {
                if (lastRescueUtc == DateTime.MinValue) return true;
                return (now - lastRescueUtc) >= RescueCooldown;
            }
            catch { return true; }
        }

        // Tor's own words for "your pinned relay is unusable". Matched
        // case-insensitively against single log lines. Deliberately narrow:
        // generic TLS/handshake failures are NOT pin evidence (they happen
        // on censored networks with healthy pins too) — those still rescue
        // via the stall timeout, just without claiming certainty.
        //
        // False-positive hardening (boot-loop fix): every pinned start logs
        // routine info lines ("StrictNodes set", "Bootstrapped ...") that
        // must NEVER count as pin blame. Only failure lines qualify — and
        // the failure must carry tor's own [warn]/[err] severity. Substring
        // matches on "warn"/"err" are banned: they fire inside innocent
        // words ("error" inside other tokens, "[notice]" lines mentioning
        // StrictNodes, ...). The level prefix is tor's own verdict.
        public static bool IsPinFailureLogLine(string? line)
        {
            try
            {
                if (string.IsNullOrEmpty(line)) return false;
                var l = line.ToLowerInvariant();
                // Progress, never failure.
                if (l.Contains("bootstrapped")) return false;
                // Severity gate: tor blames pins with [warn]/[err]. A
                // [notice] info line (e.g. "StrictNodes set", "EntryNodes
                // configured") is never a verdict, no matter what nouns it
                // mentions. This single gate kills the whole class of
                // info-line false positives that wiped healthy pins.
                bool isFailureLevel = l.Contains("[warn]") || l.Contains("[err]");
                if (!isFailureLevel) return false;
                // "StrictNodes set" info line ships on EVERY pinned start —
                // require a failure phrase so it never triggers a rescue.
                if (l.Contains("strictnodes"))
                {
                    if (l.Contains("fail") || l.Contains("unavail") || l.Contains("unknown") ||
                        l.Contains("not found") || l.Contains("down") || l.Contains("empty") ||
                        l.Contains("invalid") || l.Contains("reject") || l.Contains("no such") ||
                        l.Contains("couldn") || l.Contains("could not") || l.Contains("cannot") ||
                        l.Contains("no running") || l.Contains("no suitable") || l.Contains("exhausted"))
                        return true;
                    return false;
                }
                if (l.Contains("no such router") || l.Contains("no such relay")) return true;
                if (l.Contains("failed to find node")) return true;
                if (l.Contains("couldn't find node") || l.Contains("could not find node")) return true;
                // Narrow: bare "not running" matches unrelated status lines.
                // Only the "not a running relay/router/node" verdict counts.
                if (l.Contains("not a running relay") || l.Contains("not a running router") || l.Contains("not a running node")) return true;
                if (l.Contains("no running relays") || l.Contains("no running nodes")) return true;
                if (l.Contains("all entry nodes") && l.Contains("down")) return true;
                if (l.Contains("no entry nodes")) return true;
                if (l.Contains("no exit nodes")) return true;
                if (l.Contains("cannot choose exit") || l.Contains("couldn't choose exit") || l.Contains("could not choose exit")) return true;
                // NOTE: generic "no suitable ..." / "exhausted ..." deliberately
                // NOT matched: they happen on censored/slow networks with
                // healthy pins too. Those stall out via the freeze timeout
                // (honest "unproven" rescue) instead of an instant abort.
                // Named-position complaints: "EntryNodes ... failed/unavailable/unknown/down",
                // same for ExitNodes/MiddleNodes. Require the failure word so
                // the routine "EntryNodes configured" info line never matches.
                if ((l.Contains("entrynodes") || l.Contains("exitnodes") || l.Contains("middlenodes")) &&
                    (l.Contains("fail") || l.Contains("unavail") || l.Contains("unknown") ||
                     l.Contains("not found") || l.Contains("down") || l.Contains("empty") ||
                     l.Contains("invalid") || l.Contains("reject")))
                    return true;
                return false;
            }
            catch { return false; }
        }

        // Runtime-rescue gate: the link ladder must not fire a pin rescue
        // without a baseline. Right after boot tor needs time to warm
        // (circuits build lazily) and the first ticks fail even on healthy
        // pins — rescuing there wipes a good pin every restart ("always
        // unpinned after reboot"). Two tiers:
        //   * REGRESSED run (at least one end-to-end success this run, then
        //     dead): the pin proved working and now regressed — strong
        //     pin-death signal. 4min grace + 2 degraded ladders.
        //   * NEVER-PROVEN run (zero success this run): cold circuits fail
        //     the first ticks even on healthy pins, and a slow check URL
        //     looks identical to a dead pin. Require a much longer baseline
        //     (8min + 3 ladders) so warm-up/transients can never frame a
        //     healthy pin. Pure, never throws.
        public static readonly TimeSpan RuntimeRescueGrace = TimeSpan.FromMinutes(4);
        public static readonly TimeSpan RuntimeRescueGraceNeverProven = TimeSpan.FromMinutes(8);
        public const int RuntimeRescueLaddersNeverProven = 3;

        public static bool ShouldAllowRuntimeRescue(bool hadLinkSuccessThisRun, DateTime routingStartedUtc, DateTime now, int degradedLadders)
        {
            try
            {
                if (routingStartedUtc == DateTime.MinValue) return false;
                var age = now - routingStartedUtc;
                if (age < TimeSpan.Zero) return false;
                if (hadLinkSuccessThisRun)
                {
                    if (degradedLadders < RuntimeRescueLadders) return false;
                    if (age < RuntimeRescueGrace) return false;
                    return true;
                }
                // Never proven this run: cold-start noise fails ticks on
                // healthy pins. Demand a longer baseline before any verdict.
                if (degradedLadders < RuntimeRescueLaddersNeverProven) return false;
                if (age < RuntimeRescueGraceNeverProven) return false;
                return true;
            }
            catch { return false; }
        }

        // Effective pin positions for rescue decisions. While bridges are in
        // use Tor ignores EntryNodes entirely, so an entry-only pin can
        // never be the cause of a stall — rescuing (and wiping the user's
        // entry pick) would be pure harm. Returns false when there is
        // nothing that could plausibly block this run.
        public static bool HasEffectivePin(bool pinActive, int entryCount, int middleCount, int exitCount, bool bridgesInUse)
        {
            try
            {
                if (!pinActive) return false;
                if (bridgesInUse) return (middleCount + exitCount) > 0;
                return (entryCount + middleCount + exitCount) > 0;
            }
            catch { return false; }
        }

        public static string FormatPins(IEnumerable<string>? entry, IEnumerable<string>? middle, IEnumerable<string>? exit)
        {
            try
            {
                var segs = new List<string>();
                string je = entry == null ? "" : string.Join(",", entry);
                string jm = middle == null ? "" : string.Join(",", middle);
                string jx = exit == null ? "" : string.Join(",", exit);
                if (!string.IsNullOrEmpty(je)) segs.Add("entry " + je);
                if (!string.IsNullOrEmpty(jm)) segs.Add("middle " + jm);
                if (!string.IsNullOrEmpty(jx)) segs.Add("exit " + jx);
                return segs.Count > 0 ? string.Join(" · ", segs) : "(none)";
            }
            catch { return "(unknown)"; }
        }

        static string Shorten(string s, int max)
        {
            try
            {
                if (s == null) return "";
                var t = s.Replace('\r', ' ').Replace('\n', ' ').Trim();
                return t.Length <= max ? t : t.Substring(0, max) + "…";
            }
            catch { return ""; }
        }

        public static string PinStallMessage(string what, int pct, string evidence, bool explicitEvidence)
        {
            try
            {
                var where = pct >= 0 ? $" at {pct}%" : "";
                if (explicitEvidence)
                    return $"Tor is stuck{where} via {what} and its own log blames the pinned relays ({Shorten(evidence, 140)}). " +
                           "The pinned relay(s) look offline or retired — auto-recovery will try an unpinned restart, then re-pin to a live relay. " +
                           "Routing stays OFF until the retry.";
                return $"Tor stalled{where} via {what} with circuit pin ON — the pinned relay(s) may be offline (tor gave no explicit reason, " +
                       "so this is unproven). Auto-recovery will probe once without the pin: if that connects, the pin was the cause and it gets " +
                       "re-pinned to a live relay; if not, your pin is kept untouched. Routing stays OFF until the retry.";
            }
            catch { return "Tor stalled with circuit pin ON."; }
        }
    }
}
