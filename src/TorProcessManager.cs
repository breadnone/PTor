using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{
    public enum TorState
    {
        Stopped,
        Starting,
        Bootstrapping,
        Connected,
        Reconnecting,
        Error
    }

    public class TorStateChangedEventArgs : EventArgs
    {
        public TorState State { get; init; }
        public string Message { get; init; } = "";
        public int? BootstrapPercent { get; init; }
    }

    public class TorProcessManager : IDisposable
    {
        readonly string _toolsDir;
        readonly string _dataDir;
        readonly string _torrcPath;

        Process? _proc;

        // Death-pact job handle: open for tor's whole life, closed only
        // after it is down. Closing it kills any remaining job members.
        IntPtr _jobHandle = IntPtr.Zero;

        void CloseJob()
        {
            try
            {
                var h = _jobHandle;
                _jobHandle = IntPtr.Zero;
                ProcessDeathPact.Close(h);
            }
            catch { }
        }

        public int SocksPort { get; }
        public int ControlPort { get; }
        public int DnsPort { get; }
        public string TorExePath { get; }
        public string ControlCookiePath => Path.Combine(_dataDir, "control_auth_cookie");

        // Entry/exit path options, set before Start, persist across
        // reconnects (same torrc regenerated). Sanitized lists only.
        public List<string> ExitCountries { get; set; } = new();
        // Circuit dirtiness: how long Tor reuses circuits (default 600s).
        // Stable mode raises it so exits hop as rarely as possible.
        public int MaxCircuitDirtinessSec { get; set; } = 600;

        // Circuit pin (anti IP-hop): when enabled AND at least one valid
        // node is listed, torrc pins EntryNodes/MiddleNodes/ExitNodes with
        // StrictNodes 1 and forces MaxCircuitDirtiness to
        // PinnedCircuitDirtinessSec. This OVERRIDES ExitCountries (geo) and
        // any dirtiness value (custom or stable-mode 24h) — enforced in
        // BuildTorrcContent below, so no caller can accidentally emit both.
        // Bridge-run exception: the entry line is dropped there (tor refuses
        // UseBridges+EntryNodes — the bridge is the entry); middle/exit
        // pins still apply.
        public const int PinnedCircuitDirtinessSec = 999999999;
        public bool PinnedCircuitEnabled { get; set; } = false;
        public List<string> PinnedEntryNodes { get; set; } = new();
        public List<string> PinnedMiddleNodes { get; set; } = new();
        public List<string> PinnedExitNodes { get; set; } = new();

        // A pinned node token is either a relay fingerprint (40 hex, with
        // optional leading "$", optional "=name"/"~name" suffix) or a relay
        // nickname. Anything else is rejected (prevents torrc injection via
        // spaces, quotes, comments, or newlines — callers split on those
        // before validating, so a token never legitimately contains them).
        static bool IsValidPinnedNodeToken(string token)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(token)) return false;
                var t = token.Trim();
                if (t.Length == 0 || t.Length > 80) return false;
                if (t.IndexOfAny(new[] { ' ', '\t', '\r', '\n', '"', '\'', '#', ';', ',' }) >= 0)
                    return false;
                var body = t.StartsWith("$") ? t.Substring(1) : t;
                // Split optional "=name" / "~name" suffix (tor's
                // "$FP=name" / "$FP~name" forms).
                string fpPart = body;
                string? nickSuffix = null;
                var sep = body.IndexOfAny(new[] { '=', '~' });
                if (sep >= 0)
                {
                    fpPart = body.Substring(0, sep);
                    nickSuffix = body.Substring(sep + 1);
                    if (string.IsNullOrEmpty(nickSuffix) || nickSuffix.Length > 19)
                        return false;
                    foreach (var c in nickSuffix)
                        if (!(char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '+'))
                            return false;
                }
                // 40-hex fingerprint (with or without "$").
                if (fpPart.Length == 40)
                {
                    var hex = true;
                    foreach (var c in fpPart)
                        if (!Uri.IsHexDigit(c)) { hex = false; break; }
                    if (hex) return true;
                }
                // No suffix allowed on bare nicknames with a separator that
                // wasn't a valid fingerprint form.
                if (sep >= 0) return false;
                // Relay nickname: 1..19 chars, starts alnum.
                if (body.Length < 1 || body.Length > 19) return false;
                if (!char.IsLetterOrDigit(body[0])) return false;
                foreach (var c in body)
                    if (!(char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '+'))
                        return false;
                return true;
            }
            catch { return false; }
        }

        static string NormalizePinnedNodeToken(string token)
        {
            try
            {
                var t = token.Trim();
                var hasDollar = t.StartsWith("$");
                var body = hasDollar ? t.Substring(1) : t;
                var sep = body.IndexOfAny(new[] { '=', '~' });
                if (sep >= 0)
                {
                    var fp = body.Substring(0, sep);
                    var suffix = body.Substring(sep); // keeps =/~ + name
                    if (fp.Length == 40)
                    {
                        var hex = true;
                        foreach (var c in fp)
                            if (!Uri.IsHexDigit(c)) { hex = false; break; }
                        if (hex) return "$" + fp.ToUpperInvariant() + suffix;
                    }
                    return (hasDollar ? "$" : "") + body;
                }
                if (body.Length == 40)
                {
                    var hex = true;
                    foreach (var c in body)
                        if (!Uri.IsHexDigit(c)) { hex = false; break; }
                    if (hex) return "$" + body.ToUpperInvariant();
                }
                return t;
            }
            catch { return token.Trim(); }
        }

        // Parse free-form user input (comma/semicolon/space/newline
        // separated) into sanitized, de-duplicated node tokens. Invalid
        // tokens are dropped. Never throws. Accepts either a raw string or
        // a pre-split list (both funnel here).
        public static List<string> ParsePinnedNodes(string? raw)
        {
            var out_ = new List<string>();
            try
            {
                if (string.IsNullOrWhiteSpace(raw)) return out_;
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var part in raw.Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var tok = part.Trim();
                    if (tok.Length == 0) continue;
                    if (!IsValidPinnedNodeToken(tok)) continue;
                    var norm = NormalizePinnedNodeToken(tok);
                    if (seen.Add(norm)) out_.Add(norm);
                }
            }
            catch { }
            return out_;
        }

        public static List<string> SanitizePinnedNodes(IEnumerable<string>? tokens)
        {
            var out_ = new List<string>();
            try
            {
                if (tokens == null) return out_;
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var raw in tokens)
                {
                    var tok = (raw ?? "").Trim();
                    if (tok.Length == 0) continue;
                    if (!IsValidPinnedNodeToken(tok)) continue;
                    var norm = NormalizePinnedNodeToken(tok);
                    if (seen.Add(norm)) out_.Add(norm);
                }
            }
            catch { }
            return out_;
        }

        // Single rule for "is the pin actually active": toggle ON plus at
        // least one valid node across the three positions. An ON toggle with
        // zero valid nodes is INACTIVE (torrc falls back to normal path) —
        // callers log a warning in that case. Never throws.
        public static bool IsPinActive(bool enabled, IEnumerable<string>? entry, IEnumerable<string>? middle, IEnumerable<string>? exit)
        {
            try
            {
                if (!enabled) return false;
                var e = SanitizePinnedNodes(entry).Count;
                var m = SanitizePinnedNodes(middle).Count;
                var x = SanitizePinnedNodes(exit).Count;
                return (e + m + x) > 0;
            }
            catch { return false; }
        }

        public static bool IsPinActiveRaw(bool enabled, string? entryRaw, string? middleRaw, string? exitRaw)
        {
            try
            {
                if (!enabled) return false;
                return (ParsePinnedNodes(entryRaw).Count
                    + ParsePinnedNodes(middleRaw).Count
                    + ParsePinnedNodes(exitRaw).Count) > 0;
            }
            catch { return false; }
        }

        // Stream retry timeout, seconds (torrc CircuitStreamTimeout): how
        // long until Tor detaches a stream from a sluggish circuit and tries
        // a new one. 0 = Tor's internal schedule (tor default).
        public int CircuitStreamTimeoutSec { get; set; } = 0;

        // Restrictive local firewall (torrc FascistFirewall): guard links
        // only on ports 80/443. For networks that filter other outbound
        // ports (guard TLS handshakes die otherwise).
        public bool FascistFirewallOnly { get; set; } = false;

        // Config range for the above: 60s..24h, Tor default 600s on anything
        // else (single rule shared by settings load, UI save, and start).
        internal static int SanitizeDirtinessSec(int v)
        {
            try { return v >= 60 && v <= 86400 ? v : 600; }
            catch { return 600; }
        }

        // Config range for the stream timeout: 0..600s, Tor internal
        // schedule (0) on anything else.
        internal static int SanitizeStreamTimeoutSec(int v)
        {
            try { return v >= 0 && v <= 600 ? v : 0; }
            catch { return 0; }
        }
        public bool IsRunning
        {
            get
            {
                try
                {
                    // Snapshot once: _proc is nulled lock-free by
                    // MadmanKillTor/KillTreeNow racing a gated Start — a
                    // double field read can NRE between the null check and
                    // HasExited.
                    var p = _proc;
                    return p != null && !p.HasExited;
                }
                catch { return false; }
            }
        }

        public int? CurrentPid
        {
            get
            {
                try
                {
                    var p = _proc;
                    return (p != null && !p.HasExited) ? p.Id : null;
                }
                catch { return null; }
            }
        }

        // Re-asserts the never-Eco invariant on us + the daemon (something
        // may have re-tagged either mid-run: user click, OS heuristics).
        // Returns a human note when it actually cleared a tag, else null.
        // Never throws. Called on the slow link-tick cadence, not per packet.
        public string? ReassertNoEcoMode()
        {
            try
            {
                var cleared = new System.Collections.Generic.List<string>();
                try { if (EcoModeGuard.ClearIfTaggedCurrent()) cleared.Add("PTor"); } catch { }
                var p = _proc;
                try
                {
                    if (p != null)
                    {
                        bool dead = false;
                        try { dead = p.HasExited; } catch { dead = true; }
                        if (!dead && EcoModeGuard.ClearIfTaggedProcess(p)) cleared.Add("tor.exe");
                    }
                }
                catch { }
                if (cleared.Count == 0) return null;
                return string.Join(", ", cleared);
            }
            catch { return null; }
        }

        public event EventHandler<TorStateChangedEventArgs>? StateChanged;
        public event EventHandler? UnexpectedExit;

        public TorProcessManager(string appBaseDir, int socksPort = 9050, int controlPort = 9051, int dnsPort = 9053)
        {
            _toolsDir = Path.Combine(appBaseDir, "tools");
            TorExePath = Path.Combine(_toolsDir, "Tor", "tor.exe");
            if (!File.Exists(TorExePath))
            {

                var alt = Path.Combine(_toolsDir, "tor.exe");
                if (File.Exists(alt)) TorExePath = alt;
            }

            _dataDir = Path.Combine(appBaseDir, "tordata");
            Directory.CreateDirectory(_dataDir);
            _torrcPath = Path.Combine(_dataDir, "torrc.generated");

            SocksPort = socksPort;
            ControlPort = controlPort;
            DnsPort = dnsPort;
        }

        internal static string BuildTorrcContent(
            int socksPort, int controlPort, int dnsPort,
            string dataDir, string? geoV4, string? geoV6,
            ResolvedBridges? bridges,
            int dirtinessSec = 600,
            IEnumerable<string>? exitCountries = null,
            int circuitStreamTimeoutSec = 0,
            bool fascistFirewall = false,
            bool pinnedCircuitEnabled = false,
            IEnumerable<string>? pinnedEntryNodes = null,
            IEnumerable<string>? pinnedMiddleNodes = null,
            IEnumerable<string>? pinnedExitNodes = null)
        {
            // PIN OVERRIDES EVERYTHING below: when active, dirtiness is
            // forced huge and the geo ExitNodes block is skipped entirely
            // (a single torrc must never contain two ExitNodes / StrictNodes
            // lines — Tor would apply the last one, silently breaking the
            // guarantee). Sanitized here, so even a caller that forgot to
            // clear ExitCountries still gets the pin and nothing else.
            var pinEntry = SanitizePinnedNodes(pinnedEntryNodes);
            var pinMiddle = SanitizePinnedNodes(pinnedMiddleNodes);
            var pinExit = SanitizePinnedNodes(pinnedExitNodes);
            var pinActive = pinnedCircuitEnabled && (pinEntry.Count + pinMiddle.Count + pinExit.Count) > 0;
            var effectiveDirtiness = pinActive ? PinnedCircuitDirtinessSec : Math.Max(60, dirtinessSec);
            var torrc = $@"
SocksPort 127.0.0.1:{socksPort}
ControlPort 127.0.0.1:{controlPort}
CookieAuthentication 1
DNSPort 127.0.0.1:{dnsPort}
DataDirectory {dataDir.Replace("\\", "/")}
{(geoV4 != null ? $"GeoIPFile {geoV4.Replace("\\", "/")}" : "# GeoIPFile <bundle geoip not found - country lookup unavailable>")}
{(geoV6 != null ? $"GeoIPv6File {geoV6.Replace("\\", "/")}" : "# GeoIPv6File <bundle geoip6 not found - country lookup unavailable>")}
AvoidDiskWrites 1
ClientOnly 1
KeepalivePeriod 10
MaxClientCircuitsPending 64
MaxCircuitDirtiness {effectiveDirtiness}
CircuitStreamTimeout {Math.Max(0, circuitStreamTimeoutSec)}
{(fascistFirewall ? "FascistFirewall 1" : "# FascistFirewall 0 (all ports allowed)")}
Log notice stdout
";
            if (bridges != null && bridges.UseBridges)
            {
                torrc += "UseBridges 1\n";
                foreach (var plugin in bridges.PluginLines)
                    torrc += plugin + "\n";
                foreach (var line in bridges.BridgeLines)
                    torrc += "Bridge " + line + "\n";
            }
            if (pinActive)
            {
                // StrictNodes 1: never use a node outside the pinned set.
                // Only non-empty positions are emitted (an empty Middle list
                // simply means "any middle" while entry+exit stay pinned).
                //
                // Bridge exception: tor REFUSES a torrc containing both
                // UseBridges and EntryNodes ("Failed to parse/validate
                // config: You cannot set both UseBridges and EntryNodes" —
                // instant exit, verified on tor 0.4.9.11). The bridge IS the
                // entry on such runs, so the entry pin is dropped here while
                // middle/exit pins still apply. An entry-only pin under
                // bridges therefore emits no pin block at all (a bare
                // StrictNodes 1 with nothing to constrain would be a lie in
                // the torrc) — BootstrapPinActive already treats that run as
                // unpinned for rescue purposes.
                var bridging = bridges != null && bridges.UseBridges;
                if (pinEntry.Count > 0 && !bridging)
                    torrc += "EntryNodes " + string.Join(",", pinEntry) + "\n";
                else if (pinEntry.Count > 0)
                    torrc += "# EntryNodes <dropped for this run: the bridge is the entry — tor refuses UseBridges+EntryNodes>\n";
                if (pinMiddle.Count > 0)
                    torrc += "MiddleNodes " + string.Join(",", pinMiddle) + "\n";
                if (pinExit.Count > 0)
                    torrc += "ExitNodes " + string.Join(",", pinExit) + "\n";
                if (!bridging || (pinMiddle.Count + pinExit.Count) > 0)
                    torrc += "StrictNodes 1\n";
                else
                    torrc += "# StrictNodes <dropped with the entry-only pin: nothing to constrain on this bridge run>\n";
            }
            else if (exitCountries != null)
            {
                var codes = exitCountries
                    .Where(c => !string.IsNullOrWhiteSpace(c))
                    .Select(c => c.Trim().ToLowerInvariant())
                    .Where(c => c.Length == 2 && c.All(char.IsLetter))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                if (codes.Count > 0)
                {
                    // StrictNodes 0 (the default, stated explicitly): fall
                    // back to any country when preferred exits are unavailable.
                    torrc += "ExitNodes " + string.Join(",", codes.Select(c => "{" + c + "}")) + "\n";
                    torrc += "StrictNodes 0\n";
                }
            }
            return torrc;
        }

        void WriteTorrc(ResolvedBridges? bridges)
        {

            var geoV4 = FindBundleFile("geoip");
            var geoV6 = FindBundleFile("geoip6");

            // Atomic: a crash mid-write must not leave a truncated torrc for
            // the next start to read (regenerated every launch anyway, but a
            // torn file fails tor with a cryptic config error).
            if (!SafeFiles.WriteAllTextAtomic(_torrcPath, BuildTorrcContent(
                SocksPort, ControlPort, DnsPort, _dataDir, geoV4, geoV6, bridges,
                MaxCircuitDirtinessSec, ExitCountries, CircuitStreamTimeoutSec, FascistFirewallOnly,
                PinnedCircuitEnabled, PinnedEntryNodes, PinnedMiddleNodes, PinnedExitNodes)))
                throw new IOException("Could not write torrc (disk full or access denied): " + _torrcPath);
        }

        string? FindBundleFile(string name)
        {
            try
            {
                var exeDir = Path.GetDirectoryName(TorExePath);
                var candidates = new[]
                {
                    exeDir != null ? Path.Combine(exeDir, name) : null,
                    Path.Combine(_toolsDir, name),
                    Path.Combine(_toolsDir, "Tor", name),
                    Path.Combine(_toolsDir, "data", name)
                };
                foreach (var c in candidates)
                    if (!string.IsNullOrEmpty(c) && File.Exists(c))
                        return c;
            }
            catch { }
            return null;
        }

        // Crash orphans: a killed PTor strands tor.exe + pluggable transports
        // (lyrebird/snowflake helpers) that pile up across restarts, wasting
        // RAM/sockets and fighting over files. Anything running from OUR
        // tools dir is ours by construction (single instance; Tor Browser et
        // al live elsewhere) — reap it before launching. Never throws.
        static readonly string[] StaleSweepNames = { "tor", "lyrebird", "conjure-client", "snowflake-client" };

        void ReclaimStaleProcesses()
        {
            try
            {
                string root;
                try { root = Path.GetFullPath(_toolsDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar; }
                catch { return; }
                var me = Environment.ProcessId;
                var reaped = 0;
                Process[] all;
                try { all = Process.GetProcesses(); }
                catch { return; }
                foreach (var p in all)
                {
                    string name = "";
                    try
                    {
                        if (p.Id == me || p.HasExited) continue;
                        name = p.ProcessName ?? "";
                    }
                    catch { try { p.Dispose(); } catch { } continue; }
                    bool wanted = false;
                    foreach (var n in StaleSweepNames)
                        if (name.Equals(n, StringComparison.OrdinalIgnoreCase)) { wanted = true; break; }
                    if (!wanted) { try { p.Dispose(); } catch { } continue; }
                    try
                    {
                        var exe = RunningAppEnumerator.TryGetExePath(p.Id);
                        if (string.IsNullOrEmpty(exe) ||
                            !Path.GetFullPath(exe).StartsWith(root, StringComparison.OrdinalIgnoreCase))
                            continue; // same name, different owner (e.g. Tor Browser) — hands off
                        try { p.Kill(); } catch { continue; }
                        try { p.WaitForExit(3000); } catch { }
                        reaped++;
                    }
                    catch { }
                    finally { try { p.Dispose(); } catch { } }
                }
                if (reaped > 0)
                    RaiseState(TorState.Starting,
                        $"Removed {reaped} stale Tor/transport process(es) orphaned by a previous run.");
            }
            catch { }
        }

        void ReclaimOurPorts()
        {
            foreach (var port in new[] { (ushort)SocksPort, (ushort)ControlPort, (ushort)DnsPort })
            {
                int? pid;
                try { pid = AppTrafficMonitor.GetTcpListenerOwner(port); }
                catch { continue; }
                if (pid == null) continue;

                string? exe = null;
                try { exe = RunningAppEnumerator.TryGetExePath(pid.Value); } catch { }

                if (string.IsNullOrEmpty(exe) ||
                    !string.Equals(exe, TorExePath, StringComparison.OrdinalIgnoreCase))
                {
                    var who = string.IsNullOrEmpty(exe) ? $"PID {pid.Value}" : $"{exe} (PID {pid.Value})";
                    throw new InvalidOperationException(
                        $"Port {port} is already in use by {who} — not our tor. Free the port (or stop the other program) and try again. " +
                        "(Launching tor anyway would die with tor's cryptic 'Failed to bind / Reading config failed'.)");
                }

                var stopped = false;
                string stopErr = "";
                try
                {
                    using var p = Process.GetProcessById(pid.Value);
                    try
                    {
                        p.Kill();

                        try { p.WaitForExit(5000); } catch { }
                        stopped = true;
                    }
                    catch (Exception ex) { stopErr = ex.GetType().Name; }
                }
                catch { stopped = true; }
                if (!stopped)
                    throw new InvalidOperationException(
                        $"Port {port} is held by our tor.exe (PID {pid.Value}) but stopping it failed ({stopErr}) — kill it in Task Manager and retry.");
                RaiseState(TorState.Starting,
                    $"Removed stale tor.exe (PID {pid.Value}) holding port {port} — likely orphaned by a crash.");
            }
        }

        public void Start(ResolvedBridges? bridges = null)
        {
            if (IsRunning) return;
            // New generation owns Exited events again: a prior Stop/ForceKill
            // left _stopping/_disposing true to quiet late duplicates — clear
            // here so a genuine crash of THIS daemon still reports.
            _stopping = false;
            _disposing = false;
            TorUpdater.RecoverIncompleteInstall(_toolsDir, msg => RaiseState(TorState.Starting, msg));
            if (!File.Exists(TorExePath))
                throw new FileNotFoundException(
                    $"tor.exe not found. Expected the Tor Expert Bundle extracted under: {_toolsDir}");

            ReclaimStaleProcesses();
            ReclaimOurPorts();

            try { ClearLogTail(); } catch { }
            WriteTorrc(bridges);
            RaiseState(TorState.Starting, "Launching tor.exe...");

            var psi = new ProcessStartInfo
            {
                FileName = TorExePath,
                Arguments = $"-f \"{_torrcPath}\"",
                WorkingDirectory = Path.GetDirectoryName(TorExePath)!,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            _proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            _proc.OutputDataReceived += (_, e) => ParseLogLine(e.Data);
            _proc.ErrorDataReceived += (_, e) => ParseLogLine(e.Data);
            _proc.Exited += (_, __) =>
            {
                if (!_disposing && !_stopping)
                {
                    RaiseState(TorState.Error, "tor.exe exited unexpectedly.");
                    UnexpectedExit?.Invoke(this, EventArgs.Empty);
                }
            };

            _proc.Start();
            _proc.BeginOutputReadLine();
            _proc.BeginErrorReadLine();

            // Never-Eco: tor inherits OUR throttling state at creation (we
            // opted out at app startup), and this re-asserts it on the fresh
            // daemon in case anything re-tagged us between launch and now.
            try { EcoModeGuard.OptOutProcess(_proc); } catch { }

            // Death pact BEFORE anything else can crash us: from this point
            // on, our death (even Task Manager kill) takes tor + its
            // transports with it — no orphans, ever.
            CloseJob();
            _jobHandle = ProcessDeathPact.Assign(_proc);
            if (_jobHandle == IntPtr.Zero)
                RaiseState(TorState.Starting,
                    "Tor death-pact unavailable (sandboxed launch?) — stale-process sweep on next start remains as backstop.");

            RaiseState(TorState.Bootstrapping, "Waiting for Tor to bootstrap...");
        }

        void ParseLogLine(string? line)
        {
            if (string.IsNullOrWhiteSpace(line)) return;
            PushLogTail(line.Trim());

            var idx = line.IndexOf("Bootstrapped ", StringComparison.Ordinal);
            if (idx >= 0)
            {
                var rest = line[(idx + "Bootstrapped ".Length)..];
                var pctEnd = rest.IndexOf('%');
                if (pctEnd > 0 && int.TryParse(rest[..pctEnd], out var pct))
                {
                    var state = pct >= 100 ? TorState.Connected : TorState.Bootstrapping;
                    RaiseState(state, line.Trim(), pct);
                    return;
                }
            }

            if (line.Contains("[warn]") || line.Contains("[err]"))
            {
                // Expected-transient bridge noise: while a multi-candidate
                // fallback is in flight, tor logs one of these per dead
                // bridge ("Proxy Client ... handshaking (proxy) ... general
                // SOCKS server failure", "Problem bootstrapping. Stuck at")
                // and then tries the next candidate. Painting each one as a
                // terminal Error turns every partially-blocked bridge set
                // red even when a later candidate connects — and makes a
                // single stale bundled bridge read as "obfs4 mode always
                // errors". The log tail still keeps them (stall/pin scans
                // read the raw lines), and a truly exhausted run still fails
                // loudly via the start exception. Status-only demotion.
                if (IsTransientBridgeWarning(line))
                    RaiseState(TorState.Bootstrapping, line.Trim());
                else
                    RaiseState(TorState.Error, line.Trim());
            }
        }

        // Tor lines that are routine per-candidate fallout during bridge
        // fallback, not run-level failures. Never throws.
        internal static bool IsTransientBridgeWarning(string? line)
        {
            try
            {
                if (string.IsNullOrEmpty(line)) return false;
                if (line.IndexOf("Proxy Client", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    line.IndexOf("handshaking (proxy)", StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
                if (line.IndexOf("general SOCKS server failure", StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
                var l = line.ToLowerInvariant();
                if (l.Contains("problem bootstrapping") && l.Contains("stuck at"))
                    return true;
                return false;
            }
            catch { return false; }
        }

        volatile bool _disposing;
        // Cross-thread stop flag: volatile so an in-flight Exited event can't misread a clean stop as a crash.
        volatile bool _stopping;

        // Rolling tail of tor's own stdout/stderr (1st-boot failures say WHY
        // here: port binds, missing files, guard/TLS issues). Shown in Config.
        readonly System.Collections.Concurrent.ConcurrentQueue<string> _logTail = new();
        const int LogTailCap = 300;

        void PushLogTail(string line)
        {
            try
            {
                _logTail.Enqueue(line);
                while (_logTail.Count > LogTailCap && _logTail.TryDequeue(out _)) { }
            }
            catch { }
        }

        public List<string> GetLogTail()
        {
            try { return _logTail.ToList(); }
            catch { return new List<string>(); }
        }

        // Fresh daemon, fresh evidence: without this, pin-blame lines from
        // the PREVIOUS run linger in the rolling tail and the next
        // bootstrap wait (seen=0) instantly "finds" stale pin evidence —
        // every restart rescues again even though the new tor is healthy
        // (the reported boot-loop + always-unpinned-after-reboot). Start()
        // clears; waits additionally skip pre-existing lines (belt and
        // suspenders for rescue restarts that reuse the manager).
        public void ClearLogTail()
        {
            try { while (_logTail.TryDequeue(out _)) { } } catch { }
        }

        // Instant kill, no waits: SIGKILL lands in ms, the OS reaps after
        // us. Exit/quit must never park on WaitForExit (stdout pipe +
        // inherited handles can hold it the full timeout). Cancel the
        // async stdout/stderr pumps FIRST so the Process object completes,
        // kill, close the death-pact job (reaps transports), dispose.
        // Fire-and-forget sweep for stragglers — never waited on.
        public Task StopAsync()
        {
            var proc = _proc;
            if (proc == null) return Task.CompletedTask;
            _stopping = true; // first: quiet any in-flight Exited event
            _disposing = true;
            try
            {
                if (!SafeHasExited(proc))
                {
                    // Cancel pumps BEFORE kill so a full pipe can't hold the
                    // handle (and its ports) alive until GC.
                    try { proc.CancelOutputRead(); } catch { }
                    try { proc.CancelErrorRead(); } catch { }
                    try { proc.Kill(); } catch { }
                }
                else
                {
                    try { proc.CancelOutputRead(); } catch { }
                    try { proc.CancelErrorRead(); } catch { }
                }
            }
            finally
            {
                try { proc.Dispose(); } catch { }
                if (ReferenceEquals(_proc, proc)) _proc = null;
                // Closing the pact handle IS a kill for job members
                // (transports die with it, instantly).
                CloseJob();
                try { System.Threading.Tasks.Task.Run(() => { try { KillOursSweep(); } catch { } }); } catch { }
                RaiseState(TorState.Stopped, "Tor stopped.");
                // NOTE: _stopping/_disposing stay true (quiet late Exited
                // duplicates that would otherwise resurrect tor after an
                // explicit stop). Next Start() clears them for the new daemon.
            }
            return Task.CompletedTask;
        }

        static bool SafeHasExited(Process proc)
        {
            try { return proc.HasExited; }
            catch { return true; } // uninterrogable: treat as gone, disposal below still runs
        }

        // Live-daemon shield for the detached sweeps below. A Stop fires a
        // detached KillOursSweep/KillPortOwners, and every auto path that
        // follows a Stop with a Start within milliseconds (reconnect,
        // pin-rescue probe/restore/re-pin, force retry) spawns the SUCCESSOR
        // tor before the sweep finishes enumerating — without this shield the
        // sweep murders the healthy successor (same tools dir, same ports)
        // and the boot loops on BOTH pinned and unpinned runs; when the
        // murder lands on the rescue's re-pin restart the rescue falls back
        // unpinned with the pin OFF ("always unpinned after reboot" while the
        // server was fine). The pid is re-read at kill time (not cached at
        // enumeration time) so a successor spawned mid-sweep is still spared.
        // Never throws; null when no live daemon is tracked.
        int? LivePidNow()
        {
            try
            {
                var p = _proc;
                if (p == null) return null;
                try { if (p.HasExited) return null; }
                catch { return null; }
                try { return p.Id; }
                catch { return null; }
            }
            catch { return null; }
        }

        // True when pid is the live daemon or a child of it (the successor's
        // own transports). Stale transports from a dead run are reparented
        // away from the dead daemon, so they never match. Never throws.
        bool IsLiveDaemonTree(int pid)
        {
            try
            {
                var live = LivePidNow();
                if (live == null) return false;
                if (pid == live.Value) return true;
                try { if (RunningAppEnumerator.GetParentPid(pid) == live.Value) return true; }
                catch { }
                return false;
            }
            catch { return false; }
        }

        // Instant single-target kill: fire SIGKILL, cancel pumps, report
        // liveness WITHOUT waiting. Never blocks the exit path. Never throws.
        // (Old code did WaitForExit(budget) here — up to 5s parked on a
        // stdout pipe held open by transports. Children are covered by the
        // job object + detached sweep, not by waiting here.)
        internal static bool KillVerified(Process? proc, TimeSpan waitBudget)
        {
            try
            {
                if (proc == null) return true;
                bool dead;
                try { dead = proc.HasExited; } catch { dead = true; }
                if (dead) return true;
                try { proc.CancelOutputRead(); } catch { }
                try { proc.CancelErrorRead(); } catch { }
                try { proc.Kill(); } catch { }
                try { dead = proc.HasExited; } catch { dead = true; }
                return dead;
            }
            catch { return false; }
        }

        // Instant exit kill: close the job FIRST (KILL_ON_JOB_CLOSE reaps
        // tor + every transport instantly, even ones mid-spawn), cancel the
        // stdout/stderr pumps, direct-kill the daemon, dispose, close the
        // job again. Sweeps run DETACHED (fire-and-forget) — enumerating
        // processes + resolving exe paths can take seconds on a sick system
        // and must never park the exit path. Returns 0 (instant, unverified
        // by design — the OS finishes reaping after we die). Never throws.
        // Runs anywhere, including the UI thread. Returns in milliseconds.
        public int MadmanKillTor()
        {
            try
            {
                _stopping = true; // quiet any in-flight Exited event on the way out
                _disposing = true;
                try { CloseJob(); } catch { }
                Process? p = null;
                try
                {
                    p = _proc;
                    _proc = null;
                    if (p != null)
                    {
                        try { p.CancelOutputRead(); } catch { }
                        try { p.CancelErrorRead(); } catch { }
                        try { if (!SafeHasExited(p)) p.Kill(); } catch { }
                    }
                }
                catch { }
                finally { try { p?.Dispose(); } catch { } }
                try { CloseJob(); } catch { }
                // Stragglers (stale crash leftovers, port squatters) die
                // detached: exit does not wait for enumeration.
                try
                {
                    System.Threading.Tasks.Task.Run(() =>
                    {
                        try { KillOursSweep(); } catch { }
                        try { KillPortOwners(); } catch { }
                    });
                }
                catch { try { KillOursSweep(); } catch { } }
            }
            catch { }
            return 0;
        }

        // PIDs holding our SOCKS/control/DNS listen ports, whatever their exe
        // path (even unreadable under elevation mismatch). A tor holding our
        // ports IS ours for kill purposes: no other program should ever bind
        // them (start refuses to launch over a foreign owner). This is the
        // backstop for the case TryGetExePath returns null (elevated tor vs
        // non-elevated PTor) where the path-prefix sweep would go blind and
        // falsely report "verified dead" while tor lives until reboot.
        List<int> FindPortOwnerPids()
        {
            var out_ = new List<int>();
            try
            {
                var me = Environment.ProcessId;
                foreach (var port in new[] { (ushort)SocksPort, (ushort)ControlPort, (ushort)DnsPort })
                {
                    int? pid = null;
                    try { pid = AppTrafficMonitor.GetTcpListenerOwner(port); }
                    catch { continue; }
                    if (pid == null || pid <= 0 || pid == me) continue;
                    if (!out_.Contains(pid.Value)) out_.Add(pid.Value);
                }
            }
            catch { }
            return out_;
        }

        void KillPortOwners()
        {
            List<int> pids;
            try { pids = FindPortOwnerPids(); } catch { return; }
            foreach (var pid in pids)
            {
                try
                {
                    // Shield: the successor tor (spawned after our Stop, before
                    // this detached sweep ran) legitimately holds these ports.
                    // Killing it here re-bricked every reconnect/rescue restart.
                    try { if (IsLiveDaemonTree(pid)) continue; } catch { }
                    using var p = Process.GetProcessById(pid);
                    bool dead = false;
                    try { dead = p.HasExited; } catch { dead = true; }
                    if (dead) continue;
                    // Direct kill only: no tree-walk (slow WMI walk can stall
                    // the exit path on a sick system; children die via the
                    // job object, stragglers via the name sweep).
                    try { p.Kill(); } catch { }
                }
                catch { }
            }
        }

        // PIDs of OUR tools-dir tor/transport binaries, whatever parentage
        // (tracked daemon, forgotten handles, stale crash leftovers). Same
        // ownership rule as the sweeps: Tor Browser et al live elsewhere.
        // Fallback when the exe path is unreadable (elevation mismatch):
        // a same-named process holding OUR ports, or parented to us / our
        // tracked tor, is treated as ours instead of being skipped (skipping
        // is what orphaned tor until reboot while reporting "verified dead").
        List<int> FindOursPids()
        {
            var out_ = new List<int>();
            try
            {
                string root;
                try { root = Path.GetFullPath(_toolsDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar; }
                catch { return out_; }
                var me = Environment.ProcessId;
                int? trackedPid = null;
                try
                {
                    var tp = _proc;
                    if (tp != null && !SafeHasExited(tp)) trackedPid = tp.Id;
                }
                catch { }
                HashSet<int> portOwners;
                try { portOwners = new HashSet<int>(FindPortOwnerPids()); }
                catch { portOwners = new HashSet<int>(); }
                Process[] all;
                try { all = Process.GetProcesses(); }
                catch { return out_; }
                foreach (var p in all)
                {
                    try
                    {
                        if (p.Id == me) continue;
                        bool dead = false;
                        try { dead = p.HasExited; } catch { dead = true; }
                        if (dead) continue;
                        var name = p.ProcessName ?? "";
                        bool wanted = false;
                        foreach (var n in StaleSweepNames)
                            if (name.Equals(n, StringComparison.OrdinalIgnoreCase)) { wanted = true; break; }
                        if (!wanted) continue;
                        var exe = RunningAppEnumerator.TryGetExePath(p.Id);
                        if (!string.IsNullOrEmpty(exe))
                        {
                            bool ours = false;
                            try { ours = Path.GetFullPath(exe).StartsWith(root, StringComparison.OrdinalIgnoreCase); }
                            catch { ours = false; }
                            if (ours) out_.Add(p.Id);
                            continue;
                        }
                        // Exe path unreadable (access denied / elevation
                        // mismatch): fall back to port + parentage signals.
                        // Never blindly kill unknown tor (Tor Browser), but a
                        // tor holding OUR ports, or parented to us/tor, is ours.
                        if (portOwners.Contains(p.Id)) { out_.Add(p.Id); continue; }
                        try
                        {
                            var ppid = RunningAppEnumerator.GetParentPid(p.Id);
                            if (ppid == me || (trackedPid != null && ppid == trackedPid.Value))
                                out_.Add(p.Id);
                        }
                        catch { }
                    }
                    catch { }
                    finally { try { p.Dispose(); } catch { } }
                }
                // Port owners with a non-tor name (shouldn't happen) still
                // count: something squats our tor ports and must die for a
                // clean exit/restart. Verify liveness cheaply.
                try
                {
                    foreach (var pid in portOwners)
                    {
                        if (out_.Contains(pid)) continue;
                        try
                        {
                            // Shield (see KillPortOwners): never list the live
                            // successor or its tree for the detached kill.
                            try { if (IsLiveDaemonTree(pid)) continue; } catch { }
                            using var q = Process.GetProcessById(pid);
                            bool dead = false;
                            try { dead = q.HasExited; } catch { dead = true; }
                            if (!dead) out_.Add(pid);
                        }
                        catch { }
                    }
                }
                catch { }
            }
            catch { }
            // Final shield at enumeration time (the per-kill recheck in
            // KillOursSweep covers successors spawned after this return):
            // never hand the live daemon tree to a detached killer.
            try
            {
                if (out_.Count > 0)
                    out_.RemoveAll(pid => { try { return IsLiveDaemonTree(pid); } catch { return false; } });
            }
            catch { }
            return out_;
        }

        int CountOursAlive()
        {
            try { return FindOursPids().Count; }
            catch { return 0; }
        }

        // Instant kill for exit paths: fire SIGKILL, wait for nothing. The
        // death-pact job reaps transports with us; the OS reaps the rest on
        // process death. No waits by design — the caller is dying anyway.
        // Order matters: the tracked daemon dies first, then the pact handle
        // closes (KILL_ON_JOB_CLOSE reaps any remaining job members such as
        // pluggable transports instantly), then a sweep kills anything of
        // ours still alive (a transport that escaped the tree-kill, a stale
        // daemon from a previous crash). All fire-and-forget: this must
        // return in milliseconds, never block the exit path.
        public void KillTreeNow()
        {
            _stopping = true; // quiet any in-flight Exited event on the way out
            _disposing = true;
            try
            {
                var p = _proc;
                _proc = null;
                // Direct kill, NOT entireProcessTree: the tree-walk enumerates
                // via WMI and can stall for seconds on a sick system, parking
                // the exit path. Children die via the job close below.
                try { if (p != null && !SafeHasExited(p)) p.Kill(); } catch { }
                try { if (p != null) { try { p.CancelOutputRead(); } catch { } try { p.CancelErrorRead(); } catch { } } } catch { }
                try { p?.Dispose(); } catch { }
                // Closing the pact handle IS a kill for job members.
                CloseJob();
            }
            catch { }
            try { KillOursSweep(); } catch { }
            try { KillPortOwners(); } catch { }
        }

        // Backstop for the exit path only: kill any tor/transport binary
        // running from OUR tools dir, whatever its parentage. Same ownership
        // rule as the start-time sweep (single instance; Tor Browser et al
        // live elsewhere — never touched). No waits: SIGKILL lands in ms,
        // the OS finishes the reaping after we are gone.
        void KillOursSweep()
        {
            // Kill by re-resolved PID (ownership re-verified inside
            // FindOursPids): fire-and-forget SIGKILL, no waits — callers that
            // need certainty follow with CountOursAlive. Direct kill only:
            // entireProcessTree walks can stall the exit path.
            List<int> pids;
            try { pids = FindOursPids(); } catch { return; }
            foreach (var pid in pids)
            {
                try
                {
                    // Shield (see LivePidNow): re-verify at kill time — a
                    // successor spawned after the enumeration must survive.
                    try { if (IsLiveDaemonTree(pid)) continue; } catch { }
                    using var p = Process.GetProcessById(pid);
                    try { if (!p.HasExited) p.Kill(); } catch { }
                }
                catch { }
            }
        }

        void RaiseState(TorState state, string msg, int? pct = null) =>
            StateChanged?.Invoke(this, new TorStateChangedEventArgs { State = state, Message = msg, BootstrapPercent = pct });

        public void Dispose()
        {
            _stopping = true;
            _disposing = true;
            try { try { _proc?.CancelOutputRead(); } catch { } try { _proc?.CancelErrorRead(); } catch { } } catch { }
            try { if (_proc != null && !SafeHasExited(_proc)) _proc.Kill(); } catch { }
            try { _proc?.Dispose(); } catch { }
            _proc = null;
            CloseJob();
        }

        // Last-resort kill used by stop verification: instant, no waits.
        // The normal StopAsync path already killed the daemon; this makes
        // sure nothing lingers to hold ports or circuits after quit.
        public void ForceKill()
        {
            _stopping = true;
            _disposing = true;
            try
            {
                var p = _proc;
                _proc = null;
                try { if (p != null) { try { p.CancelOutputRead(); } catch { } try { p.CancelErrorRead(); } catch { } } } catch { }
                try { if (p != null && !SafeHasExited(p)) p.Kill(); } catch { }
                try { p?.Dispose(); } catch { }
                CloseJob();
                try
                {
                    System.Threading.Tasks.Task.Run(() =>
                    {
                        try { KillOursSweep(); } catch { }
                        try { KillPortOwners(); } catch { }
                    });
                }
                catch { }
                RaiseState(TorState.Stopped, "Tor force-stopped.");
            }
            catch { }
            // NOTE: flags stay true (see StopAsync) — next Start clears.
        }
    }
}
