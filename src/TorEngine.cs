using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{

    public class TorEngine : IAsyncDisposable
    {
        readonly string _appDir;
        readonly TorProcessManager _proc;
        readonly HttpToSocksBridge _bridge;
        readonly SocksRelay _socksRelay;
        readonly SystemProxyManager _proxy = new();
        readonly UserEnvManager _env = new();
        readonly SystemDnsManager _dnsMgr = new();
        DnsForwarder? _dnsFwd;
        DivertEnforcement? _divert;

        BridgeConfig _bridges = BridgeConfig.DirectOnly();
        bool _stableConnection;
        // Circuit pin (anti IP-hop): when true, torrc pins Entry/Middle/Exit
        // with StrictNodes 1 + huge MaxCircuitDirtiness, and ALL competing
        // settings (stable dirtiness, custom dirtiness, geo ExitNodes,
        // scheduled rotation, manual New ID, link-tick refresh) are forced
        // off in StartAsync / SetRotationInterval / RotateNowAsync /
        // LinkTickCore below. Set once per StartAsync from the caller's pin
        // args; read by the rotation gates for the whole run.
        bool _pinnedCircuitActive;
        // Strict lockdown requirement for THIS run (mirrors
        // EnforceTorOnly || BlockWebRtc from settings, synced by the UI
        // before every start/rescue). When true, routing must never sit
        // without the packet filter: starts enable it inline (same gate,
        // no UI round-trip window), link ticks auto re-enable + re-assert
        // proxy/env/DNS instead of warn-only. Proxy-only users (false)
        // keep the old warn-only behavior. Volatile: set under gate by
        // starts, read lock-free by link ticks.
        public volatile bool LockdownRequired;
        DateTime _lastEnforceRepairUtc = DateTime.MinValue;
        ResolvedBridges? _lastResolved;
        readonly BridgeHealthStore _bridgeHealth = new(BridgeHealthStore.DefaultPath());
        readonly Dictionary<int, DateTime> _ptKnown = new();
        readonly object _ptGate = new();
        static readonly HashSet<string> TransportExeNames = new(StringComparer.OrdinalIgnoreCase)
            { "lyrebird.exe", "conjure-client.exe", "snowflake-client.exe" };

        public bool PinnedCircuitActive => _pinnedCircuitActive;

        // Secret-diagnostics surface (read-only snapshots for DebugWindow).
        // All never-throw; pool-thread safe.
        public int? EngineTorPid
        {
            get { try { return _proc.CurrentPid; } catch { return null; } }
        }

        public List<string> ActiveBridgeLines
        {
            get
            {
                try { return _lastResolved?.UseBridges == true ? new List<string>(_lastResolved.BridgeLines) : new List<string>(); }
                catch { return new List<string>(); }
            }
        }

        public (List<string> entry, List<string> middle, List<string> exit) ActivePinLists
        {
            get
            {
                try
                {
                    return (new List<string>(_proc.PinnedEntryNodes ?? new List<string>()),
                        new List<string>(_proc.PinnedMiddleNodes ?? new List<string>()),
                        new List<string>(_proc.PinnedExitNodes ?? new List<string>()));
                }
                catch { return (new List<string>(), new List<string>(), new List<string>()); }
            }
        }

        public int PinDegradedLadders { get { try { return _pinDegradedLadders; } catch { return 0; } } }
        public int LinkFailsCount { get { try { return _linkFails; } catch { return 0; } } }
        public long EnforceAllowed { get { try { var d = _divert; return d != null ? d.Allowed : 0; } catch { return 0; } } }
        public long EnforceDropped { get { try { var d = _divert; return d != null ? d.Dropped : 0; } catch { return 0; } } }

        public (bool proxy, bool env, bool dns, bool enforcement, bool degraded) GetRoutingChecks()
        {
            try
            {
                var div = _divert;
                var enf = div != null && div.Running;
                var deg = div != null && div.Running && div.Degraded;
                bool dns;
                try { dns = !enf || _dnsMgr.MatchesApplied(); } catch { dns = false; }
                return (_proxy.MatchesApplied(), _env.MatchesApplied(), dns, enf, deg);
            }
            catch { return (false, false, false, false, false); }
        }

        public async Task<int> GetBootstrapPercentAsync()
        {
            try
            {
                var c = _control;
                if (c == null) return -1;
                return await c.GetBootstrapPercentAsync();
            }
            catch { return -1; }
        }

        // torrc key lines with bridge secrets truncated (fingerprint/cert
        // material never leaves the panel in full).
        public List<string> GetTorrcProofLines()
        {
            var out_ = new List<string>();
            try
            {
                var path = System.IO.Path.Combine(_appDir, "tordata", "torrc.generated");
                // Capped: never slurp blindly (a runaway file must not OOM us).
                var text = SafeFiles.ReadAllTextCapped(path, 1024 * 1024);
                if (text == null) { out_.Add("(torrc unreadable — missing, locked, or oversized)"); return out_; }
                foreach (var raw in text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
                {
                    var line = (raw ?? "").Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;
                    if (line.StartsWith("Bridge ", StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = line.Split(new[] { ' ' }, 3, StringSplitOptions.RemoveEmptyEntries);
                        var short_ = parts.Length >= 2 ? parts[0] + " " + parts[1] : line;
                        out_.Add(short_ + " […credentials truncated]");
                    }
                    else out_.Add(line);
                }
            }
            catch (Exception ex) { out_.Add("(torrc unreadable: " + ex.GetType().Name + ")"); }
            return out_;
        }

        // The entry-proof verdict: with IP-pinned transports (obfs4/vanilla)
        // every non-loopback socket tor holds MUST be a listed bridge IP —
        // anything else is a bypass. Snowflake/dynamic transports dial
        // broker-chosen peers, so the subset check is n/a there by design.
        public async Task<string> BuildDebugReportAsync()
        {
            var sb = new System.Text.StringBuilder();
            try
            {
                sb.AppendLine("=== PTor proof panel — " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " ===");
                sb.AppendLine("routing=" + (RoutingActive ? "ON" : "OFF")
                    + "  lockdown-required=" + (LockdownRequired ? "yes" : "no")
                    + "  enforcement=" + (EnforcementActive ? (EnforcementDegraded ? "DEGRADED(held, drops)" : "ON") : "OFF")
                    + $"  filter[allowed={EnforceAllowed} dropped={EnforceDropped}]");
                var chk = GetRoutingChecks();
                sb.AppendLine($"checks: proxy={(chk.proxy ? "ok" : "DIVERGED")} env={(chk.env ? "ok" : "DIVERGED")} dns={(chk.dns ? "ok" : "DIVERGED")}");
                sb.AppendLine("entry: " + (_lastResolved?.UseBridges == true ? _lastResolved.Label : "direct guards"));
                foreach (var bl in ActiveBridgeLines)
                    sb.AppendLine("  bridge: " + BridgeHealthStore.ShortName(bl));
                var pins = ActivePinLists;
                sb.AppendLine("pin: " + (_pinnedCircuitActive
                    ? ("ON [" + PinAutoRecovery.FormatPins(pins.entry, pins.middle, pins.exit) + "]"
                        + " effective-for-rescue=" + (IsEffectivePinForRescue() ? "yes" : "no")
                        + $" degraded-ladders={PinDegradedLadders} had-success={HadLinkSuccessThisRun}")
                    : "off"));
                sb.AppendLine($"link: fails-in-ladder={LinkFailsCount} status={TorLinkStatus} exit={ExitLabel}");
                int pct = -1;
                try { pct = await GetBootstrapPercentAsync(); } catch { }
                sb.AppendLine("bootstrap(control)=" + (pct >= 0 ? pct + "%" : "unknown (control down)")
                    + "  tor-pid=" + (EngineTorPid?.ToString() ?? "none"));
                List<(int pid, string name, string exePath)> eng;
                try { eng = GetEnginePids(); } catch { eng = new List<(int, string, string)>(); }
                if (eng.Count == 0) sb.AppendLine("helpers: none alive");
                else foreach (var e in eng) sb.AppendLine($"helper: {e.name} pid={e.pid}");
                sb.AppendLine("--- tor sockets (non-loopback must be listed bridges) ---");
                var expected = ExpectedBridgeIps(ActiveBridgeLines);
                var attemptedRemotes = new List<string>();
                if (eng.Count == 0 && EngineTorPid == null)
                    sb.AppendLine("(tor not running — nothing to check)");
                else
                {
                    var pids = new List<(int pid, string name)>();
                    try
                    {
                        if (EngineTorPid != null) pids.Add((EngineTorPid.Value, "tor"));
                        foreach (var e in eng)
                            if (!pids.Exists(p => p.pid == e.pid)) pids.Add((e.pid, e.name));
                    }
                    catch { }
                    var allOk = true;
                    var checkedAny = false;
                    foreach (var (pid, name) in pids)
                    {
                        List<AppTrafficMonitor.RemoteEndpoint> rems;
                        try { rems = AppTrafficMonitor.SnapshotRemotes(pid); } catch { continue; }
                        var live = rems.Where(r => !r.Loopback).ToList();
                        if (live.Count == 0) { sb.AppendLine($"{name}[{pid}]: no non-loopback sockets"); continue; }
                        checkedAny = true;
                        foreach (var r in live)
                        {
                            var tag = $"{r.Ip}:{r.Port} ({r.State})";
                            attemptedRemotes.Add(tag);
                            bool ok = expected.Count > 0 && expected.Contains(r.Ip);
                            if (!ok) allOk = false;
                            sb.AppendLine($"{name}[{pid}]: {tag}" + (expected.Count == 0 ? "" : (ok ? "  [listed bridge]" : "  [NOT A LISTED BRIDGE]")));
                        }
                    }
                    if ((_lastResolved?.UseBridges == true) && UsesDynamicPeers(ActiveBridgeLines))
                        sb.AppendLine("verdict: n/a — this transport dials broker-chosen peers (Snowflake-style); listed-bridge subset check does not apply.");
                    else if (!checkedAny)
                        sb.AppendLine("verdict: n/a — no live non-loopback sockets to judge right now.");
                    else
                        sb.AppendLine("verdict: " + (allOk
                            ? "PASS — every tor socket goes to a listed bridge (entry proof holds)."
                            : "FAIL — tor holds sockets outside the listed bridges (see [NOT A LISTED BRIDGE] above)."));
                }
                sb.AppendLine("--- torrc (secrets truncated) ---");
                foreach (var l in GetTorrcProofLines()) sb.AppendLine(l);
            }
            catch (Exception ex)
            {
                try { sb.AppendLine("report issue: " + ex.Message); } catch { }
            }
            return sb.ToString();
        }

        // Literal IPs from bridge lines, minus documentation/test ranges
        // (Snowflake-style dummy 192.0.2.x entries must never count).
        static HashSet<string> ExpectedBridgeIps(List<string>? lines)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (lines == null) return set;
                foreach (var line in lines)
                {
                    try
                    {
                        var parts = (line ?? "").Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 2) continue;
                        var hostPort = parts[1].Trim();
                        string host = hostPort;
                        if (host.StartsWith("["))
                        {
                            var c = host.IndexOf(']');
                            if (c > 0) host = host.Substring(1, c - 1);
                        }
                        else if (host.IndexOf(':') == host.LastIndexOf(':') && host.Contains(':'))
                            host = host.Substring(0, host.IndexOf(':'));
                        host = host.Trim().Trim('.').ToLowerInvariant();
                        if (host.Length == 0) continue;
                        if (host.StartsWith("192.0.2.") || host.StartsWith("198.51.100.") || host.StartsWith("203.0.113."))
                            continue;
                        if (System.Net.IPAddress.TryParse(host, out _)) set.Add(host);
                    }
                    catch { }
                }
            }
            catch { }
            return set;
        }

        static bool UsesDynamicPeers(List<string>? lines)
        {
            try
            {
                if (lines == null || lines.Count == 0) return false;
                foreach (var line in lines)
                {
                    var t = BridgeConfigEngine.TransportOfLine(line ?? "");
                    if (string.Equals(t, "snowflake", StringComparison.OrdinalIgnoreCase)) return true;
                }
                // No literal IPs at all (meek-style / dummy entries only):
                // nothing pinnable, same n/a verdict.
                return ExpectedBridgeIps(lines).Count == 0;
            }
            catch { return false; }
        }
        public string PtToolsDir => Path.Combine(_appDir, "tools", "tor", "pluggable_transports");
        public string BridgeLabel => _lastResolved?.UseBridges == true ? _lastResolved.Label : "direct";

        public (bool hasFile, int obfs4, int snowflake) BridgeDefaultsInfo()
        {
            try
            {
                var d = BridgeConfigEngine.LoadDefaults(Path.Combine(PtToolsDir, "pt_config.json"));
                if (d == null) return (false, 0, 0);
                d.Bridges.TryGetValue("obfs4", out var o);
                d.Bridges.TryGetValue("snowflake", out var s);
                return (true, o?.Count ?? 0, s?.Count ?? 0);
            }
            catch { return (false, 0, 0); }
        }

        public string BridgeStatus
        {
            get
            {
                try
                {
                    var (has, o, s) = BridgeDefaultsInfo();
                    var active = RoutingActive ? $"active entry: {BridgeLabel}" : "tor not running";
                    var ptCount = GetTransportPids().Count;
                    return $"Bridges: {active} · transport processes: {ptCount} · bundled defaults: " +
                        (has ? $"obfs4×{o}, snowflake×{s}" : "missing (paste custom lines)") +
                        ". Mode changes take effect on next Tor start.";
                }
                catch { return "Bridges: unknown."; }
            }
        }

        TorControlClient? _control;
        TorMaintenance? _maintenance;

        int _reconnectAttempt;
        CancellationTokenSource? _lifetimeCts;

        readonly SemaphoreSlim _lifecycleGate = new(1, 1);

        const uint ES_CONTINUOUS = 0x80000000;
        const uint ES_SYSTEM_REQUIRED = 0x00000001;

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        static extern uint SetThreadExecutionState(uint esFlags);

        static void PreventSleep(bool on)
        {
            try
            {
                SetThreadExecutionState(on ? ES_CONTINUOUS | ES_SYSTEM_REQUIRED : ES_CONTINUOUS);
            }
            catch { }
        }

        const string LinkCheckUrl = "https://check.torproject.org/api/ip";
        const int LinkCheckPeriodSec = 30;
        const int LinkCheckTimeoutSec = 20;
        const int LinkFailThreshold = 3;
        Timer? _linkTimer;
        HttpClient? _linkClient;
        int _linkBusy;
        int _linkFails;
        int _linkGen;
        int _softRecoverStreak;
        DateTime _lastLinkOkUtc = DateTime.MinValue;

        // Pin self-healing (runtime half): counts consecutive degraded
        // link ladders while the circuit pin is active. Reset on any
        // successful link check. When it reaches
        // PinAutoRecovery.RuntimeRescueLadders the engine fires
        // PinRescueNeeded instead of looping a same-pin restart forever.
        // The UI owns settings + restarts, so the engine only signals.
        int _pinDegradedLadders;
        volatile int _pinRescueSignalInFlight;
        // Per-run data-path proof: true once ANY end-to-end stream has
        // succeeded since the current RoutingActive began (link tick,
        // resume probe, or pinned post-bootstrap probe). Reset on every
        // start AND every stop — _lastLinkOkUtc is deliberately NOT used
        // here because it survives restarts and would let a previous run's
        // success green-light an instant rescue on the new (still cold)
        // run. Consulted via PinAutoRecovery.ShouldAllowRuntimeRescue
        // before any PinRescueNeeded signal so slow boots can never wipe
        // a healthy pin.
        bool _hadLinkSuccessThisRun;
        public bool HadLinkSuccessThisRun => Volatile.Read(ref _hadLinkSuccessThisRun);
        // Effective pin for THIS run (bridge-aware twin of
        // BootstrapPinActive, exposed so the UI never rescues on a run
        // whose pin cannot be the cause — e.g. settings saved pinned but
        // the live run started unpinned, or entry-only pin under bridges).
        public bool IsEffectivePinForRescue()
        {
            try { return RuntimePinEffective(); }
            catch { return false; }
        }

        public int SocksPort { get; }
        public int ControlPort { get; }
        public int BridgePort { get; }
        public int DnsPort { get; }

        public int RelayPort { get; }

        public bool RoutingActive { get; private set; }

        public bool IsTorRunning
        {
            get { try { return _proc.IsRunning; } catch { return false; } }
        }

        public DateTime? RoutingStartedUtc { get; private set; }

        public event EventHandler<TorStateChangedEventArgs>? StateChanged;
        public event EventHandler<string>? LogMessage;

        public event EventHandler<RelayEventArgs>? TrafficRelayed;

        // Fired (pool thread, fire-and-forget, never throws) when the data
        // path is dead while the circuit pin is active and the pin is the
        // prime suspect: bootstrap callers get a PinSuspectBootstrapException
        // instead, but an already-bootstrapped run can only signal. The UI
        // performs the actual unpin -> restart -> re-pin rescue (it owns
        // settings + the lifecycle gate). Single-flight per degraded
        // episode: the flag resets on the next successful link check.
        public event EventHandler<PinRescueNeededEventArgs>? PinRescueNeeded;

        public TorEngine(string appDir, int socksPort = 9050, int controlPort = 9051, int bridgePort = 9080, int relayPort = 9060, int dnsPort = 9053)
        {
            _appDir = appDir;
            SocksPort = socksPort;
            ControlPort = controlPort;
            BridgePort = bridgePort;
            RelayPort = relayPort;
            DnsPort = dnsPort;

            _proc = new TorProcessManager(appDir, socksPort, controlPort, dnsPort);
            _proc.StateChanged += (_, e) =>
            {
                // tor's stdout ALSO announces bootstrap % ("Bootstrapped
                // 100%"): capture it so the readiness gate can complete on
                // whichever signal arrives first (stdout event or control
                // poll) instead of polling alone.
                try { if ((e.BootstrapPercent ?? -1) >= 100) Volatile.Write(ref _stdoutBootstrapped, 1); } catch { }
                try { StateChanged?.Invoke(this, e); } catch { }
            };
            _proc.UnexpectedExit += async (_, __) => await HandleUnexpectedExit();

            _bridge = new HttpToSocksBridge("127.0.0.1", socksPort, bridgePort);
            _bridge.Relayed += (_, e) =>
            {
                try { TrafficRelayed?.Invoke(this, e); } catch { }
            };
            // Live blocklist feed: the delegate reads the volatile snapshot,
            // so Config edits apply to proxied traffic instantly (no restart).
            _bridge.BlockedDomainsProvider = () => _blockedSnapshot;

            _socksRelay = new SocksRelay("127.0.0.1", socksPort, relayPort);
            _socksRelay.Relayed += (_, e) =>
            {
                try { TrafficRelayed?.Invoke(this, e); } catch { }
            };
            _socksRelay.BlockedDomainsProvider = () => _blockedSnapshot;
        }

        // Start generation: bumped once per logical start (UI BeginStart or
        // ForceRetry entry — NEVER inside StartAsync itself, which a retry
        // also funnels through). Lets a superseded in-flight start stand
        // down silently instead of tearing down the UI under its successor.
        volatile int _startGeneration;

        public int CurrentStartGeneration => Volatile.Read(ref _startGeneration);

        public int BeginStart() => Interlocked.Increment(ref _startGeneration);

        // Barbaric unstick for a wedged boot: cancel whatever is in flight,
        // kill OUR tor + helpers (verified), tear down lockdown ONLY if it
        // is ours-and-live in this run (a foreign WinDivert driver — another
        // app may have booted it first — is never touched), run a full
        // serialized stop, then a clean start with the given (current UI)
        // settings. Takes NO gate itself (Stop/Start acquire it in turn, so
        // no reentrancy deadlock); never throws, reports every step.
        public async Task<string> ForceRetryAsync(
            int rotateEverySec,
            BridgeConfig? bridges = null,
            bool stableConnection = false,
            List<string>? exitCountries = null,
            int maxCircuitDirtinessSec = 600,
            int circuitStreamTimeoutSec = 0,
            bool restrictiveFirewall = false,
            bool pinnedCircuitEnabled = false,
            List<string>? pinnedEntryNodes = null,
            List<string>? pinnedMiddleNodes = null,
            List<string>? pinnedExitNodes = null,
            bool requireLockdown = false)
        {
            Interlocked.Increment(ref _startGeneration);
            var parts = new List<string>();
            void Add(string s) { try { parts.Add(s); } catch { } }
            try
            {
                try { _lifetimeCts?.Cancel(); } catch { }
                Add("stuck start cancelled");
                try
                {
                    _proc.MadmanKillTor();
                    Add("tor kill fired (instant, stragglers reaped detached)");
                }
                catch (Exception ex) { Add("tor kill issue: " + ex.Message); }
                // NOTE: no direct DisableEnforcementCore() here (it requires
                // gate + enforce-lock; calling it lock-free raced gated
                // Enable/Disable/Stop on _divert/_dnsFwd + checkpoint).
                // StopAsync below tears enforcement down under the gate.
                try { await StopAsync(); Add("stopped clean"); }
                catch (Exception ex) { Add("stop issue: " + ex.Message); }
                try
                {
                    await StartAsync(rotateEverySec, bridges, stableConnection,
                        exitCountries, maxCircuitDirtinessSec, circuitStreamTimeoutSec,
                        restrictiveFirewall, pinnedCircuitEnabled,
                        pinnedEntryNodes, pinnedMiddleNodes, pinnedExitNodes, requireLockdown);
                    Add(RoutingActive
                        ? "tor rebootstrapping with current settings"
                        : "start finished but routing is off — see status");
                }
                catch (OperationCanceledException) { Add("restart cancelled (stop requested)"); }
                catch (Exception ex) { Add("restart failed: " + ex.Message); }
            }
            catch (Exception ex) { Add("force retry issue: " + ex.Message); }
            return string.Join(" ", parts.ToArray());
        }

        // Shared path/pin/lockdown field update for StartAsync AND
        // RestartTorOnlyAsync (single choke point so the two can never
        // drift: same sanitize, same pin override, same torrc fields).
        // Gate held by caller. Returns the effective rotation interval.
        // Never throws (field writes only; logging best-effort).
        int ApplyPathSettings(
            int rotateEverySec,
            BridgeConfig? bridges,
            bool stableConnection,
            List<string>? exitCountries,
            int maxCircuitDirtinessSec,
            int circuitStreamTimeoutSec,
            bool restrictiveFirewall,
            bool pinnedCircuitEnabled,
            List<string>? pinnedEntryNodes,
            List<string>? pinnedMiddleNodes,
            List<string>? pinnedExitNodes,
            bool requireLockdown)
        {
            try { _bridges = bridges ?? BridgeConfig.DirectOnly(); } catch { }
            try { _stableConnection = stableConnection; } catch { }
            try { LockdownRequired = requireLockdown; } catch { }
            // PIN OVERRIDE (single choke point): sanitize once here, then
            // force every competing setting below. torrc itself re-checks
            // in BuildTorrcContent, so even a caller that forgot to clear
            // ExitCountries/dirtiness still gets pin-only output.
            List<string> pinEntry = new();
            List<string> pinMiddle = new();
            List<string> pinExit = new();
            try
            {
                pinEntry = TorProcessManager.SanitizePinnedNodes(pinnedEntryNodes);
                pinMiddle = TorProcessManager.SanitizePinnedNodes(pinnedMiddleNodes);
                pinExit = TorProcessManager.SanitizePinnedNodes(pinnedExitNodes);
            }
            catch { }
            var pinActive = pinnedCircuitEnabled && (pinEntry.Count + pinMiddle.Count + pinExit.Count) > 0;
            try { _pinnedCircuitActive = pinActive; } catch { }
            // PIN + STABLE OVERRIDE: scheduled rotation rebuilds circuits
            // on a timer — exactly the IP-hop both modes exist to
            // prevent. Forced off for the whole run (the user's value
            // survives in the UI box + SetRotateIntervalCache and applies
            // again on plain runs).
            int effectiveRotateSec = (pinActive || stableConnection) ? 0 : rotateEverySec;
            try
            {
                if (pinActive)
                {
                    _proc.MaxCircuitDirtinessSec = TorProcessManager.PinnedCircuitDirtinessSec;
                    _proc.ExitCountries = new List<string>();
                }
                else
                {
                    _proc.MaxCircuitDirtinessSec = stableConnection
                        ? 86400
                        : TorProcessManager.SanitizeDirtinessSec(maxCircuitDirtinessSec);
                    _proc.ExitCountries = exitCountries ?? new List<string>();
                }
                _proc.CircuitStreamTimeoutSec =
                    TorProcessManager.SanitizeStreamTimeoutSec(circuitStreamTimeoutSec);
                _proc.FascistFirewallOnly = restrictiveFirewall;
                _proc.PinnedCircuitEnabled = pinnedCircuitEnabled;
                _proc.PinnedEntryNodes = pinEntry;
                _proc.PinnedMiddleNodes = pinMiddle;
                _proc.PinnedExitNodes = pinExit;
            }
            catch { }
            try
            {
                if (pinActive)
                {
                    LogMessage?.Invoke(this,
                        "Circuit pin ON: path pinned to " +
                        (pinEntry.Count > 0 ? "entry " + string.Join(",", pinEntry) + " " : "") +
                        (pinMiddle.Count > 0 ? "middle " + string.Join(",", pinMiddle) + " " : "") +
                        (pinExit.Count > 0 ? "exit " + string.Join(",", pinExit) + " " : "") +
                        "(StrictNodes 1, MaxCircuitDirtiness 999999999). " +
                        "Overrides: stable mode, circuit lifetime, exit geography, scheduled + manual rotation.");
                    if ((_bridges.Mode != BridgeMode.Direct) && pinEntry.Count > 0)
                        LogMessage?.Invoke(this,
                            "Note: bridges are in use — Tor ignores EntryNodes while bridging, so the entry pin is inactive until direct guards return; middle/exit pins still apply.");
                    if (rotateEverySec > 0)
                        LogMessage?.Invoke(this,
                            "Scheduled rotation forced OFF by circuit pin (was " + rotateEverySec + "s).");
                    if (stableConnection || (exitCountries?.Count ?? 0) > 0 || maxCircuitDirtinessSec != 600)
                        LogMessage?.Invoke(this,
                            "Stable / lifetime / geography settings are saved but overridden by circuit pin for this run.");
                }
                else
                {
                    if (pinnedCircuitEnabled)
                        LogMessage?.Invoke(this,
                            "Circuit pin is ON but no valid entry/middle/exit node was listed — pin inactive for this run (normal path in use). Add a fingerprint or nickname.");
                    if (stableConnection)
                        LogMessage?.Invoke(this, "Stable connection mode: exits hop as rarely as possible (no scheduled rotation)." +
                            (rotateEverySec > 0 ? $" Scheduled rotation forced OFF by stable mode (was {rotateEverySec}s)." : ""));
                    else if ((_proc.ExitCountries?.Count ?? 0) > 0)
                    {
                        LogMessage?.Invoke(this,
                            "Entry/exit path: exit preference: " + string.Join(",", _proc.ExitCountries) + " (fallback: any).");
                    }
                }
            }
            catch { }
            return effectiveRotateSec;
        }

        public async Task StartAsync(
            int rotateEverySec,
            BridgeConfig? bridges = null,
            bool stableConnection = false,
            List<string>? exitCountries = null,
            int maxCircuitDirtinessSec = 600,
            int circuitStreamTimeoutSec = 0,
            bool restrictiveFirewall = false,
            bool pinnedCircuitEnabled = false,
            List<string>? pinnedEntryNodes = null,
            List<string>? pinnedMiddleNodes = null,
            List<string>? pinnedExitNodes = null,
            bool requireLockdown = false)
        {
            await _lifecycleGate.WaitAsync();
            try
            {
                int effectiveRotateSec = ApplyPathSettings(rotateEverySec, bridges, stableConnection,
                    exitCountries, maxCircuitDirtinessSec, circuitStreamTimeoutSec,
                    restrictiveFirewall, pinnedCircuitEnabled,
                    pinnedEntryNodes, pinnedMiddleNodes, pinnedExitNodes, requireLockdown);
                await StartCoreAsync(effectiveRotateSec);
            }
            finally
            {
                _lifecycleGate.Release();
            }
        }

        // Fail-closed tor restart for pin auto-recovery (and any future
        // torrc-change path): restarts ONLY the tor daemon + control +
        // maintenance, preserving proxy/env/DNS/divert/relays and keeping
        // RoutingActive true throughout. While tor is down proxy-aware apps
        // get 502s and the packet filter drops the rest — never direct.
        // This is what makes the unpinned probe + re-pin safe: the old
        // StopAsync/StartAsync chain restored direct internet mid-rescue
        // (proxy + DNS back to ISP = DNS + direct leak window). Requires
        // routing to be ON (fail-closed rescue only; cold starts still use
        // StartAsync). On daemon failure tor stays dead + routing stays ON
        // (fail-closed) and the exception propagates — the caller decides
        // (rescue falls back tor-only again, never via direct). Gate-held.
        public async Task RestartTorOnlyAsync(
            int rotateEverySec,
            BridgeConfig? bridges = null,
            bool stableConnection = false,
            List<string>? exitCountries = null,
            int maxCircuitDirtinessSec = 600,
            int circuitStreamTimeoutSec = 0,
            bool restrictiveFirewall = false,
            bool pinnedCircuitEnabled = false,
            List<string>? pinnedEntryNodes = null,
            List<string>? pinnedMiddleNodes = null,
            List<string>? pinnedExitNodes = null,
            bool requireLockdown = false)
        {
            await _lifecycleGate.WaitAsync();
            try
            {
                if (!RoutingActive)
                    throw new InvalidOperationException("Tor-only restart needs routing ON (use StartAsync for cold starts).");
                int effectiveRotateSec = ApplyPathSettings(rotateEverySec, bridges, stableConnection,
                    exitCountries, maxCircuitDirtinessSec, circuitStreamTimeoutSec,
                    restrictiveFirewall, pinnedCircuitEnabled,
                    pinnedEntryNodes, pinnedMiddleNodes, pinnedExitNodes, requireLockdown);
                // Fresh lifetime for the new daemon, but routing stays ON:
                // park link ticks via _reconnectAttempt (same shape as the
                // reconnect path) so the cold tor isn't judged mid-bootstrap.
                try { _lifetimeCts?.Dispose(); } catch { }
                _lifetimeCts = new CancellationTokenSource();
                Interlocked.Increment(ref _runSeq);
                Volatile.Write(ref _stdoutBootstrapped, 0);
                _pinDegradedLadders = 0;
                Volatile.Write(ref _pinRescueSignalInFlight, 0);
                Volatile.Write(ref _hadLinkSuccessThisRun, false);
                _linkFails = 0;
                _softRecoverStreak = 0;
                _lastRotationCompletedUtc = DateTime.MinValue;
                _reconnectAttempt = 1;
                _reconnecting = false;
                PreventSleep(true);
                try
                {
                    try { _maintenance?.Dispose(); } catch { }
                    _maintenance = null;
                    try { _control?.Dispose(); } catch { }
                    _control = null;
                    try { _proc.ClearLogTail(); } catch { }
                    if (_proc.IsRunning) { try { await _proc.StopAsync(); } catch { } }
                    PtDefaults? bridgeDefaults = null;
                    try
                    {
                        bridgeDefaults = BridgeConfigEngine.LoadDefaults(
                            Path.Combine(_appDir, "tools", "tor", "pluggable_transports", "pt_config.json"));
                    }
                    catch { }
                    // Daemon start only (mirrors StartCoreInnerAsync tiers,
                    // minus proxy: relays stay bound, proxy/env/DNS/divert
                    // untouched). No StopCore rollback here — that would
                    // restore direct. On failure tor stays dead, routing
                    // stays ON (fail-closed), caller retries tor-only.
                    if (_bridges.Mode == BridgeMode.Direct)
                    {
                        var direct = BridgeConfigEngine.Resolve(BridgeConfig.DirectOnly(), PtToolsDir, bridgeDefaults);
                        _proc.Start(null);
                        _lastResolved = direct;
                        StartRelays();
                        await WaitForBootstrapAndConnectControl(40);
                        await WaitForBootstrapCompleteAsync(180, "direct guards", 60, BootstrapPinActive());
                    }
                    else if (_bridges.Mode == BridgeMode.Auto)
                    {
                        await StartAutoTierAsync(bridgeDefaults);
                    }
                    else
                    {
                        ResolvedBridges resolved;
                        try { resolved = ResolveExplicitBridges(bridgeDefaults); }
                        catch (Exception ex) { throw new InvalidOperationException("Bridge configuration failed: " + ex.Message, ex); }
                        if (!resolved.UseBridges)
                            throw new InvalidOperationException("Bridge mode '" + _bridges.Mode + "' is unusable: " +
                                string.Join(" ", resolved.Errors) + " Tor was NOT started.");
                        LogMessage?.Invoke(this, $"Routing entry via {resolved.Label} ({resolved.BridgeLines.Count} bridge(s)).");
                        await StartWithBridgeFallbackAsync(resolved);
                    }
                    if (BootstrapPinActive())
                        await VerifyPinnedDataPathAsync();
                    try { _maintenance?.Dispose(); } catch { }
                    _maintenance = new TorMaintenance(_control!) { RotateIntervalSec = effectiveRotateSec, KeepAliveIntervalSec = LinkCheckPeriodSec };
                    if (!_pinnedCircuitActive && !_stableConnection) SetRotateIntervalCache = rotateEverySec;
                    _maintenance.Died += async (_, __) => await HandleUnexpectedExit();
                    _maintenance.RotationRequested += (_, msg) => LogMessage?.Invoke(this, msg);
                    _maintenance.RotationCompleted += (_, ok) => OnRotationCompleted(ok);
                    _maintenance.Start();
                    try { RecreateLinkClient(); } catch { }
                    _lastRotationCompletedUtc = DateTime.MinValue;
                    RoutingStartedUtc = DateTime.UtcNow;
                    _reconnectAttempt = 0;
                }
                catch
                {
                    // Stay fail-closed (routing ON, tor dead) but unpark the
                    // link ladder so it keeps judging (and can re-signal
                    // after the UI cooldown instead of wedging parked).
                    try { _reconnectAttempt = 0; } catch { }
                    try { RecreateLinkClient(); } catch { }
                    throw;
                }
                finally
                {
                    PreventSleep(false);
                }
            }
            finally
            {
                _lifecycleGate.Release();
            }
        }

        public async Task StopAsync()
        {
            // Cancel BEFORE waiting the gate: a start stuck in a long
            // bootstrap (bridge tiers!) observes this while we wait and
            // aborts, instead of Stop hanging behind it indefinitely.
            try { _lifetimeCts?.Cancel(); } catch { }
            var gateSw = Stopwatch.StartNew();
            ExitTrace.Log("engine stop: waiting gate");
            await _lifecycleGate.WaitAsync();
            ExitTrace.Log("engine stop: gate acquired in " + gateSw.ElapsedMilliseconds + "ms");
            try
            {
                await StopCoreAsync();
                ExitTrace.Log("engine stop: core done");
            }
            finally
            {
                _lifecycleGate.Release();
            }
        }

        // Fast exit teardown: restore every shared system setting, then the
        // caller kills the process. Used ONLY by exit/restart paths (the app
        // keeps running through toggle-off/update, which use StopAsync).
        // INSTANT by design — order is the whole strategy:
        //  1. tor killed FIRST (no waits at all): from that millisecond on
        //     there can be no orphan — even if WE die mid-restore, tor is
        //     already dead. Apps losing circuits here is intended.
        //  2. proxy/DNS/env registry writes (~milliseconds); once restored,
        //     direct internet works again immediately.
        //  3. divert handle closed (instant, no Join): traffic goes normal
        //     instantly. Handover restarts (handover: true) KEEP our driver
        //     service + checkpoint for the takeover successor (no reinstall,
        //     no foreign-touch); anything else kills OUR service synchronously
        //     (bounded 3s — SCM can wedge, so never unbounded).
        // No gate wait: restores are idempotent, and waiting 2s for an
        // in-flight start violates instant-exit. ExitMarker blocks fresh
        // starts during teardown instead.
        public string FastTeardownForExit(bool handover = false)
        {
            var notes = new List<string>();
            void Note(string s) { try { notes.Add(s); } catch { } }
            var sw = Stopwatch.StartNew();
            // FIRST: plant the exit marker so any fresh non-takeover launch
            // during the teardown below dies silently instead of auto-starting
            // a new tor into the mess (the orphan + stranded-proxy bug).
            try { ExitMarker.Write(); } catch { }
            try { _lifetimeCts?.Cancel(); } catch { }
            // A start holds ES_SYSTEM_REQUIRED while bootstrapping; dying
            // without clearing it would forbid sleep until reboot.
            try { PreventSleep(false); } catch { }
            // Stop timers/relays/control first so nothing re-dials tor while
            // we kill it, and loopback ports free promptly for a takeover.
            // All fire-and-forget and idempotent; never throws.
            try { StopLinkChecks(); } catch { }
            try { _maintenance?.Dispose(); } catch { }
            _maintenance = null;
            try { _control?.Dispose(); } catch { }
            _control = null;
            try { _bridge.Dispose(); } catch { }
            try { _socksRelay.Dispose(); } catch { }
            try { _dnsFwd?.Dispose(); } catch { }
            _dnsFwd = null;
            // Kill FIRST: every millisecond tor lives after Exit is a
            // potential orphan. No waits — SIGKILL + job-close land in ms,
            // sweeps run detached inside MadmanKillTor.
            try
            {
                _proc.MadmanKillTor();
                try { ExitTrace.Log($"exit teardown: tor kill done in {sw.ElapsedMilliseconds}ms"); } catch { }
                Note("tor killed");
            }
            catch (Exception ex) { Note("tor kill issue: " + ex.Message); }
            // No gate wait (instant exit): restore immediately. If a start
            // holds the gate, we restore anyway — restores are idempotent
            // and the marker blocks fresh starts; next-start repair covers
            // any residual race.
            bool gateTaken = false;
            try { gateTaken = _lifecycleGate.Wait(TimeSpan.Zero); } catch { gateTaken = false; }
            try
            {
                try { ExitTrace.Log($"exit teardown: gate {(gateTaken ? "taken" : "skipped")} at {sw.ElapsedMilliseconds}ms"); } catch { }
                RestoreAndVerify(notes, handover);
                try { ExitTrace.Log($"exit teardown: restore done at {sw.ElapsedMilliseconds}ms"); } catch { }
            }
            finally { if (gateTaken) { try { _lifecycleGate.Release(); } catch { } } }
            return string.Join(" ", notes.ToArray());
        }

        // Barbaric quit teardown: the ONLY path used when quitting the app.
        // Fully SYNCHRONOUS — zero await, zero Wait, zero gate wait, zero
        // process-table enumeration, zero verify reads. Every step below is
        // millisecond-scale by construction (verified at each callee):
        // relay/control/timer disposes cancel + close with no joins,
        // MadmanKillTor SIGKILLs with no waits (sweeps detached),
        // DivertEnforcement.Dispose closes the handle with no join, OUR
        // driver service is stopped + deleted synchronously (bounded 3s),
        // and proxy/DNS/env restores are registry writes (FlushDns is
        // fire-and-forget by design).
        // Order is the whole strategy, exactly as requested:
        //   1. tor.exe killed FIRST — from that millisecond on there can be
        //      no orphan, even if WE die mid-restore (apps losing circuits
        //      here is intended).
        //   2. windivert handle closed — traffic goes normal instantly —
        //      then OUR driver service stopped + deleted SYNCHRONOUSLY
        //      (bounded 3s): the old detached removal usually died with the
        //      process and orphaned our privileged service. A handover
        //      restart (handover: true) skips the delete and keeps the
        //      checkpoint: the takeover successor reuses the live service
        //      instead of reinstalling (it refuses foreign drivers anyway).
        //   3. internet recovered — proxy, then DNS, then env.
        // Runs on the UI thread; returns in milliseconds when healthy.
        // Never throws. (The old bounded async teardown stays for restart
        // handovers, which want its diagnostic report — quit never touches it.)
        public string BarbaricQuitTeardown(bool handover = false)
        {
            var notes = new List<string>();
            void Note(string s) { try { notes.Add(s); } catch { } }
            // FIRST: plant the exit marker so a fresh non-takeover launch
            // during the milliseconds below dies silently instead of
            // auto-starting a new tor into the mess.
            try { ExitMarker.Write(); } catch { }
            try { _lifetimeCts?.Cancel(); } catch { }
            // A start holds ES_SYSTEM_REQUIRED while bootstrapping; dying
            // without clearing it would forbid sleep until reboot.
            try { PreventSleep(false); } catch { }
            // Stop timers/relays/control so nothing re-dials tor while we
            // kill it. All instant, idempotent, never throws.
            try { StopLinkChecks(); } catch { }
            try { _maintenance?.Dispose(); } catch { }
            _maintenance = null;
            try { _control?.Dispose(); } catch { }
            _control = null;
            try { _bridge.Dispose(); } catch { }
            try { _socksRelay.Dispose(); } catch { }
            try { _dnsFwd?.Dispose(); } catch { }
            _dnsFwd = null;
            // 1. TOR FIRST: SIGKILL + job-close land in ms, sweeps detached.
            try { _proc.MadmanKillTor(); Note("tor killed"); }
            catch (Exception ex) { Note("tor kill issue: " + ex.Message); }
            // 2. WINDIVERT: our handle is ALWAYS closed here (whatever the
            // checkpoint says — the handle is ours by construction; leaving
            // it open would filter traffic into a dying process). Then the
            // service: synchronous bounded kill when ours, kept for handover.
            try { _divert?.Dispose(); } catch { }
            _divert = null;
            try
            {
                if (handover)
                    Note("lockdown off, driver service kept for the takeover successor (no reinstall needed).");
                else
                    RemoveOwnDriverServiceSync(notes);
            }
            catch { }
            // 3. INTERNET BACK: connectivity-first order — if the process
            // dies mid-restore, the most critical thing (browsers/system
            // HTTP via the proxy) is already back, then DNS, then env.
            // Env skips its WM_SETTINGCHANGE broadcast (up to 2s parked
            // behind hung windows) — the registry restore is what matters.
            try { Note(_proxy.Disable()); } catch (Exception ex) { Note("proxy restore issue: " + ex.Message); }
            try { Note(_dnsMgr.Disable()); } catch (Exception ex) { Note("DNS restore issue: " + ex.Message); }
            try { Note(_env.Disable(broadcast: false)); } catch (Exception ex) { Note("env restore issue: " + ex.Message); }
            // System state is back: the boot safety net has nothing to fix.
            try { BootRestore.Remove(); } catch { }
            return string.Join(" ", notes.ToArray());
        }

        // No gate, fully idempotent: every Disable below is a no-op when not
        // managed, so this is safe to run twice (race second-pass) and from
        // the last-resort sync restore. Shared by the exit teardown and
        // RestoreCriticalNow — one restore implementation, no drift.
        void RestoreAndVerify(List<string> notes, bool handover = false)
        {
            void Note(string s) { try { notes.Add(s); } catch { } }
            // Single instant pass: proxy/DNS/env are registry writes (ms),
            // divert handle close is instant, own-service removal is bounded.
            // No second pass — re-reading + re-restoring only adds exit
            // latency for a race the marker + next-start repair already cover.
            RestoreOnce(notes, handover);
            // A racing start may have relaunched tor after our first
            // kill: kill again now (instant, no waits).
            try
            {
                if (_proc.IsRunning) { _proc.KillTreeNow(); Note("tor re-killed"); }
            }
            catch (Exception ex) { Note("tor re-kill issue: " + ex.Message); }
            // Prove-it check, not a repair loop: read back everything a
            // browser needs for direct internet and say it out loud. If
            // this line ever shows leftovers, the trace names them.
            try { Note("verify: " + VerifyDirectState()); }
            catch (Exception ex) { Note("verify failed: " + ex.Message); }
        }

        // Last-resort synchronous restore, for the (should-be-impossible)
        // case where the bounded exit teardown timed out: idempotent
        // registry restores with no gate and no waits beyond the managers'
        // own bounded courtesies. Never throws. The UI calls this on the
        // timeout path BEFORE dying, so the user is never left offline.
        public string RestoreCriticalNow()
        {
            var notes = new List<string>();
            try { RestoreAndVerify(notes); }
            catch (Exception ex) { try { notes.Add("restore issue: " + ex.Message); } catch { } }
            return string.Join(" ", notes.ToArray());
        }

        // Runs a step with a hard timeout (SCM/driver calls can wedge
        // indefinitely on a sick system — that exact hang is what made
        // exits take forever, in BOTH the teardown and the timeout-path
        // final restore). Returns true when the step finished in time.
        // Never throws; a timed-out step keeps running detached on the pool
        // while the exit proceeds (its checkpoint/state lets the next start
        // or kill-windivert.bat finish the job).
        internal static bool RunBounded(Action? step, TimeSpan timeout)
        {
            try
            {
                if (step == null) return true;
                var t = Task.Run(step);
                var done = Task.WhenAny(t, Task.Delay(timeout)).GetAwaiter().GetResult();
                if (ReferenceEquals(done, t))
                {
                    try { t.GetAwaiter().GetResult(); } catch { }
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        void RestoreOnce(List<string> notes, bool handover = false)
        {
            void Note(string s) { try { notes.Add(s); } catch { } }
            // Order matches BarbaricQuitTeardown (divert/DNS first, then
            // proxy/env): if the process dies mid-restore, packet filtering
            // is already off so restored proxy/DNS take effect immediately.
            // Our handle is ALWAYS closed (it is ours by construction);
            // handover restarts keep the service + checkpoint for the
            // takeover successor, everything else kills OUR service
            // synchronously (bounded) so no privileged orphan is left.
            // DNS forwarder port first (frees :53 for the restored resolvers).
            try { _dnsFwd?.Dispose(); } catch { }
            _dnsFwd = null;
            try { _divert?.Dispose(); } catch { }
            _divert = null;
            try
            {
                if (handover)
                    Note("lockdown off, driver service kept for the takeover successor (no reinstall needed).");
                else
                    RemoveOwnDriverServiceSync(notes);
            }
            catch { }
            try { Note(_dnsMgr.Disable()); } catch (Exception ex) { Note("DNS restore issue: " + ex.Message); }
            try { Note(_proxy.Disable()); } catch (Exception ex) { Note("proxy restore issue: " + ex.Message); }
            try { Note(_env.Disable()); } catch (Exception ex) { Note("env restore issue: " + ex.Message); }
            // System state is back: the boot safety net has nothing to fix.
            try { BootRestore.Remove(); } catch { }
        }

        // Read-only proof that direct internet works again: proxy off and not
        // ours, no PAC override, no Tor env vars, DNS resolvers not ours.
        // Pure reads — safe to call anytime, including from the harness.
        public string VerifyDirectState()
        {
            var parts = new List<string>();
            try
            {
                var p = _proxy.GetSnapshot();
                parts.Add("proxy=" + (p.ManagedByPTor ? "STILL-MANAGED" :
                    (p.Enabled == 1 ? "on(" + (p.Server ?? "") + ")" : "off")));
                string? pac = null;
                try
                {
                    using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                        @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", writable: false);
                    pac = k?.GetValue("AutoConfigURL", null) as string;
                }
                catch { }
                parts.Add("pac=" + (string.IsNullOrEmpty(pac) ? "absent" : "PRESENT(" + pac + ")"));
            }
            catch (Exception ex) { parts.Add("proxy-check-failed(" + ex.GetType().Name + ")"); }
            try
            {
                var leftovers = new List<string>();
                foreach (var name in new[] { "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy" })
                {
                    string? v = null;
                    try { v = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.User); } catch { }
                    if (!string.IsNullOrEmpty(v) && v.IndexOf("127.0.0.1", StringComparison.OrdinalIgnoreCase) >= 0)
                        leftovers.Add(name);
                }
                parts.Add("tor-env=" + (leftovers.Count == 0 ? "clean" : "LEFTOVER(" + string.Join(",", leftovers) + ")"));
            }
            catch (Exception ex) { parts.Add("env-check-failed(" + ex.GetType().Name + ")"); }
            try
            {
                var d = _dnsMgr.GetSnapshot();
                // Marker-only is not proof: stranded loopback with the marker
                // already gone still breaks the internet, so count the real
                // interfaces too (mirrors the rescue script's verify step).
                var stranded = _dnsMgr.CountStrandedLoopback();
                parts.Add("dns=" + (d.Managed ? "STILL-MANAGED" : "system") +
                    (stranded > 0 ? $"+LOOPBACK-LEFT({stranded})" : ""));
            }
            catch (Exception ex) { parts.Add("dns-check-failed(" + ex.GetType().Name + ")"); }
            return string.Join(" ", parts.ToArray());
        }

        volatile int _stdoutBootstrapped;
        // Run generation: bumped on every start AND every stop. A reconnect
        // sleeping through either wakes up stale and must stand down, even
        // if it captured a fresh CTS (late-duplicate crash event).
        volatile int _runSeq;

        async Task StartCoreAsync(int rotateEverySec)
        {
            try { _lifetimeCts?.Dispose(); } catch { }
            _lifetimeCts = new CancellationTokenSource();
            Interlocked.Increment(ref _runSeq);
            Volatile.Write(ref _stdoutBootstrapped, 0);
            // Fresh run, fresh pin episode: a previous run's degraded
            // ladders must not trigger a rescue against the new tor, and
            // a previous run's link success must not green-light one
            // either (cold circuits fail the first ticks even on healthy
            // pins — the "always unpinned after reboot" bug).
            _pinDegradedLadders = 0;
            Volatile.Write(ref _pinRescueSignalInFlight, 0);
            Volatile.Write(ref _hadLinkSuccessThisRun, false);
            // Fresh run, fresh link baseline (same bug family): a previous
            // run's fail counters / settle hold / last-OK timestamp must not
            // judge the cold new daemon. StopCoreAsync resets the counters on
            // the stop side; a start WITHOUT a prior stop (toggle pressed
            // while already routing, rescue probe chains) would otherwise
            // inherit a nearly-tripped ladder and "reconnect over and over"
            // on both pinned and unpinned runs.
            _linkFails = 0;
            _softRecoverStreak = 0;
            _lastRotationCompletedUtc = DateTime.MinValue;
            _lastLinkOkUtc = DateTime.MinValue;
            PreventSleep(true);
            try
            {
                await StartCoreInnerAsync(rotateEverySec);
            }
            finally
            {
                PreventSleep(false);
            }
        }

        // Effective pin for THIS run's bootstrap waits: while bridges are
        // in use Tor ignores EntryNodes, so an entry-only pin can never
        // stall the bootstrap and must never trigger a pin rescue (which
        // would wipe a pick that was never the problem). Direct runs count
        // every position. Never throws.
        bool BootstrapPinActive()
        {
            try
            {
                if (!_pinnedCircuitActive) return false;
                int middle = 0, exit = 0;
                try { middle = _proc.PinnedMiddleNodes?.Count ?? 0; } catch { }
                try { exit = _proc.PinnedExitNodes?.Count ?? 0; } catch { }
                if (_bridges.Mode != BridgeMode.Direct) return (middle + exit) > 0;
                return true;
            }
            catch { return false; }
        }

        // Runtime twin of BootstrapPinActive: the data path can only be
        // pin-caused when an effective position exists. Same bridge rule.
        bool RuntimePinEffective()
        {
            try { return BootstrapPinActive(); }
            catch { return false; }
        }

        async Task StartCoreInnerAsync(int rotateEverySec)
        {

            try
            {
                var report = RestoreCheckpointIfUnclean();
                if (!string.IsNullOrEmpty(report)) LogMessage?.Invoke(this, report);
            }
            catch { }
            // Arm BEFORE tor bootstraps (not after routing engages): the
            // bootstrap takes minutes, and a crash/kill inside that window
            // would otherwise leave loopback settings with no safety net.
            // Clean paths disarm (StopCoreSync / teardown Remove hooks).
            try
            {
                var bootNote = BootRestore.Ensure(_appDir);
                if (!string.IsNullOrEmpty(bootNote)) LogMessage?.Invoke(this, bootNote);
            }
            catch { }

            PtDefaults? bridgeDefaults = null;
            try
            {
                bridgeDefaults = BridgeConfigEngine.LoadDefaults(
                    Path.Combine(_appDir, "tools", "tor", "pluggable_transports", "pt_config.json"));
            }
            catch { }

            // Tor-phase rollback: any failure below (bad torrc, control
            // timeout, bootstrap timeout, bridge exhaustion) must not leave
            // a live tor.exe + relays + control behind. Proxy/env failures
            // already roll back via the block below; this covers everything
            // BEFORE that block. StopCoreAsync is idempotent (gate held).
            try
            {
            if (_bridges.Mode == BridgeMode.Direct)
            {
                var direct = BridgeConfigEngine.Resolve(BridgeConfig.DirectOnly(), PtToolsDir, bridgeDefaults);
                _proc.Start(null);
                _lastResolved = direct;
                StartRelays();
                await WaitForBootstrapAndConnectControl(40);
                // Control-port auth is NOT readiness (the port opens in the
                // first seconds of life): only flip routing on at 100%.
                await WaitForBootstrapCompleteAsync(180, "direct guards", 60, BootstrapPinActive());
            }
            else if (_bridges.Mode == BridgeMode.Auto)
            {
                await StartAutoTierAsync(bridgeDefaults);
            }
            else
            {
                // Fail closed: never silently fall back to direct guards. Invalid config fails the start.
                ResolvedBridges resolved;
                try
                {
                    resolved = ResolveExplicitBridges(bridgeDefaults);
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("Bridge configuration failed: " + ex.Message, ex);
                }
                if (!resolved.UseBridges)
                    throw new InvalidOperationException(
                        "Bridge mode '" + _bridges.Mode + "' is unusable: " +
                        string.Join(" ", resolved.Errors) +
                        " Tor was NOT started (falling back to direct guards would leak intent in censored regions).");
                LogMessage?.Invoke(this, $"Routing entry via {resolved.Label} ({resolved.BridgeLines.Count} bridge(s)).");
                await StartWithBridgeFallbackAsync(resolved);
            }
            // Bootstrap 100% is NOT proof when pinned: a dead pinned EXIT
            // still bootstraps (guards work, exit streams die). Flipping
            // routing on there strands the user with "connected, no
            // internet". Verify one end-to-end stream while still gated —
            // failure here throws pin-suspect so the UI rescues instead of
            // declaring success. Unpinned runs skip the extra ~20s.
            if (BootstrapPinActive())
                await VerifyPinnedDataPathAsync();
            }
            catch
            {
                try { await StopCoreAsync(); } catch { }
                throw;
            }

            try
            {
                // Filter-FIRST when lockdown is required and achievable: the
                // packet filter + Tor-DNS engage BEFORE the system proxy/env
                // flip, so there is never a proxy-ON/filter-OFF window where
                // non-proxy/UDP apps go direct. Failure rolls everything back
                // (no proxy-only fallback when the filter should work).
                // When elevation/driver is missing we keep proxy-only + loud
                // warn (refusing would brick non-admin users; proxy-via-Tor
                // still beats direct — the UI names the gap honestly).
                bool filterFirst = false;
                try { filterFirst = LockdownRequired && !EnforcementActive && AdminHelper.IsAdministrator() && DivertEnforcement.DriverFilesPresent(_appDir); }
                catch { filterFirst = false; }
                if (filterFirst)
                {
                    try
                    {
                        string note;
                        lock (_enforceGate) { note = EnableEnforcementCore(allowPreRouting: true); }
                        try { LogMessage?.Invoke(this, note); } catch { }
                    }
                    catch (Exception lex)
                    {
                        try { await StopCoreAsync(); } catch { }
                        throw new InvalidOperationException(
                            "Tor-only lockdown required but failed to engage (" + lex.Message +
                            ") — routing is OFF (no proxy-only fallback when the filter should work).", lex);
                    }
                }
                LogMessage?.Invoke(this, _proxy.Enable(RelayPort, BridgePort));
                try
                {
                    LogMessage?.Invoke(this, _env.Enable(SocksPort, BridgePort));
                }
                catch (Exception envEx)
                {
                    try { _proxy.Disable(); } catch { }
                    throw new InvalidOperationException(
                        "System proxy was set but env proxy failed — rolled both back, routing is OFF. " +
                        "Details: " + envEx.Message, envEx);
                }
                RoutingActive = true;
                RoutingStartedUtc = DateTime.UtcNow;
                // (Boot safety net is armed at start entry — see
                // StartCoreInnerAsync — so bootstrap-crash windows are
                // covered too, not just post-engage deaths.)
                // Late filter (non-filter-first path): required but the
                // machine couldn't do it up-front — try now that routing is
                // up (same strict rollback on achievable-but-failed).
                if (LockdownRequired && !EnforcementActive && !filterFirst)
                {
                    bool canTry = false;
                    try { canTry = AdminHelper.IsAdministrator() && DivertEnforcement.DriverFilesPresent(_appDir); }
                    catch { canTry = false; }
                    if (canTry)
                    {
                        try
                        {
                            string note;
                            lock (_enforceGate) { note = EnableEnforcementCore(); }
                            try { LogMessage?.Invoke(this, note); } catch { }
                        }
                        catch (Exception lex)
                        {
                            try { await StopCoreAsync(); } catch { }
                            throw new InvalidOperationException(
                                "Tor-only lockdown required but failed to engage (" + lex.Message +
                                ") — routing is OFF (no proxy-only fallback when the filter should work).", lex);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Half-built stack teardown: StopCoreAsync is idempotent.
                await StopCoreAsync();
                throw new InvalidOperationException(
                    "Tor start failed — routing is OFF, tor.exe and internal relays stopped. " +
                    "Details: " + ex.Message, ex);
            }

            try { _maintenance?.Dispose(); } catch { }
            _maintenance = new TorMaintenance(_control!) { RotateIntervalSec = rotateEverySec, KeepAliveIntervalSec = LinkCheckPeriodSec };
            // User-interval cache for reconnects (plain runs only): pinned /
            // stable force the live timer to 0 but must never clobber the
            // user's value — otherwise the first reconnect kills scheduled
            // rotation forever (cache stayed 0 for the whole session).
            if (!_pinnedCircuitActive && !_stableConnection) SetRotateIntervalCache = rotateEverySec;
            _maintenance.Died += async (_, __) => await HandleUnexpectedExit();
            _maintenance.RotationRequested += (_, msg) => LogMessage?.Invoke(this, msg);
            _maintenance.RotationCompleted += (_, ok) => OnRotationCompleted(ok);
            _maintenance.Start();

            StartLinkChecks();

            _reconnectAttempt = 0;
        }

        void ThrowIfStopping()
        {
            if (_lifetimeCts?.IsCancellationRequested == true)
                throw new OperationCanceledException("Stop requested.");
        }

        void StartRelays()
        {
            // Re-apply the live content policy on every (re)bind so a
            // restart never silently drops the toggles.
            try { _bridge.BlockJs = _blockJs; } catch { }
            try { _bridge.BlockWebRtc = _blockWebRtc; } catch { }
            try { _bridge.BlockCookies = _blockCookies; } catch { }
            try { _bridge.MitmEnabled = _mitmEnabled; } catch { }
            try { _bridge.MitmCa = _mitmCa; } catch { }
            try { _socksRelay.BlockWebRtc = _blockWebRtc; } catch { }
            // SOCKS TLS inspection mirrors the HTTP channel exactly.
            try { _socksRelay.BlockJs = _blockJs; } catch { }
            try { _socksRelay.BlockCookies = _blockCookies; } catch { }
            try { _socksRelay.SpoofHost = HeaderSpoof; } catch { }
            try { _socksRelay.MitmEnabled = _mitmEnabled; } catch { }
            try { _socksRelay.MitmCa = _mitmCa; } catch { }
            _bridge.Start();
            _socksRelay.Start();
        }

        // Snowflake rendezvous is slow; obfs4-style either connects fast or never.
        internal static int AttemptsForLine(string line)
        {
            try
            {
                if (string.Equals(BridgeConfigEngine.TransportOfLine(line ?? ""),
                        "snowflake", StringComparison.OrdinalIgnoreCase))
                    return 150;
            }
            catch { }
            return 80;
        }

        // Bootstrap takes far longer than control-connect on slow transports.
        // Snowflake rendezvous is legitimately slow (broker + WebRTC, 7min
        // budget). obfs4-style TCP either handshakes in about a minute or
        // never — and the 120s stall gate usually aborts dead ones earlier
        // anyway. The old 300s per candidate turned a set of stale bundled
        // bridges into ~half an hour of apparent deadness.
        internal static int BootstrapTimeoutForLine(string? line)
        {
            try
            {
                if (string.Equals(BridgeConfigEngine.TransportOfLine(line ?? ""),
                        "snowflake", StringComparison.OrdinalIgnoreCase))
                    return 420;
            }
            catch { }
            return 180;
        }

        // Hard readiness gate: control-port auth only proves tor is ALIVE.
        // Flipping routing on before bootstrap 100% sends every app (and the
        // link checks) into cold circuits that time out — the classic
        // "bootstrapped, but nothing routes until I toggle" report. Polls
        // GETINFO status/bootstrap-phase; a stalled bootstrap fails the start
        // loudly instead of stranding routing on a dead Tor.
        //
        // First-boot stalls (frozen at ~10%, "connections died in state
        // handshaking (TLS)") must NOT burn the whole timeout blindly: two
        // parallel diagnostics run inside the wait — a clock-skew probe
        // (wrong clock kills guard TLS deterministically) and a scan of
        // tor's own log for handshake-death evidence. Either aborts early
        // with the exact cause + fix. Pure slowness (no evidence) still gets
        // the full timeout.
        //
        // PIN SELF-HEALING: when pinActive is true the same wait doubles as
        // the dead-pin detector (bug: pinned relay retired overnight ->
        // stuck bootstrap forever). Two pin-specific fast paths apply ONLY
        // in that case: (1) any tor log line blaming the pin aborts
        // immediately with PinSuspectBootstrapException (no freeze wait —
        // tor already gave the verdict); (2) the freeze threshold shrinks to
        // PinAutoRecovery.PinStallFreezeSec and ANY timeout/stall while
        // pinned throws PinSuspectBootstrapException instead of a plain
        // TimeoutException, so the UI can probe once unpinned. The
        // unproven-vs-explicit distinction travels in the exception — the
        // UI must not claim certainty it doesn't have.
        async Task WaitForBootstrapCompleteAsync(int timeoutSec, string what, int stallFreezeSec = 60, bool pinActive = false)
        {
            // Pin runs use the pin freeze (90s) exactly: long enough to ride
            // out slow first boots (no cached consensus, slow guards) so a
            // healthy pin is never declared dead on a cold start ("always
            // unpinned after reboot"), but far shorter than bridge-tier 120s
            // / full 180-300s timeouts so a dead StrictNodes pin still aborts
            // early. Never shorter than 90 when pinned — callers passing 60
            // (direct) must not make pinned boots MORE aggressive than
            // unpinned ones.
            if (pinActive) stallFreezeSec = PinAutoRecovery.PinStallFreezeSec;
            var clockSkewTask = ProbeClockSkewAsync();
            var sw = Stopwatch.StartNew();
            var lastPct = -1;
            var frozenSince = TimeSpan.Zero;
            var handshakeDeaths = 0;
            var clockHints = 0;
            var logSeen = 0;
            var pinHits = 0;
            string pinEvidence = "";
            var skewChecked = false;
            TimeSpan? skew = null;
            while (sw.Elapsed.TotalSeconds < timeoutSec)
            {
                if (_lifetimeCts?.IsCancellationRequested == true)
                    throw new OperationCanceledException("Stop requested during bootstrap.");
                // Fast-fail when the daemon died mid-bootstrap (dead bridge,
                // killed helper): otherwise a tor that exited at 5s burns the
                // whole 180s timeout as a "stall" while the UI looks wedged.
                // Pin-suspect stays out of here — a dead daemon is not a pin
                // verdict (the bridge loop treats this as a candidate failure
                // and tries the next bridge; the pin rescue never sees it).
                bool torAlive = true;
                try { torAlive = _proc.IsRunning; } catch { torAlive = true; }
                if (!torAlive)
                    throw TorDiedException($"Tor exited during bootstrap via {what}");
                // Clock verdict is deterministic: a >30min skew means guard
                // TLS CANNOT succeed — abort as soon as the probe proves it
                // instead of stalling with everyone else.
                if (!skewChecked && clockSkewTask.IsCompletedSuccessfully)
                {
                    skewChecked = true;
                    try { skew = await clockSkewTask; } catch { skew = null; }
                    if (skew is TimeSpan s && s.Duration() >= TimeSpan.FromMinutes(30))
                        throw new InvalidOperationException(ClockSkewMessage(s));
                }
                int pct = -1;
                try { if (_control != null) pct = await _control.GetBootstrapPercentAsync(); }
                catch { }
                // Either signal completes the gate: stdout event or control poll.
                if (Volatile.Read(ref _stdoutBootstrapped) == 1 || pct >= 100)
                {
                    LogMessage?.Invoke(this, "Tor bootstrap complete (100%) — data path is live.");
                    return;
                }
                if (pct != lastPct && pct >= 0)
                {
                    lastPct = pct;
                    frozenSince = sw.Elapsed;
                    handshakeDeaths = 0;
                    clockHints = 0;
                    // Pin evidence is per-stall, not per-boot: tor resolving
                    // the pin and making progress proves the earlier blame
                    // line was transient (pre-consensus lookup on a healthy
                    // first boot). Without this reset a single stale line
                    // from 0% framed the pin during a later freeze and wiped
                    // a healthy pin on every slow boot.
                    pinHits = 0;
                    pinEvidence = "";
                    StateChanged?.Invoke(this, new TorStateChangedEventArgs
                    {
                        State = TorState.Bootstrapping,
                        Message = $"Tor bootstrapping ({pct}%)",
                        BootstrapPercent = pct
                    });
                }
                try { ScanBootstrapLog(ref logSeen, ref handshakeDeaths, ref clockHints, ref pinHits, ref pinEvidence); } catch { }
                // Pin fast path (ONLY explicit tor verdict, SUSTAINED): tor
                // explicitly blamed the pinned relay(s) more than once
                // inside the CURRENT freeze (progress resets the count
                // above). A single line is never enough — a healthy first
                // boot logs one transient pre-consensus "no such router"
                // while the consensus downloads, and a slow network then
                // sits frozen 20s+ on zero evidence. A genuinely dead
                // StrictNodes pin logs blame on every retry, so >= 2 hits
                // still aborts far earlier than the full timeout. No
                // explicit evidence => NEVER PinSuspect here: unproven
                // stalls throw plain TimeoutException below (pin kept,
                // watchdog retries with pin intact). Framing the pin on
                // thin evidence is exactly the "always unpinned after
                // reboot" bug.
                var frozenSec = (sw.Elapsed - frozenSince).TotalSeconds;
                if (pinActive && pinHits >= 2 &&
                    (frozenSec >= 20 || sw.Elapsed.TotalSeconds >= 30))
                    throw new PinSuspectBootstrapException(
                        PinAutoRecovery.PinStallMessage(what, lastPct, pinEvidence, true),
                        pinEvidence, true);
                // Early abort: frozen WITH tor-attested handshake deaths (not
                // mere slowness). Bridge paths get a longer freeze (Snowflake
                // rendezvous is legitimately slow and noisy).
                if (sw.Elapsed.TotalSeconds >= 60 && frozenSec >= stallFreezeSec && handshakeDeaths >= 3)
                {
                    throw new TimeoutException(StallAbortMessage(what, lastPct, handshakeDeaths, clockHints, skew));
                }

                if (sw.Elapsed.TotalSeconds >= 90 && frozenSec >= 90 && handshakeDeaths == 0)
                {
                    throw new TimeoutException(SilentStallMessage(what, lastPct));
                }
                // Pin slow-stall: frozen past the pin threshold with a pin
                // active but NO explicit tor verdict. A dead StrictNodes pin
                // usually produces pin lines (caught above), but a
                // silently-vanished relay can look exactly like slowness —
                // and so can a healthy-but-slow first boot (no cached
                // consensus, slow guards, Snowflake rendezvous). Guessing
                // "pin dead" here wiped good pins on every slow boot, so:
                // NO PinSuspect on unproven evidence — fall through to the
                // full timeout below as a plain stall (pin kept). The
                // runtime ladder (grace + symmetric unpinned probe) is the
                // only unproven path to a rescue, where both sides are
                // measured equally.
                await Task.Delay(1000);
            }
            // Full timeout with a pin active but no explicit verdict: plain
            // stall, NOT pin-suspect. The pin is unproven — keep it.
            var tail = handshakeDeaths > 0
                ? $" ({handshakeDeaths} guard handshake(s) died along the way — tor's raw errors stay in Config → Tor log)"
                : "";
            throw new TimeoutException(
                $"Tor stalled during bootstrap{(lastPct >= 0 ? $" at {lastPct}%" : "")} via {what} — " +
                "no usable path yet. Routing stays OFF (toggle to retry; Snowflake on slow links can need several minutes)." + tail);
        }
        internal static string SilentStallMessage(string what, int pct) =>
            $"Tor is stuck{(pct >= 0 ? $" at {pct}%" : "")} via {what} with NO handshake errors in tor's own " +
            "log — packets are being silently dropped, not actively refused. Usual causes: Windows Defender " +
            "Firewall or antivirus quietly blocking tor.exe's outbound TLS (check for a blocked-outbound rule " +
            "under tor.exe / add an explicit allow), or a censoring network dropping Tor TLS fingerprints " +
            "(switch Config → bridges → Automatic/Snowflake instead of direct guards). Routing stays OFF.";
        // Tor's own log is the ground truth for WHY a bootstrap is stuck.
        // Counts only fresh lines since the last scan (index-guarded; a ring
        // overflow rescan may double-count a few lines, which merely hurries
        // an abort that already requires 60s of frozen progress).
        // pinHits/pinEvidence additionally count tor lines that blame the
        // circuit pin (StrictNodes / no such router / ...). Callers that
        // don't care pass dummy refs; pin-aware waits surface the first
        // such line as the rescue evidence string.
        void ScanBootstrapLog(ref int seen, ref int deaths, ref int clock, ref int pinHits, ref string pinEvidence)
        {
            List<string> tail;
            try { tail = _proc.GetLogTail(); } catch { return; }
            if (tail == null || tail.Count == 0) return;
            if (seen > tail.Count) seen = 0;
            for (var i = seen; i < tail.Count; i++)
            {
                var line = tail[i];
                // Tor's own "stuck" verdict is authoritative on its own —
                // weight it like several generic hits so a single sighting
                // (plus the freeze-time requirement above) is enough to
                // abort, instead of waiting on the weaker heuristic below to
                // accumulate three hits that may never come.
                if (IsBootstrapStuckLine(line)) deaths += 3;
                else if (IsHandshakeDeathLine(line)) deaths++;
                else if (IsClockHintLine(line)) clock++;
                try
                {
                    if (PinAutoRecovery.IsPinFailureLogLine(line))
                    {
                        pinHits++;
                        if (string.IsNullOrEmpty(pinEvidence)) pinEvidence = (line ?? "").Trim();
                    }
                }
                catch { }
            }
            seen = tail.Count;
        }

        // Backward-compatible overload for callers that only track the
        // generic signals (kept so the diff stays reviewable; pin-aware
        // waits use the 5-arg form above).
        void ScanBootstrapLog(ref int seen, ref int deaths, ref int clock)
        {
            int pinHits = 0;
            string pinEvidence = "";
            ScanBootstrapLog(ref seen, ref deaths, ref clock, ref pinHits, ref pinEvidence);
        }

        // Tor's canonical stall warning: "[warn] Problem bootstrapping.
        // Stuck at 10%: Finishing handshake with first hop. (DONE; DONE;
        // count 10; recommendation warn; host FP at IP:PORT)". This is the
        // single most common real-world "stuck at 10%" message, and its
        // bracketed reason code (DONE/MISC/NOROUTE/INTERNAL/...) usually
        // contains NONE of died/fail/error/timeout/reset/refused — so
        // without this dedicated check it was invisible to
        // IsHandshakeDeathLine below, and a bootstrap that Tor itself was
        // actively reporting as stuck got misdiagnosed as a "silent" stall
        // (blamed on firewall/AV) instead of a real handshake failure.
        internal static bool IsBootstrapStuckLine(string? line)
        {
            try
            {
                if (string.IsNullOrEmpty(line)) return false;
                var l = line.ToLowerInvariant();
                return l.Contains("problem bootstrapping") && l.Contains("stuck at");
            }
            catch { return false; }
        }

        // A tor guard-handshake death: e.g. "[warn] 1 connections died in
        // state handshaking (TLS) with SSL state ... in HANDSHAKE".
        internal static bool IsHandshakeDeathLine(string? line)
        {
            try
            {
                if (string.IsNullOrEmpty(line)) return false;
                var l = line.ToLowerInvariant();
                if (!l.Contains("handshak")) return false;
                return l.Contains("died") || l.Contains("fail") || l.Contains("error") ||
                       l.Contains("timed out") || l.Contains("timeout") ||
                       l.Contains("reset") || l.Contains("refused");
            }
            catch { return false; }
        }

        internal static bool IsClockHintLine(string? line)
        {
            try
            {
                if (string.IsNullOrEmpty(line)) return false;
                var l = line.ToLowerInvariant();
                // "skew" in tor logs is always clock skew ("skewed time").
                if (l.Contains("skew")) return true;
                if (!l.Contains("clock")) return false;
                return l.Contains("jump") ||
                       l.Contains("behind") || l.Contains("ahead") || l.Contains("wrong");
            }
            catch { return false; }
        }

        // Direct HTTPS Date-header probe (never via tor: tor may be the
        // broken half). Null = unknown (blocked/offline), never a verdict.
        // Runs parallel to the bootstrap poll — zero added startup latency.
        async Task<TimeSpan?> ProbeClockSkewAsync()
        {
            try
            {
                using var handler = new SocketsHttpHandler { UseProxy = false };
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
                foreach (var url in new[] { "https://www.google.com/", "https://www.microsoft.com/" })
                {
                    try
                    {
                        using var req = new HttpRequestMessage(HttpMethod.Head, url);
                        using var resp = await client.SendAsync(req);
                        var skew = ComputeSkew(resp.Headers.Date?.ToString("r"), DateTimeOffset.UtcNow);
                        if (skew != null) return skew;
                    }
                    catch { }
                }
                return null;
            }
            catch { return null; }
        }

        internal static TimeSpan? ComputeSkew(string? dateHeaderValue, DateTimeOffset now)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(dateHeaderValue)) return null;
                if (!DateTimeOffset.TryParse(dateHeaderValue, out var server)) return null;
                var skew = now - server.ToUniversalTime();
                // Absurd values mean a lying middlebox, not a clock: unknown.
                if (skew.Duration() > TimeSpan.FromDays(370)) return null;
                return skew;
            }
            catch { return null; }
        }

        internal static string ClockSkewMessage(TimeSpan skew)
        {
            var mag = skew.Duration();
            var size = mag.TotalHours >= 1
                ? $"~{(int)mag.TotalHours}h {mag.Minutes}m"
                : $"~{(int)mag.TotalMinutes}m";
            var dir = skew.TotalSeconds >= 0 ? "ahead of" : "behind";
            return $"System clock is off by {size} ({dir} network time) — Tor's TLS handshakes to guards " +
                "fail with a wrong clock, which is exactly this stall. Fix: Windows Settings → Time & language → " +
                "turn ON \"Set time automatically\" (and \"Set time zone automatically\"), then toggle routing to " +
                "retry. Bootstrap aborted early instead of stalling.";
        }

        internal static string StallAbortMessage(string what, int pct, int deaths, int clockHints, TimeSpan? skew)
        {
            var where = pct >= 0 ? $" at {pct}%" : "";
            var msg = new System.Text.StringBuilder();
            msg.Append($"Tor is stuck{where} via {what}: Tor's own log reports the handshake to a guard/bridge " +
                "isn't completing (\"Problem bootstrapping... Stuck at\" / \"connections died in state handshaking\"). Guard TLS isn't completing. ");
            if ((what ?? "").IndexOf("direct", StringComparison.OrdinalIgnoreCase) >= 0)
                msg.Append("Typical on networks that filter Tor (first boots hurt most — no cached consensus yet): " +
                    "retry with Config → bridges → Automatic (or Snowflake). ");
            else
                msg.Append("The bridge/transport path isn't completing TLS: try Config → bridges → Automatic, a fresh " +
                    "custom line, or Snowflake — and allow tor.exe / helpers if a firewall prompts. ");
            if (clockHints > 0)
                msg.Append("Tor's own log also flags clock problems — fix the system clock first (see Config → Tor log). ");
            else if (skew is TimeSpan s)
                msg.Append($"(Clock check: system clock looks OK here — off by ~{(int)s.Duration().TotalMinutes}m, not the cause.) ");
            msg.Append("Tor's raw handshake errors stay visible in Config → Tor log. Routing stays OFF.");
            return msg.ToString();
        }

        // Explicit-mode resolve with the Snowflake→obfs4 fallback: when the
        // user picked Snowflake but it can never work here (helper binary
        // missing/misconfigured, or no bundled lines), bundled obfs4 is used
        // instead of a dead end — still fully via Tor (a transport swap, not
        // a leak-class change), and logged loudly below. Custom lines are
        // NOT converted: pasted bridges are the user's explicit trust choice
        // (often private), and their Resolve error already says what to do.
        // Auto mode needs nothing here (its tiers already escalate). Never
        // throws; unusable results carry Errors for the caller's throw.
        ResolvedBridges ResolveExplicitBridges(PtDefaults? bridgeDefaults)
        {
            ResolvedBridges resolved;
            try
            {
                resolved = BridgeConfigEngine.Resolve(_bridges, PtToolsDir, bridgeDefaults);
            }
            catch (Exception ex)
            {
                return new ResolvedBridges(false, new List<string>(), new List<string>(),
                    new List<string> { "Bridge configuration failed: " + ex.Message }, _bridges.Mode.ToString());
            }
            if (resolved.UseBridges || _bridges.Mode != BridgeMode.SnowflakeDefault)
                return resolved;
            ResolvedBridges obfs4;
            try
            {
                obfs4 = BridgeConfigEngine.Resolve(
                    new BridgeConfig(BridgeMode.Obfs4Default, new List<string>()), PtToolsDir, bridgeDefaults);
            }
            catch (Exception ex)
            {
                return new ResolvedBridges(false, new List<string>(), new List<string>(),
                    new List<string>(resolved.Errors) { "obfs4 fallback also failed to resolve: " + ex.Message },
                    resolved.Label);
            }
            if (!obfs4.UseBridges)
            {
                var errs = new List<string>(resolved.Errors);
                errs.AddRange(obfs4.Errors);
                return resolved with { Errors = errs };
            }
            try
            {
                LogMessage?.Invoke(this,
                    "WARNING: Snowflake unavailable (" + string.Join(" ", resolved.Errors) +
                    ") — falling back to bundled obfs4 bridges (still fully via Tor). " +
                    "Drop a snowflake-client.exe into tools\\tor\\pluggable_transports to use Snowflake.");
            }
            catch { }
            return obfs4 with { Label = "obfs4 bridges (automatic Snowflake fallback)" };
        }

        // One candidate per attempt (best-ranked first); health persists, so steady state burns one bridge per start.
        async Task StartWithBridgeFallbackAsync(ResolvedBridges resolved)
        {
            var ordered = _bridgeHealth.OrderForAttempt(resolved.BridgeLines);
            if (ordered.Count == 0)
                throw new InvalidOperationException("No bridge candidates available.");
            StartRelays();
            Exception? last = null;
            var allSnowflake = ordered.Count > 0 && ordered.All(l => IsSnowflakeLine(l));
            var preflightCache = new Dictionary<string, (bool ok, string reason)>();
            var tried = 0;
            foreach (var line in ordered)
            {
                ThrowIfStopping();
                tried++;
                try
                {
                    LogMessage?.Invoke(this,
                        $"Trying bridge {tried}/{ordered.Count} ({BridgeHealthStore.ShortName(line)})…");
                }
                catch { }
                // Snowflake rendezvous (broker + UDP) either works in seconds
                // or never: without this, tor sits at 10% for the whole
                // bootstrap timeout with zero log evidence. Preflight each
                // distinct helper infra once; mixed sets skip the dead line,
                // all-snowflake sets fail fast with the cause (Auto tier then
                // escalates to obfs4 instead of burning 7 minutes).
                // Skipped under active enforcement: our own probe packets
                // would be dropped like any foreign traffic, lying that UDP
                // is dead. Pre-routing there is no filter, so the reading is
                // the true uplink.
                if (IsSnowflakeLine(line) && !EnforcementActive)
                {
                    ThrowIfStopping();
                    var key = SnowflakePreflight.CacheKey(line);
                    if (!preflightCache.TryGetValue(key, out var verdict))
                    {
                        verdict = await SnowflakePreflight.CheckAsync(
                            SnowflakePreflight.ParseIceServers(line),
                            SnowflakePreflight.ParseFronts(line),
                            SnowflakePreflight.UdpStunProbeAsync,
                            SnowflakePreflight.DnsResolvesAsync,
                            TimeSpan.FromSeconds(12),
                            _lifetimeCts?.Token ?? CancellationToken.None);
                        preflightCache[key] = verdict;
                    }
                    if (!verdict.ok)
                    {
                        _bridgeHealth.RecordResult(line, false);
                        var msg = $"Snowflake preflight failed ({verdict.reason}) — " +
                            (allSnowflake
                                ? "not starting tor into a hopeless rendezvous. " + SnowflakeAdvice()
                                : "skipping this line.");
                        LogMessage?.Invoke(this, msg);
                        if (allSnowflake)
                            throw new InvalidOperationException(msg);
                        continue;
                    }
                }
                var single = resolved with { BridgeLines = new List<string> { line } };
                try
                {
                    // No stale daemon: leftover tor would bootstrap against the previous torrc.
                    if (_proc.IsRunning) await _proc.StopAsync();
                    _proc.Start(single);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    last = ex;
                    _bridgeHealth.RecordResult(line, false);
                    var left = ordered.Count - tried;
                    LogMessage?.Invoke(this,
                        $"Bridge candidate {BridgeHealthStore.ShortName(line)} failed to launch ({ShortError(ex)}" +
                        (left > 0 ? $", {left} left — trying next)." : ", none left)."));
                    continue;
                }
                try
                {
                    await WaitForBootstrapAndConnectControl(AttemptsForLine(line));
                    await WaitForBootstrapCompleteAsync(BootstrapTimeoutForLine(line),
                        BridgeHealthStore.ShortName(line), stallFreezeSec: 120, pinActive: BootstrapPinActive());
                    _bridgeHealth.RecordResult(line, true);
                    _lastResolved = single;
                    LogMessage?.Invoke(this,
                        $"Bridge connected via {BridgeHealthStore.ShortName(line)}.");
                    return;
                }
                catch (OperationCanceledException)
                {
                    try { await _proc.StopAsync(); } catch { }
                    throw;
                }
                catch (PinSuspectBootstrapException)
                {
                    // Dead pin, not a dead bridge: trying the next bridge
                    // with the SAME torrc pin would burn minutes proving the
                    // same point, and would poison that bridge's health
                    // score for a failure that was never its fault.
                    try { await _proc.StopAsync(); } catch { }
                    throw;
                }
                catch (Exception ex)
                {
                    last = ex;
                    _bridgeHealth.RecordResult(line, false);
                    try { await _proc.StopAsync(); } catch { }
                    // Name the cause inline: a silent "failed — trying next"
                    // per candidate is exactly the "didn't do anything"
                    // report. Stale bundled bridges show their tor verdict
                    // here (handshake deaths, clock hints, stalls).
                    var left = ordered.Count - tried;
                    LogMessage?.Invoke(this,
                        $"Bridge candidate {BridgeHealthStore.ShortName(line)} failed ({ShortError(ex)}" +
                        (left > 0 ? $", {left} left — trying next)." : ", none left)."));
                    ThrowIfStopping();
                }
            }
            throw new InvalidOperationException(
                "All bridge candidates failed" +
                (ordered.Count > 1 ? $" ({ordered.Count} tried, dead ones are benched for next time)" : "") +
                ". " + ShortError(last) +
                " If the bundled bridges are stale, paste fresh ones (Tor Project website / bridges.torproject.org) as Custom lines.", last);
        }

        static bool IsSnowflakeLine(string line)
        {
            try
            {
                return string.Equals(BridgeConfigEngine.TransportOfLine(line ?? ""),
                    "snowflake", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        static string SnowflakeAdvice() =>
            "Snowflake needs working system DNS plus direct UDP. Use obfs4/Automatic instead, " +
            "or fix the path (hotspots, VPNs and strict firewalls commonly block UDP).";

        static string ShortError(Exception? ex)
        {
            try
            {
                if (ex == null) return "";
                var msg = (ex.Message ?? "").Replace('\r', ' ').Replace('\n', ' ');
                return msg.Length <= 160 ? msg : msg.Substring(0, 160) + "…";
            }
            catch { return ""; }
        }

        // Tor died under us (bad torrc, dead transport helper, AV kill).
        // Surfaces tor's own last log lines so a dead obfs4 bridge reads as
        // its cause instead of a generic control/bootstrap timeout, and
        // points at Config → Tor log for the full tail. Never throws.
        InvalidOperationException TorDiedException(string what)
        {
            string tail = "";
            try
            {
                var lines = _proc.GetLogTail();
                if (lines != null && lines.Count > 0)
                    tail = " Tor said: " + string.Join(" | ",
                        lines.Skip(Math.Max(0, lines.Count - 4)).Take(4)
                            .Select(l => ((l ?? "").Length <= 140 ? (l ?? "") : (l ?? "").Substring(0, 140) + "…")));
            }
            catch { }
            return new InvalidOperationException(
                what + " — tor.exe is not running." + tail +
                " (full log: Config → Tor log; bridge lines: Config → bridges).");
        }

        internal static List<(BridgeMode mode, string label)> AutoTiers() => new()
        {
            // Direct first (fast path where nothing is censored), then
            // private, Snowflake, public obfs4 last.
            (BridgeMode.Direct, "direct"),
            (BridgeMode.Custom, "private bridges"),
            (BridgeMode.SnowflakeDefault, "Snowflake"),
            (BridgeMode.Obfs4Default, "public obfs4"),
        };

        async Task StartAutoTierAsync(PtDefaults? defaults)
        {
            foreach (var (mode, label) in AutoTiers())
            {
                ThrowIfStopping();
                if (mode == BridgeMode.Direct)
                {
                    try
                    {
                        LogMessage?.Invoke(this, "Trying direct guards...");
                        var direct = BridgeConfigEngine.Resolve(BridgeConfig.DirectOnly(), PtToolsDir, defaults);
                        if (_proc.IsRunning) await _proc.StopAsync();
                        _proc.Start(null);
                        _lastResolved = direct;
                        StartRelays();
                        await WaitForBootstrapAndConnectControl(40);
                        await WaitForBootstrapCompleteAsync(180, "direct guards", 60, BootstrapPinActive());
                        return;
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (PinSuspectBootstrapException) { throw; }
                    catch (Exception ex)
                    {
                        LogMessage?.Invoke(this, $"Direct guards unreachable ({ShortError(ex)}), escalating to bridges...");
                        continue;
                    }
                }
                var cfg = mode == BridgeMode.Custom
                    ? _bridges
                    : new BridgeConfig(mode, new List<string>());
                var resolved = BridgeConfigEngine.Resolve(cfg, PtToolsDir, defaults);
                if (!resolved.UseBridges)
                {
                    LogMessage?.Invoke(this,
                        $"{label} tier unavailable ({string.Join(" ", resolved.Errors)}), skipping.");
                    continue;
                }
                try
                {
                    LogMessage?.Invoke(this, $"Trying {label}...");
                    await StartWithBridgeFallbackAsync(resolved);
                    return;
                }
                catch (OperationCanceledException) { throw; }
                catch (PinSuspectBootstrapException) { throw; }
                catch (Exception ex)
                {
                    LogMessage?.Invoke(this, $"{label} tier exhausted ({ShortError(ex)}), escalating.");
                }
            }
            throw new InvalidOperationException("All bridge tiers failed — no usable path found.");
        }

        async Task WaitForBootstrapAndConnectControl(int attempts = 40)
        {

            for (var i = 0; i < attempts; i++)
            {
                if (_lifetimeCts?.IsCancellationRequested == true)
                    throw new OperationCanceledException("Stop requested during bootstrap.");
                // Fast-fail when the daemon is already gone (bad torrc, dead
                // transport helper, AV kill): without this every dead bridge
                // burns the full ~20s control wait with tor nowhere to be
                // seen ("stuck retrying, tor.exe not running").
                try { if (!_proc.IsRunning) throw TorDiedException("Tor exited before the control port opened"); } catch (OperationCanceledException) { throw; } catch (InvalidOperationException) { throw; }
                _control ??= new TorControlClient("127.0.0.1", ControlPort, _proc.ControlCookiePath);
                if (await _control.ConnectAsync(1000)) return;
                await Task.Delay(500);
            }
            var bridges = _lastResolved?.UseBridges == true;
            throw new TimeoutException(
                _control?.CookieSeen == false
                    ? "Could not connect to Tor control port: the control cookie never appeared (tor may lack permission to write it, or PTor can't read it — different elevated user?)."
                    : bridges
                        ? $"Could not connect to Tor control port after start via {BridgeLabel} — bridge/transport unreachable? Check Config → bridges (wrong lines? censored network? try Snowflake) and Tor's log."
                        : "Could not connect to Tor control port after start.");
        }

        // Concurrent control/daemon death double-fires this; the second entry drops.
        readonly SemaphoreSlim _reconnectGate = new(1, 1);
        volatile bool _reconnecting;

        async Task HandleUnexpectedExit()
        {
            await _reconnectGate.WaitAsync();
            try
            {
                if (_reconnecting) return;
                if (_lifetimeCts?.IsCancellationRequested == true) return; // shut down, not crashed
                // Cold-start failures belong to the start caller (which reports
                // them + clears the busy overlay): reconnecting here would loop
                // "Reconnecting (attempt N)..." over a tor that never came up —
                // the boot-time "stuck retrying, tor.exe flapping" shape. Only
                // an established routing session (RoutingActive) may reconnect.
                if (!RoutingActive) return;
                _reconnecting = true;
            }
            finally { _reconnectGate.Release(); }

            // Pinned to THIS run: a stop+start during the backoff below swaps
            // _lifetimeCts, and the stale run must not hijack the new tor.
            var runCts = _lifetimeCts;
            var runSeq = Volatile.Read(ref _runSeq);

            try
            {
                StateChanged?.Invoke(this, new TorStateChangedEventArgs
                {
                    State = TorState.Reconnecting,
                    Message = $"Reconnecting (attempt {_reconnectAttempt + 1})..."
                });

                _maintenance?.Dispose();
                _control?.Dispose();
                _control = null;

                var delaySec = Math.Min(30, 2 << Math.Min(_reconnectAttempt, 4))
                    + Random.Shared.Next(0, 4); // jitter: no stopwatch-regular retry burst
                _reconnectAttempt++;
                await Task.Delay(TimeSpan.FromSeconds(delaySec));

                // Never resurrect after an explicit stop; the gated restart
                // section below re-checks, so a stop racing the wait wins.
                // Generation check first: any start or stop since entry (even
                // a stop+start that handed us a fresh CTS via a late event)
                // voids this run.
                if (Volatile.Read(ref _runSeq) != runSeq ||
                    !ReferenceEquals(_lifetimeCts, runCts) ||
                    runCts?.IsCancellationRequested == true ||
                    _lifetimeCts?.IsCancellationRequested == true)
                {
                    _reconnectAttempt = 0;
                    _reconnecting = false;
                    return;
                }

                await _lifecycleGate.WaitAsync();
                try
                {
                    // Re-check INSIDE the gate: a stop+start may have slipped
                    // through while waiting for it.
                    if (Volatile.Read(ref _runSeq) != runSeq ||
                        !ReferenceEquals(_lifetimeCts, runCts) ||
                        runCts?.IsCancellationRequested == true ||
                        _lifetimeCts?.IsCancellationRequested == true)
                    {
                        _reconnectAttempt = 0;
                        _reconnecting = false;
                        return;
                    }
                    await _proc.StopAsync();
                    var last = _lastResolved;
                    _proc.Start(last?.UseBridges == true ? last : null);
                }
                finally
                {
                    _lifecycleGate.Release();
                }
                // Reconnect sticks to the winning single candidate: no pool re-probing on a blip.
                var rl = _lastResolved;
                await WaitForBootstrapAndConnectControl(
                    rl?.UseBridges == true && rl.BridgeLines.Count == 1
                        ? AttemptsForLine(rl.BridgeLines[0])
                        : rl?.UseBridges == true ? 120 : 40);

                // Stop during bootstrap: shut the new daemon down, swap in nothing.
                if (_lifetimeCts?.IsCancellationRequested == true)
                {
                    try { await _proc.StopAsync(); } catch { }
                    _reconnectAttempt = 0;
                    _reconnecting = false;
                    return;
                }

                // The stdout 100% flag belongs to the DEAD run: without a
                // reset the bootstrap wait below completes instantly on the
                // new (0%) tor and "reconnects" into cold circuits.
                try { Volatile.Write(ref _stdoutBootstrapped, 0); } catch { }

                // A reconnect is a fresh tor: control-connect only proves it
                // is alive. Declaring success here resumed link ticks into a
                // still-bootstrapping daemon — every tick failed, and after
                // two ladders a healthy pin was "rescued" (wiped) while an
                // unpinned run restarted again: the reconnect-over-and-over
                // loop on both modes. Wait for real bootstrap, pin-aware.
                bool pinActive;
                try { pinActive = BootstrapPinActive(); } catch { pinActive = false; }
                string bsWhat = "direct guards";
                int bsTimeout = 180;
                int bsFreeze = 60;
                try
                {
                    if (rl?.UseBridges == true && rl.BridgeLines.Count == 1)
                    {
                        bsWhat = BridgeHealthStore.ShortName(rl.BridgeLines[0]);
                        bsTimeout = BootstrapTimeoutForLine(rl.BridgeLines[0]);
                        bsFreeze = 120;
                    }
                    else if (rl?.UseBridges == true)
                    {
                        bsWhat = string.IsNullOrEmpty(rl.Label) ? "bridges" : rl.Label;
                        bsTimeout = 300;
                        bsFreeze = 120;
                    }
                }
                catch { }
                try
                {
                    await WaitForBootstrapCompleteAsync(bsTimeout, bsWhat, stallFreezeSec: bsFreeze, pinActive: pinActive);
                }
                catch (OperationCanceledException)
                {
                    try { await _proc.StopAsync(); } catch { }
                    _reconnectAttempt = 0;
                    _reconnecting = false;
                    return;
                }
                catch (PinSuspectBootstrapException pse)
                {
                    // The dead pin survived into the reconnect: restarting
                    // the same torrc again would burn minutes proving the
                    // same point. Park the daemon and hand one signal to the
                    // UI rescue (unpin -> probe -> re-pin). Attempt counter
                    // resets so the link monitor keeps judging if the UI
                    // declines (cooldown) instead of parking paused forever.
                    try { await _proc.StopAsync(); } catch { }
                    _reconnectAttempt = 0;
                    _reconnecting = false;
                    try { LogMessage?.Invoke(this, "Reconnect found the pinned relay(s) blamed by Tor's log — requesting pin auto-recovery instead of looping the same pin..."); } catch { }
                    SignalPinRescue("reconnect bootstrap pins blamed (" + pse.Evidence + ")");
                    return;
                }

                // Stop during bootstrap: shut the new daemon down, swap in nothing.
                if (_lifetimeCts?.IsCancellationRequested == true)
                {
                    try { await _proc.StopAsync(); } catch { }
                    _reconnectAttempt = 0;
                    _reconnecting = false;
                    return;
                }

                // Fresh tor, fresh episode: the old run's success, age and
                // degraded ladders must not judge the cold new daemon, or
                // the first ticks (cold circuits fail even on healthy pins)
                // instantly re-trigger a rescue/restart loop. Reset BEFORE
                // the data-path proof so a passing probe becomes the new
                // baseline; the settle hold is meaningless for a new tor.
                _linkFails = 0;
                _softRecoverStreak = 0;
                _pinDegradedLadders = 0;
                Volatile.Write(ref _pinRescueSignalInFlight, 0);
                Volatile.Write(ref _hadLinkSuccessThisRun, false);
                // Fresh pool for the fresh tor: the old client's pooled
                // connections ran through the DEAD daemon's circuits. Reusing
                // them fails every tick until the pool expires, which the
                // ladder reads as "still dead" and answers with another
                // rescue/restart — the reconnect-over-and-over loop on both
                // pinned and unpinned runs. Fresh starts get this via
                // StartLinkChecks; reconnects need it here.
                try { RecreateLinkClient(); } catch { }
                _lastRotationCompletedUtc = DateTime.MinValue;
                RoutingStartedUtc = DateTime.UtcNow;

                // Pinned data-path proof (same rule as a fresh start): only
                // SUSTAINED explicit tor blame (>= 2 fresh lines) throws
                // (handed to rescue); a slow check URL stays inconclusive
                // and the link ladder judges.
                if (pinActive)
                {
                    try { await VerifyPinnedDataPathAsync(); }
                    catch (OperationCanceledException)
                    {
                        try { await _proc.StopAsync(); } catch { }
                        _reconnectAttempt = 0;
                        _reconnecting = false;
                        return;
                    }
                    catch (PinSuspectBootstrapException pse2)
                    {
                        try { await _proc.StopAsync(); } catch { }
                        _reconnectAttempt = 0;
                        _reconnecting = false;
                        try { LogMessage?.Invoke(this, "Reconnected tor carries no data and Tor's log blames the pinned relay(s) — requesting pin auto-recovery..."); } catch { }
                        SignalPinRescue("reconnected pinned exit carries no data (" + pse2.Evidence + ")");
                        return;
                    }
                }

                // Stop racing the probe: shut the new daemon down, swap in nothing.
                if (_lifetimeCts?.IsCancellationRequested == true)
                {
                    try { await _proc.StopAsync(); } catch { }
                    _reconnectAttempt = 0;
                    _reconnecting = false;
                    return;
                }

                // Pin/stable override survives reconnects: a cached non-zero
                // interval must never resurrect scheduled rotation on a
                // pinned (or stable) run.
                _maintenance = new TorMaintenance(_control!) { RotateIntervalSec = (_pinnedCircuitActive || _stableConnection) ? 0 : SetRotateIntervalCache, KeepAliveIntervalSec = LinkCheckPeriodSec };
                _maintenance.Died += async (_, __) => await HandleUnexpectedExit();
                _maintenance.Start();

                _reconnectAttempt = 0;
                _reconnecting = false;

                LogMessage?.Invoke(this, "Reconnected to Tor — user routing continues.");
            }
            catch (Exception ex)
            {
                _reconnecting = false;
                // Unpark the link monitor: with _reconnectAttempt > 0 every
                // future tick returns early, so a failed reconnect with tor
                // down and routing still ON would wedge the ladder forever
                // (no further rescue, no further retry). The ladder
                // re-escalates on its own cadence if the path stays dead.
                _reconnectAttempt = 0;
                if (_lifetimeCts?.IsCancellationRequested == true) return; // cooperative stop, not failure
                StateChanged?.Invoke(this, new TorStateChangedEventArgs
                {
                    State = TorState.Error,
                    Message = "Reconnect failed: " + ex.Message
                });
            }
        }

        int SetRotateIntervalCache;

        public void SetRotationInterval(int seconds)
        {
            // PIN OVERRIDE: scheduled rotation would rebuild circuits on a
            // timer — exactly the IP-hop the pin exists to prevent. Forced
            // off for the whole run, like stable mode (checked first so the
            // message names the pin, which outranks stable).
            // NOTE: the saved interval cache is deliberately left untouched
            // while pinned — overwriting it to 0 here destroyed the user's
            // saved interval on every pin toggle/start, so rotation never
            // resumed after unpinning (and reconnects inherited the clobbered
            // 0). The live timer is forced off; the cache is the user's.
            if (_pinnedCircuitActive)
            {
                LogMessage?.Invoke(this,
                    "Scheduled rotation stays OFF while circuit pin is on (it would hop IPs). Turn pin off to rotate.");
                if (_maintenance != null)
                {
                    try { _maintenance.RotateIntervalSec = 0; } catch { }
                    try { _maintenance.RestartRotationTimer(); } catch { }
                }
                return;
            }
            if (_stableConnection)
            {
                LogMessage?.Invoke(this,
                    "Scheduled rotation is paused while stable-connection mode is on (it would defeat the purpose).");
                return;
            }
            if (_maintenance != null)
            {
                // Plain run: this IS the user's intent — cache it so tor
                // restarts (reconnects) restore the interval instead of
                // silently dropping scheduled rotation.
                SetRotateIntervalCache = seconds;
                _maintenance.RotateIntervalSec = seconds;
                _maintenance.RestartRotationTimer();
            }
        }

        const int NewNymMinGapSec = 10;
        DateTime _lastNewNymUtc = DateTime.MinValue;

        // Last SUCCESSFUL rotation (manual New ID included). The link ladder
        // must not fire another NEWNYM inside the settle window — tor kills
        // in-flight circuits on rotation and rebuilds lazily, so a second
        // rotation just re-kills the rebuild and blackholes apps in a loop.
        const int RotationSettleHoldSec = 60;
        DateTime _lastRotationCompletedUtc = DateTime.MinValue;

        internal static bool ShouldHoldFireForSettling(DateTime lastCompletedUtc, DateTime now, double holdSec = RotationSettleHoldSec)
        {
            try
            {
                if (lastCompletedUtc == DateTime.MinValue) return false;
                var age = (now - lastCompletedUtc).TotalSeconds;
                return age >= 0 && age < holdSec;
            }
            catch { return false; }
        }

        public async Task<(bool ok, string message)> RotateNowAsync()
        {
            // PIN OVERRIDE: manual New ID sends SIGNAL NEWNYM, which closes
            // circuits and rebuilds — an IP-hop (or churn inside the pinned
            // set). Blocked while the pin is active; this also blocks the
            // automatic link-tick refresh (SoftRecoverDataPathAsync funnels
            // through here), so no path can rotate out from under the pin.
            if (_pinnedCircuitActive)
                return (false, "New identity is disabled while circuit pin is on — turn pin off to rotate (pin keeps one path to stop IP hops).");
            if (_maintenance == null)
                return (false, "Tor isn't running.");
            var gap = (DateTime.UtcNow - _lastNewNymUtc).TotalSeconds;
            if (gap < NewNymMinGapSec)
                return (false, $"Tor rate-limits identity changes — wait {Math.Ceiling(NewNymMinGapSec - gap)}s and try again.");
            _lastNewNymUtc = DateTime.UtcNow;
            var ok = await _maintenance.RotateNowAsync();
            if (ok)
            {
                RecreateLinkClient();

                _ = RefreshExitInfoAsync();
                return (true, "New identity requested — resolving new exit IP…");
            }
            return (false, "Failed to rotate circuit (is Tor running?).");
        }

        void OnRotationCompleted(bool ok)
        {
            if (ok)
            {
                _lastRotationCompletedUtc = DateTime.UtcNow;
                RecreateLinkClient();
                _ = RefreshExitInfoAsync();
                try { CircuitRotated?.Invoke(this, EventArgs.Empty); } catch { }
                // Warm circuits NOW, not on next app demand: a fresh stream
                // forces tor to build immediately, so apps reconnecting after
                // the rotation find live circuits instead of cold ones.
                try
                {
                    var gen = Volatile.Read(ref _linkGen);
                    ScheduleNextLinkTick(gen, TimeSpan.FromSeconds(5));
                }
                catch { }
            }
            LogMessage?.Invoke(this, ok ? "Circuit rotated — new connections use fresh circuits." : "Circuit rotation failed.");
        }

        void RecreateLinkClient()
        {
            try { _linkClient?.Dispose(); } catch { }
            _linkClient = null;
            _linkFails = 0;
            try
            {
                if (_lifetimeCts?.IsCancellationRequested == true) return;
                var handler = new SocketsHttpHandler
                {
                    Proxy = new WebProxy(new Uri($"socks5://127.0.0.1:{SocksPort}")),
                    UseProxy = true,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(2)
                };
                _linkClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(LinkCheckTimeoutSec) };
            }
            catch { }
        }

        public string TorLinkStatus
        {
            get
            {
                try
                {
                    var exit = string.IsNullOrEmpty(ExitCountry) || ExitCountry == "??" ? "" : $" · Exit {ExitCountry}";
                    if (!RoutingActive) return "Tor link: routing off.";
                    if (_lastLinkOkUtc == DateTime.MinValue)
                        return _linkFails > 0 ? $"Tor link: checking… ({_linkFails} failed)" : "Tor link: first check pending…";
                    var age = (int)(DateTime.UtcNow - _lastLinkOkUtc).TotalSeconds;
                    return _linkFails > 0
                        ? $"Tor link: DEGRADED ({_linkFails} failed, last OK {age}s ago){exit}"
                        : $"Tor link: alive (checked {age}s ago){exit}";
                }
                catch { return "Tor link: unknown."; }
            }
        }

        public string ExitIp { get; private set; } = "";
        public string ExitCountry { get; private set; } = "";

        public string ExitLabel =>
            string.IsNullOrEmpty(ExitIp) ? "Exit: —"
            : string.IsNullOrEmpty(ExitCountry) || ExitCountry == "??" ? $"Exit: {ExitIp}"
            : $"Exit: {ExitIp} ({ExitCountry})";

        public event EventHandler? ExitInfoChanged;

        // Fired after a successful rotation so the UI can sweep for apps
        // that fell back to direct connections during the window.
        public event EventHandler? CircuitRotated;

        void SetExitInfo(string ip, string country)
        {
            var changed = !string.Equals(ExitIp, ip, StringComparison.Ordinal) ||
                          !string.Equals(ExitCountry, country, StringComparison.Ordinal);
            ExitIp = ip;
            ExitCountry = country;
            if (changed)
            {
                try { ExitInfoChanged?.Invoke(this, EventArgs.Empty); } catch { }
            }
        }

        static string ParseExitIp(string body)
        {
            try
            {

                var key = body.IndexOf("\"IP\"", StringComparison.Ordinal);
                if (key < 0) return "";
                var colon = body.IndexOf(':', key);
                if (colon < 0) return "";
                var q1 = body.IndexOf('"', colon);
                if (q1 < 0) return "";
                var q2 = body.IndexOf('"', q1 + 1);
                if (q2 < 0) return "";
                var ip = body.Substring(q1 + 1, q2 - q1 - 1).Trim();
                return ip.Length is >= 3 and <= 45 ? ip : "";
            }
            catch { return ""; }
        }

        async Task<string> QueryCountryAsync(string ip)
        {
            try
            {
                var control = _control;
                if (control == null || string.IsNullOrEmpty(ip)) return "??";
                return await control.GetCountryAsync(ip);
            }
            catch { return "??"; }
        }

        // Live circuit pins for the Config "use current circuit" button:
        // returns the (entry, middle, exit) fingerprints of the current
        // BUILT GENERAL circuit via the control port. Nulls when Tor isn't
        // running / no circuit yet. Never throws. Does NOT connect tor
        // itself — only queries the existing control session.
        public async Task<(string? entry, string? middle, string? exit)> GetLiveCircuitNodesAsync()
        {
            try
            {
                var control = _control;
                if (control == null || !control.IsConnected) return (null, null, null);
                return await control.GetLiveCircuitNodesAsync();
            }
            catch { return (null, null, null); }
        }

        public async Task RefreshExitInfoAsync()
        {
            try
            {
                if (_lifetimeCts?.IsCancellationRequested == true) return;
                var handler = new SocketsHttpHandler
                {
                    Proxy = new WebProxy(new Uri($"socks5://127.0.0.1:{SocksPort}")),
                    UseProxy = true
                };
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(LinkCheckTimeoutSec) };
                string ip;
                try
                {
                    using var resp = await client.GetAsync(LinkCheckUrl);
                    resp.EnsureSuccessStatusCode();
                    ip = ParseExitIp(await resp.Content.ReadAsStringAsync());
                }
                catch { return; }
                if (string.IsNullOrEmpty(ip)) return;
                var country = await QueryCountryAsync(ip);
                var first = string.IsNullOrEmpty(ExitIp);
                SetExitInfo(ip, country);
                LogMessage?.Invoke(this, first
                    ? $"Tor exit: {ip} ({country})."
                    : $"Tor exit now: {ip} ({country}) — new connections use it.");
            }
            catch { }
        }

        // Fixed-interval heartbeats are a stopwatch signature on the guard flow: 25–38s uniform.
        internal static TimeSpan NextLinkDelay(Random? rng = null)
        {
            rng ??= Random.Shared;
            return TimeSpan.FromMilliseconds(Math.Max(5000, LinkCheckPeriodSec * 1000 + rng.Next(-5000, 8001)));
        }

        void StartLinkChecks()
        {
            StopLinkChecks();
            var handler = new SocketsHttpHandler
            {
                Proxy = new WebProxy(new Uri($"socks5://127.0.0.1:{SocksPort}")),
                UseProxy = true,
                PooledConnectionLifetime = TimeSpan.FromMinutes(2)
            };
            _linkClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(LinkCheckTimeoutSec) };
            var gen = Interlocked.Increment(ref _linkGen);
            ScheduleNextLinkTick(gen);
        }

        void ScheduleNextLinkTick(int gen, TimeSpan? firstDelay = null)
        {
            Timer? timer = null;
            try
            {
                if (_lifetimeCts?.IsCancellationRequested == true) return;
                if (gen != Volatile.Read(ref _linkGen)) return;
                // Drop the previous one-shot handle first: otherwise every
                // tick leaks a Timer until the finalizer gets around to it.
                try { _linkTimer?.Dispose(); } catch { }
                timer = _linkTimer = new Timer(async _ =>
                {
                    try { await LinkTick(); }
                    finally { if (gen == Volatile.Read(ref _linkGen)) ScheduleNextLinkTick(gen); }
                }, null, firstDelay ?? NextLinkDelay(), Timeout.InfiniteTimeSpan);
            }
            catch { try { timer?.Dispose(); } catch { } }
        }

        void StopLinkChecks()
        {
            Interlocked.Increment(ref _linkGen);
            try { _linkTimer?.Dispose(); } catch { }
            _linkTimer = null;
            try { _linkClient?.Dispose(); } catch { }
            _linkClient = null;
        }

        async Task LinkTick()
        {
            // One-shot timer callbacks can still overlap: atomic slot claim.
            if (System.Threading.Interlocked.CompareExchange(ref _linkBusy, 1, 0) != 0) return;
            try
            {
                await LinkTickCore();
            }
            finally { System.Threading.Interlocked.Exchange(ref _linkBusy, 0); }
        }

        async Task LinkTickCore()
        {
            // Snapshot the client: StopLinkChecks may null the field mid-tick.
            var client = _linkClient;
            if (client == null) return;
            try
            {
                if (_lifetimeCts?.IsCancellationRequested == true) return;
                if (_reconnectAttempt > 0) return;
            }
            catch { return; }

            try
            {
                CheckRoutingIntact();
                try
                {
                    var ecoNote = ReassertEcoMode();
                    if (!string.IsNullOrEmpty(ecoNote)) LogMessage?.Invoke(this, ecoNote);
                }
                catch { }
                using var resp = await client.GetAsync(LinkCheckUrl);
                resp.EnsureSuccessStatusCode();
                _lastLinkOkUtc = DateTime.UtcNow;
                Volatile.Write(ref _hadLinkSuccessThisRun, true);
                _softRecoverStreak = 0;
                // A working stream proves the pinned exit is alive: any
                // earlier degraded ladders were transient (flap), not a dead
                // pin. Reset the rescue episode so a later real death gets
                // its own full signal.
                _pinDegradedLadders = 0;
                Volatile.Write(ref _pinRescueSignalInFlight, 0);

                try
                {
                    var ip = ParseExitIp(await resp.Content.ReadAsStringAsync());
                    if (!string.IsNullOrEmpty(ip) && (ip != ExitIp || string.IsNullOrEmpty(ExitCountry)))
                        SetExitInfo(ip, await QueryCountryAsync(ip));
                }
                catch { }
                if (_linkFails > 0)
                {
                    _linkFails = 0;
                    LogMessage?.Invoke(this, "Tor link recovered — data path OK.");
                }
            }
            catch (ObjectDisposedException)
            {

            }
            catch (Exception ex)
            {
                _linkFails++;
                // TaskCanceledException here is the 20s HttpClient timeout, not
                // a crash: name it plainly instead of leaking exception-ese.
                var why = ex is TaskCanceledException ? "timed out" : ex.GetType().Name;
                LogMessage?.Invoke(this, $"Tor link check failed ({_linkFails}/{LinkFailThreshold}): {why}");
                // Anti-cascade: link checks failing inside the post-rotation
                // settle window mean tor is still rebuilding, not broken —
                // firing another NEWNYM here would re-kill the rebuild and
                // keep every app offline in a loop. Hold fire, reset the
                // ladder, resume fresh after the window. A genuinely dead tor
                // re-trips the ladder within ~90s past settle.
                if (ShouldHoldFireForSettling(_lastRotationCompletedUtc, DateTime.UtcNow))
                {
                    _linkFails = 0;
                    LogMessage?.Invoke(this, "Rotation still settling — holding circuit-refresh fire.");
                    return;
                }
                if (_linkFails >= LinkFailThreshold)
                {
                    _linkFails = 0;
                    var aggravated = ++_softRecoverStreak >= 3;
                    if (aggravated) _softRecoverStreak = 0;

                    // PIN MODE (checked before the generic aggravated path):
                    // a same-pin tor restart cannot fix a retired pinned
                    // relay — it just loops the dead torrc forever (the
                    // reported "no internet while pinned" bug). Count
                    // degraded ladders and hand ONE rescue signal to the UI,
                    // which restarts unpinned and re-pins to a live relay.
                    // Any NEWNYM refresh would churn the pinned path, so it
                    // is never attempted here. Checked before stable because
                    // pin outranks it. Entry-only pins under bridges are
                    // excluded (Tor ignores EntryNodes there — the entry
                    // pick can never be the cause).
                    if (_pinnedCircuitActive)
                    {
                        if (!RuntimePinEffective())
                        {
                            LogMessage?.Invoke(this, "Tor data path degraded — rotation skipped (circuit-pin mode keeps one path). Entry pin is ignored while bridges are in use, so no pin recovery was triggered.");
                        }
                        else
                        {
                            _pinDegradedLadders++;
                            // Warm-up gate (the "always unpinned after reboot"
                            // fix): cold circuits fail the first ticks even on
                            // healthy pins, so a rescue needs a baseline —
                            // either a prior success this run (pin proved
                            // working, now regressed) or a prolonged
                            // never-working run (grace elapsed + enough
                            // ladders that warm-up is ruled out). Without
                            // this, every slow boot wiped a good pin.
                            DateTime startedUtc;
                            try { startedUtc = RoutingStartedUtc ?? DateTime.MinValue; } catch { startedUtc = DateTime.MinValue; }
                            bool gated;
                            try { gated = PinAutoRecovery.ShouldAllowRuntimeRescue(Volatile.Read(ref _hadLinkSuccessThisRun), startedUtc, DateTime.UtcNow, _pinDegradedLadders); }
                            catch { gated = false; }
                            if (!gated)
                            {
                                LogMessage?.Invoke(this, "Tor data path degraded — rotation skipped (circuit-pin mode keeps one path). Still in warm-up (no baseline yet), holding pin auto-recovery fire.");
                            }
                            else if (aggravated)
                            {
                                LogMessage?.Invoke(this, "Tor data path still dead with circuit pin ON — requesting pin auto-recovery (same-pin restart cannot fix a retired relay)...");
                                SignalPinRescue("data path dead through 3 degraded ladders while pinned");
                            }
                            else if (_pinDegradedLadders >= PinAutoRecovery.RuntimeRescueLadders)
                            {
                                LogMessage?.Invoke(this, "Tor data path degraded with circuit pin ON — rotation skipped (pin keeps one path); requesting pin auto-recovery check...");
                                SignalPinRescue($"data path degraded through {_pinDegradedLadders} ladders while pinned");
                            }
                            else
                            {
                                // While the pinned path is dead the proxy
                                // still points at Tor (fail-closed 502s) — but
                                // apps with their own proxy-failure fallback
                                // (or QUIC/UDP, which Tor never carries) go
                                // DIRECT in that window, which reads as "the
                                // pin leaks after some time". Only the packet
                                // layer stops that class: name it while dead.
                                var lockdownNote = "";
                                try { if (!EnforcementActive) lockdownNote = " While Tor is down, apps that fall back (or use QUIC/UDP) go DIRECT — Tor-only lockdown (Config, admin) makes that impossible."; } catch { }
                                LogMessage?.Invoke(this, "Tor data path degraded — rotation skipped (circuit-pin mode keeps one path)." + lockdownNote);
                            }
                        }
                    }
                    else if (aggravated)
                    {
                        LogMessage?.Invoke(this, "Tor data path still dead after circuit refreshes — restarting Tor...");
                        _ = Task.Run(HandleUnexpectedExit);
                    }
                    // Stable mode: rotation would re-pin the exit, defeating
                    // the mode — count toward a restart instead of rotating.
                    else if (_stableConnection)
                    {
                        LogMessage?.Invoke(this, "Tor data path degraded — rotation skipped (stable-connection mode).");
                    }
                    // Rotation can't fix a dead guard/ISP outage: after a few
                    // fruitless rotations, restart tor wholesale instead.
                    else
                    {
                        LogMessage?.Invoke(this, "Tor data path degraded — requesting fresh circuits (no restart)...");
                        _ = SoftRecoverDataPathAsync();
                    }
                }
            }
        }

        bool _routingDiverged;
        // Last divergence warning (see CheckRoutingIntact): the one-shot
        // flag above stays, but a still-diverged state re-warns on this
        // cadence so a single missed status line doesn't hide an
        // hours-long direct leak (GPO refresh / VPN / new NIC after time).
        DateTime _lastDivergeWarnUtc = DateTime.MinValue;
        // Same throttle for the lockdown liveness lines below: they fire
        // immediately on first sight, then repeat at this cadence while the
        // condition persists (link ticks run ~every 30s — unthrottled that
        // would bury every other status line). Reset on stop so a fresh run
        // always warns immediately.
        DateTime _lastEnforceWarnUtc = DateTime.MinValue;

        DateTime _lastResumeUtc = DateTime.MinValue;

        // Sleep/wake and network-flap fast path. Timers freeze during sleep
        // while tor's guard connection dies underneath it; the passive ladder
        // then needs ~3 failed 30s ticks (≈2min) before even trying a circuit
        // refresh, and up to ~9x that before a tor restart — minutes of dead
        // internet after every wake, consistently. Probe NOW instead: if the
        // link survived, just resume; if not, refresh circuits on the spot
        // and pull the next ladder tick forward so a still-dead link keeps
        // escalating without the full idle wait. Debounced; no-op unless
        // routing is on. Never throws.
        public Task ResumeRecoveryAsync()
        {
            return Task.Run(async () =>
            {
                try
                {
                    if (!RoutingActive) return;
                    if (_lifetimeCts?.IsCancellationRequested == true) return;
                    var now = DateTime.UtcNow;
                    if ((now - _lastResumeUtc).TotalSeconds < 30) return;
                    _lastResumeUtc = now;
                    // New NICs (VPN/Wi-Fi/USB tether) appear exactly on this
                    // path with ISP resolvers: point them at loopback NOW
                    // instead of waiting for the next ~30s link tick. With
                    // lockdown their direct-53 is dropped anyway; without it
                    // this closes an outright hostname-leak window.
                    try
                    {
                        if (EnforcementActive)
                        {
                            var note = _dnsMgr.ReassertNewInterfaces();
                            if (!string.IsNullOrEmpty(note)) LogMessage?.Invoke(this, note);
                            try { if (LockdownRequired) ReassertRoutingDetached(); } catch { }
                        }
                    }
                    catch { }
                    LogMessage?.Invoke(this, "System woke / network changed — probing Tor link...");
                    if (await ProbeLinkOnceAsync(TimeSpan.FromSeconds(12)))
                    {
                        _linkFails = 0;
                        LogMessage?.Invoke(this, "Tor link survived the transition — no recovery needed.");
                        return;
                    }
                    LogMessage?.Invoke(this, "Tor link dead after transition — refreshing circuits now...");
                    await SoftRecoverDataPathAsync();
                    try
                    {
                        var gen = Volatile.Read(ref _linkGen);
                        ScheduleNextLinkTick(gen, TimeSpan.FromSeconds(10));
                    }
                    catch { }
                }
                catch { }
            });
        }

        // One-shot end-to-end probe on a FRESH client: pooled connections may
        // themselves be casualties of the transition, so reusing them would
        // report the pool's health, not tor's.
        async Task<bool> ProbeLinkOnceAsync(TimeSpan timeout)
        {
            try
            {
                if (_lifetimeCts?.IsCancellationRequested == true) return true;
                var handler = new SocketsHttpHandler
                {
                    Proxy = new WebProxy(new Uri($"socks5://127.0.0.1:{SocksPort}")),
                    UseProxy = true
                };
                using var client = new HttpClient(handler) { Timeout = timeout };
                using var resp = await client.GetAsync(LinkCheckUrl);
                resp.EnsureSuccessStatusCode();
                _lastLinkOkUtc = DateTime.UtcNow;
                Volatile.Write(ref _hadLinkSuccessThisRun, true);
                return true;
            }
            catch { return false; }
        }

        // Symmetric data-path proof for the pin-rescue flow: the pinned
        // post-bootstrap probe and the unpinned control probe must use the
        // SAME verdict, or a slow/blocked check URL always frames the pin
        // (pinned fails its probe, unpinned never probes, rescue concludes
        // "pin dead" on zero evidence). Public for the UI rescue only;
        // pool-thread safe, never throws, honors stop-racing as success-
        // neutral (a stop is not a pin verdict).
        public Task<bool> ProbeDataPathAsync(TimeSpan timeout)
        {
            return ProbeLinkOnceAsync(timeout);
        }

        // Never-Eco invariant (see EcoModeGuard), re-asserted on the slow
        // link-tick cadence in case the OS or user re-tagged us, tor, or a
        // transport mid-run. Notes only when it actually cleared a tag.
        // Never throws.
        string? ReassertEcoMode()
        {
            try
            {
                var cleared = new List<string>();
                try
                {
                    var m = _proc.ReassertNoEcoMode();
                    if (!string.IsNullOrEmpty(m)) cleared.Add(m);
                }
                catch { }
                try
                {
                    HashSet<int> pts;
                    try { pts = GetTransportPids(); } catch { pts = new HashSet<int>(); }
                    var n = 0;
                    foreach (var pid in pts)
                        try { if (EcoModeGuard.ClearIfTaggedPid(pid)) n++; } catch { }
                    if (n > 0) cleared.Add(n + " transport(s)");
                }
                catch { }
                if (cleared.Count == 0) return null;
                return "Efficiency mode was on " + string.Join(", ", cleared) +
                    " — cleared (a throttled tunnel stalls and risks leaks).";
            }
            catch { return null; }
        }

        void CheckRoutingIntact()
        {
            try
            {
                if (!RoutingActive)
                {
                    _routingDiverged = false;
                    try { _lastEnforceWarnUtc = DateTime.MinValue; } catch { }
                    return;
                }
                // Lockdown liveness FIRST (before the proxy/env/DNS reads):
                // a dead packet filter under "routing on" is a direct leak,
                // not a settings drift — it needs its own loud line, not the
                // generic proxy warning below. Immediate on first sight,
                // throttled repeats (see _lastEnforceWarnUtc); the UI's 1s
                // transition watch covers the instant alarm.
                try
                {
                    var div = _divert;
                    string? enforceWarn = null;
                    if (div != null && !div.Running)
                    {
                        enforceWarn =
                            "WARNING: Tor-only lockdown died while routing stays ON — non-proxy apps may be bypassing Tor right now. " +
                            "Toggle lockdown off/on to recover (traffic is NOT held while the filter is down).";
                        // Strict: driver-gone is the ONE open window
                        // (nothing left to hold) — auto re-engage instead
                        // of warn-only.
                        try { TryRepairEnforcementDetached("filter-down"); } catch { }
                    }
                    else if (div != null && div.Running && div.Degraded)
                    {
                        enforceWarn =
                            "Lockdown DEGRADED (filter held, traffic fails closed/drops — NOT leaking direct). Toggle lockdown off/on to recover.";
                        // Strict: fail-closed already (drops, no leak), but
                        // still try to heal back to healthy automatically.
                        try { TryRepairEnforcementDetached("degraded"); } catch { }
                    }
                    else if (div == null && LockdownRequired)
                    {
                        // Required but never engaged (e.g. died + cleaned, or
                        // start raced): try to engage now, detached.
                        try { TryRepairEnforcementDetached("missing"); } catch { }
                    }
                    if (!string.IsNullOrEmpty(enforceWarn))
                    {
                        try
                        {
                            var sinceWarn = (DateTime.UtcNow - _lastEnforceWarnUtc).TotalMinutes;
                            if (_lastEnforceWarnUtc == DateTime.MinValue || sinceWarn >= 5)
                            {
                                _lastEnforceWarnUtc = DateTime.UtcNow;
                                LogMessage?.Invoke(this, enforceWarn);
                            }
                        }
                        catch { try { LogMessage?.Invoke(this, enforceWarn); } catch { } }
                    }
                }
                catch { }
                // New interfaces (VPN dial-up, Wi-Fi reconnect, USB tether)
                // appear AFTER the DNS swap with ISP resolvers: without
                // lockdown their port-53 bypasses leak hostnames. Re-point
                // them at loopback while enforcement owns DNS.
                try
                {
                    if (EnforcementActive)
                    {
                        var note = _dnsMgr.ReassertNewInterfaces();
                        if (!string.IsNullOrEmpty(note)) LogMessage?.Invoke(this, note);
                    }
                }
                catch { }
                var intact = _proxy.MatchesApplied() && _env.MatchesApplied();
                if (intact && EnforcementActive) intact = _dnsMgr.MatchesApplied();
                // Strict: put back what was overwritten externally instead
                // of warn-only (proxy-only users keep warn-only). Runs on
                // the tick thread (registry writes only, no gate).
                if (!intact && LockdownRequired)
                {
                    try { ReassertRoutingDetached(); } catch { }
                    try
                    {
                        intact = _proxy.MatchesApplied() && _env.MatchesApplied();
                        if (intact && EnforcementActive) intact = _dnsMgr.MatchesApplied();
                        if (intact) _routingDiverged = false;
                    }
                    catch { }
                }
                if (!intact && !_routingDiverged)
                {
                    _routingDiverged = true;
                    _lastDivergeWarnUtc = DateTime.UtcNow;
                    LogMessage?.Invoke(this,
                        "WARNING: system proxy, env vars, or DNS changed externally (VPN connected? another tool?) — " +
                        "apps may be bypassing Tor right now. Toggle routing off/on to re-apply PTor's settings.");
                }
                else if (!intact && _routingDiverged)
                {
                    // Still diverged: re-warn every ~5 min (link ticks run
                    // ~every 30s) instead of staying silent for hours.
                    try
                    {
                        if ((DateTime.UtcNow - _lastDivergeWarnUtc).TotalMinutes >= 5)
                        {
                            _lastDivergeWarnUtc = DateTime.UtcNow;
                            LogMessage?.Invoke(this,
                                "WARNING (still diverged): system proxy/env/DNS still differ from PTor's settings — " +
                                "apps may STILL be bypassing Tor. Toggle routing off/on to re-apply.");
                        }
                    }
                    catch { }
                }
                else if (intact && _routingDiverged)
                {
                    _routingDiverged = false;
                    LogMessage?.Invoke(this, "Routing settings match PTor again.");
                }
            }
            catch { }
        }

        async Task SoftRecoverDataPathAsync()
        {
            try
            {
                if (_maintenance == null) return;
                var (ok, msg) = await RotateNowAsync();
                LogMessage?.Invoke(this, ok ? "Fresh circuits requested." : "Circuit refresh skipped: " + msg);
            }
            catch { }
        }

        // Single-flight rescue signal: the link ladder fires every ~90s
        // while dead, but the UI must attempt at most ONE rescue per
        // degraded episode (its cooldown + single-flight cover the rest).
        // Never throws; pool thread.
        void SignalPinRescue(string reason)
        {
            try
            {
                if (System.Threading.Interlocked.CompareExchange(ref _pinRescueSignalInFlight, 1, 0) != 0) return;
                int ladders;
                try { ladders = _pinDegradedLadders; } catch { ladders = 0; }
                try { PinRescueNeeded?.Invoke(this, new PinRescueNeededEventArgs { Reason = reason ?? "", DegradedLadders = ladders }); }
                catch { }
            }
            catch { }
        }

        // Post-bootstrap proof for pinned runs (see StartCoreInnerAsync):
        // bootstrap 100% with a dead pinned EXIT still "succeeds" at the
        // guard layer while every stream dies — the exact "connected, no
        // internet" report. End-to-end check.torproject.org fetches over
        // FRESH SOCKS clients (no pooled connections) prove the exit
        // carries streams. Throws PinSuspectBootstrapException ONLY on
        // SUSTAINED explicit tor blame (>= 2 fresh pin-blame lines, same
        // rule as the bootstrap wait); passes silently otherwise (including
        // when tor is stopping — a stop racing the probe is not a pin
        // verdict). Rationale: a slow check URL / cold first circuit
        // fails 3x20s probes with zero pin evidence on healthy pins — throwing
        // there wiped a good pin on every slow boot ("always unpinned after
        // reboot"). Unproven probe failures leave routing UP for the link
        // ladder to judge (4min grace + symmetric unpinned probe in the
        // rescue), which rules out warm-up without framing the pin.
        // Retried (3 x PostBootstrapProbeSec) before giving the inconclusive
        // verdict. Never returns a value; only throws pin-suspect or nothing.
        async Task VerifyPinnedDataPathAsync()
        {
            try
            {
                if (_lifetimeCts?.IsCancellationRequested == true) return;
                const int probeAttempts = 3;
                // Fresh-evidence floor: only tor lines logged AFTER the
                // bootstrap completed may blame the pin below. Bootstrap-
                // phase transients ("no such router" pre-consensus on a
                // healthy first boot) linger in the rolling tail — scanning
                // them after a slow-check-URL probe failure framed healthy
                // pins on every slow boot.
                int probeLogStart = 0;
                try { probeLogStart = _proc.GetLogTail()?.Count ?? 0; } catch { }
                for (var attempt = 1; attempt <= probeAttempts; attempt++)
                {
                    try
                    {
                        if (_lifetimeCts?.IsCancellationRequested == true) return;
                        var ok = await ProbeLinkOnceAsync(TimeSpan.FromSeconds(PinAutoRecovery.PostBootstrapProbeSec));
                        if (ok)
                        {
                            if (attempt > 1)
                                try { LogMessage?.Invoke(this, $"Pinned data-path probe succeeded on attempt {attempt}/{probeAttempts} — pin holds."); } catch { }
                            return;
                        }
                        if (_lifetimeCts?.IsCancellationRequested == true) return;
                        if (attempt < probeAttempts)
                        {
                            try { LogMessage?.Invoke(this, $"Pinned data-path probe attempt {attempt}/{probeAttempts} timed out — retrying (cold circuits are slow)..."); } catch { }
                            try { await Task.Delay(TimeSpan.FromSeconds(2), _lifetimeCts?.Token ?? CancellationToken.None); } catch { return; }
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { if (attempt >= probeAttempts) break; }
                }
                if (_lifetimeCts?.IsCancellationRequested == true) return;
                string evidence = "";
                int evidenceHits = 0;
                try
                {
                    var tail = _proc.GetLogTail();
                    if (tail != null && tail.Count > 0)
                    {
                        // Fresh lines only (see probeLogStart above): the
                        // last 12 lines, intersected with post-bootstrap.
                        // SUSTAINED blame only (>= 2 hits, same rule as the
                        // bootstrap wait and the generic-failure upgrade): a
                        // single isolated line is usually a transient retry
                        // note, and throwing on it wiped healthy pins on
                        // every slow boot ("always unpinned after reboot"
                        // while already connected).
                        int from = 0;
                        try { from = Math.Max(0, Math.Min(probeLogStart, tail.Count)); } catch { }
                        int lo = Math.Max(from, tail.Count - 12);
                        for (var i = tail.Count - 1; i >= lo; i--)
                        {
                            try
                            {
                                if (PinAutoRecovery.IsPinFailureLogLine(tail[i]))
                                {
                                    evidenceHits++;
                                    if (string.IsNullOrEmpty(evidence)) evidence = (tail[i] ?? "").Trim();
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
                if (!string.IsNullOrEmpty(evidence) && evidenceHits >= 2)
                    throw new PinSuspectBootstrapException(
                        "Tor bootstrapped but the pinned exit carries no data and tor's log blames the pinned relays (" + evidence + "). " +
                        "Auto-recovery will try an unpinned restart, then re-pin to a live relay.",
                        evidence, true);
                try
                {
                    if (evidenceHits == 1)
                        LogMessage?.Invoke(this, "Pinned data-path probe inconclusive (3 timeouts, only one isolated pin-blame line — needs sustained evidence) — leaving routing up for the link monitor to judge (no auto-unpin on unproven evidence).");
                    else
                        LogMessage?.Invoke(this, "Pinned data-path probe inconclusive (3 timeouts, tor gave no pin verdict) — leaving routing up for the link monitor to judge (no auto-unpin on unproven evidence).");
                }
                catch { }
            }
            catch (PinSuspectBootstrapException) { throw; }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                // Probe plumbing failed in an unexpected way (not a plain
                // timeout): don't fake a pin verdict — let the run continue
                // and the link ladder judge the path instead.
                try { LogMessage?.Invoke(this, "Pinned data-path probe inconclusive (" + ex.GetType().Name + ") — leaving routing up for the link monitor to judge."); } catch { }
            }
        }

        public bool EnforcementAvailable => DivertEnforcement.DriverFilesPresent(_appDir);
        public bool EnforcementActive => _divert?.Running == true;
        // Fail-closed park (filter held, packets dropping): still Running,
        // so EnforcementActive alone reads healthy. The UI badges this
        // separately and the Apps monitor renders Direct rows as Blocked
        // while it holds (attempts are dropped, not delivered).
        public bool EnforcementDegraded
        {
            get { try { var d = _divert; return d != null && d.Running && d.Degraded; } catch { return false; } }
        }

        public string DnsStatus
        {
            get
            {
                try
                {
                    var dns = _dnsFwd;
                    if (dns != null && EnforcementActive)
                        return $"DNS: via Tor (127.0.0.1:53 → Tor DNSPort) · {dns.Forwarded:N0} forwarded · {dns.Failed:N0} failed (SERVFAIL, never clearnet) · {dns.Blocked:N0} local-blocked (no leak).";
                    var snap = _dnsMgr.GetSnapshot();
                    if (snap.Managed)
                        return "DNS: resolver swap still marked managed but forwarder is down — toggle lockdown off/on to repair.";
                    return "DNS: system default (lockdown off).";
                }
                catch { return "DNS: unknown."; }
            }
        }

        public string EnforcementStatus
        {
            get
            {
                try
                {
                    if (_divert?.Running == true)
                    {
                        var dns = _dnsFwd;
                        var dnsPart = dns != null ? $" · dns {dns.Forwarded:N0} via Tor / {dns.Failed:N0} failed" : "";
                        var base_ = $"Enforcement: ON · allowed {_divert.Allowed:N0} · dropped {_divert.Dropped:N0} (non-Tor, non-loopback) · ttl {_divert.TtlNormalized:N0} normalized" + dnsPart;
                        // A parked fail-closed loop still reports Running
                        // (handle held, packets dropping): without this line
                        // it reads as healthy while apps see dead internet.
                        // Toggle lockdown off/on to recover.
                        try
                        {
                            if (_divert.Degraded)
                                base_ += " · DEGRADED (filter held, traffic dropping — toggle lockdown off/on to recover; NOT leaking direct).";
                        }
                        catch { }
                        return base_;
                    }
                    if (!DivertEnforcement.DriverFilesPresent(_appDir))
                        return "Enforcement: unavailable (tools\\WinDivert driver files missing).";
                    try
                    {
                        var audit = DivertBootAudit.Last;
                        if (audit != null && audit.ServiceExists == true && !audit.ServiceLooksOurs && !audit.StaleCheckpointCreated)
                            return "Enforcement: off. Note: a foreign WinDivert service is installed — PTor won't touch it; close the other app first if enabling fails.";
                    }
                    catch { }
                    return "Enforcement: off.";
                }
                catch { return "Enforcement: unknown."; }
            }
        }

        readonly object _enforceGate = new();

        int? TorPidForFilter()
        {
            try { return _proc.CurrentPid; }
            catch { return null; }
        }

        // Identity is (pid, startTime, path): exe+dir stops impostors, start-time stops PID recycling.
        // No enforcement running means no transports of interest: drop
        // retained PIDs instead of carrying dead ones.
        void ClearTransportPids()
        {
            try { lock (_ptGate) { _ptKnown.Clear(); } } catch { }
        }

        // PIDs that ARE the tunnel (daemon + pluggable transports), for UI +
        // verdict purposes. Pool-thread safe. Empty when tor isn't running.
        // This set intentionally matches the Divert allowlist (tor pid +
        // GetTransportPids): anything shown as Engine here is allowed there.
        public List<(int pid, string name, string exePath)> GetEnginePids()
        {
            var out_ = new List<(int pid, string name, string exePath)>();
            try
            {
                int? torPid = null;
                try { torPid = _proc.CurrentPid; } catch { }
                if (torPid == null) return out_;
                try
                {
                    var exe = _proc.TorExePath;
                    out_.Add((torPid.Value, StripExe(System.IO.Path.GetFileName(exe) ?? "tor"), exe));
                }
                catch { }
                HashSet<int> pts;
                try { pts = GetTransportPids(); } catch { pts = new HashSet<int>(); }
                foreach (var pid in pts)
                {
                    if (pid == torPid.Value) continue;
                    try
                    {
                        var exe = RunningAppEnumerator.TryGetExePath(pid);
                        if (string.IsNullOrEmpty(exe)) continue;
                        out_.Add((pid, StripExe(System.IO.Path.GetFileName(exe) ?? "?"), exe));
                    }
                    catch { }
                }
            }
            catch { }
            return out_;
        }

        static string StripExe(string file)
        {
            try
            {
                var dot = file.LastIndexOf('.');
                return dot > 0 ? file.Substring(0, dot) : file;
            }
            catch { return file; }
        }

        // Display verdict for engine rows. Kind 1 (green) and NEVER kind 2:
        // guard/tunnel egress is the tunnel itself, not a leak, so engine
        // rows can never trip the Direct warnings or streaks (those key off
        // kind == 2).
        public static (string label, int kind, string detail) EngineVerdict(string? exeFileName)
        {
            try
            {
                if (!string.IsNullOrEmpty(exeFileName) &&
                    exeFileName.Equals("tor", StringComparison.OrdinalIgnoreCase))
                    return ("Engine", 1, "Tor engine — guard/tunnel traffic is the tunnel itself (not a leak)");
                return ("Engine", 1, "Tor transport helper — bridge traffic (not a leak)");
            }
            catch { return ("Engine", 1, "Tor engine component"); }
        }

        internal HashSet<int> GetTransportPids()
        {
            var out_ = new HashSet<int>();
            try
            {
                int? torPid = null;
                try { torPid = _proc.CurrentPid; } catch { }
                if (torPid == null) { lock (_ptGate) { _ptKnown.Clear(); } return out_; }
                string ptDir;
                try { ptDir = Path.GetFullPath(PtToolsDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar; }
                catch { ptDir = ""; }
                var kids = RunningAppEnumerator.GetChildProcesses(torPid.Value);
                lock (_ptGate)
                {
                    var live = new HashSet<int>();
                    foreach (var k in kids)
                    {
                        string name;
                        try { name = Path.GetFileName(k.ExePath); } catch { continue; }
                        if (!TransportExeNames.Contains(name)) continue;
                        if (!string.IsNullOrEmpty(ptDir))
                        {
                            string full;
                            try { full = Path.GetFullPath(k.ExePath); }
                            catch { continue; }
                            if (!full.StartsWith(ptDir, StringComparison.OrdinalIgnoreCase)) continue;
                        }
                        if (_ptKnown.TryGetValue(k.Pid, out var knownStart) && knownStart != k.StartedUtc)
                            continue; // recycled PID, new occupant: not ours
                        _ptKnown[k.Pid] = k.StartedUtc;
                        live.Add(k.Pid);
                    }
                    foreach (var pid in new System.Collections.Generic.List<int>(_ptKnown.Keys))
                        if (!live.Contains(pid)) _ptKnown.Remove(pid);
                    foreach (var pid in live) out_.Add(pid);
                }
            }
            catch { }
            return out_;
        }

        // Gate FIRST, then enforce lock (StopCoreAsync order). The gate is
        // NOT reentrant: cores assume held, callers are wrappers/StopCoreAsync.
        static readonly TimeSpan GateWait = TimeSpan.FromSeconds(60);

        public string EnableEnforcement()
        {
            // Pool-thread callers only; bounded wait, never UI thread.
            if (!_lifecycleGate.Wait(GateWait))
                throw new InvalidOperationException("Engine is busy (start/stop in flight) — try again in a moment.");
            try
            {
                if (!RoutingActive)
                    throw new InvalidOperationException("Start Tor + routing first — enforcement without routing would take the whole machine offline.");
                lock (_enforceGate) { return EnableEnforcementCore(); }
            }
            finally { _lifecycleGate.Release(); }
        }

        string EnableEnforcementCore(bool allowPreRouting = false)
        {
            // Caller holds gate + enforce lock; guard below is backstop.
            {
                // Re-enable path (driver died under us): the dead handle is
                // already closed by FailDriverGone, but the object still
                // sits in _divert (Running=false) and the old forwarder
                // still holds :53 — both must go before a fresh Open/bind.
                // Resolvers stay at loopback throughout (no ISP restore:
                // no DNS leak window during repair).
                try
                {
                    var old = _divert;
                    if (old != null && !old.Running)
                    {
                        try { old.Dispose(); } catch { }
                        _divert = null;
                    }
                }
                catch { }
                try
                {
                    if (_divert == null && _dnsFwd != null)
                    {
                        try { _dnsFwd.Dispose(); } catch { }
                        _dnsFwd = null;
                    }
                }
                catch { }
                if (EnforcementActive) return "Enforcement already on.";
                if (!AdminHelper.IsAdministrator())
                    throw new NeedAdminException("Packet enforcement needs administrator rights — restart PTor as administrator.");
                // Filter-first startup passes allowPreRouting (tor bootstrapped
                // but RoutingActive not yet flipped): require a live tor either
                // way, and routing unless this is that pre-routing call — an
                // enforcement without any Tor underneath would offline the box.
                if (!_proc.IsRunning || (!RoutingActive && !allowPreRouting))
                    throw new InvalidOperationException("Start Tor + routing first — enforcement without a working Tor underneath would take the whole machine offline.");
                if (!DivertEnforcement.DriverFilesPresent(_appDir))
                    throw new FileNotFoundException("WinDivert driver files not found (expected tools\\WinDivert\\x64 or \\x86).");

                var snap = GetProxySnapshot();
                // hostsHadSection is always false: PTor never touches the OS
                // hosts file (field kept for old-checkpoint compat).
                // dnsWasChanged:true PESSIMISTICALLY: a crash between
                // _dnsMgr.Enable() and the re-stamp below would otherwise
                // leave 127.0.0.1 resolvers with a "false" flag, and next
                // boot would skip the DNS restore. An unnecessary restore
                // when Enable throws early is harmless (Disable no-ops when
                // not managed).
                EnforcementCheckpoint.Create("enforcement-enable",
                    driverFilesPresent: true,
                    proxyServer: snap.Server,
                    envVarCount: _env.GetSnapshot().VarCount,
                    hostsHadSection: false,
                    torExe: _proc.TorExePath,
                    dnsWasChanged: true);

                var div = new DivertEnforcement(TorPidForFilter, msg => LogMessage?.Invoke(this, msg), GetTransportPids);
                DnsForwarder? dns = null;
                try
                {
                    div.Start(_appDir);
                    dns = new DnsForwarder("127.0.0.1", DnsPort);
                    dns.BlockedDomainsProvider = () => _blockedSnapshot;
                    dns.Start();
                    _dnsFwd = dns;
                    // v6 swap only when [::1]:53 actually bound (see
                    // DnsForwarder.Ipv6Bound): a ::1 resolver with nothing
                    // answering breaks DNS outright.
                    LogMessage?.Invoke(this, _dnsMgr.Enable(includeIpv6: dns.Ipv6Bound));
                    if (!dns.Ipv6Bound)
                        LogMessage?.Invoke(this, "IPv6 DNS forwarder unavailable ([::1]:53 would not bind) — IPv6 resolvers left as-is; direct port-53 stays dropped at the packet layer.");
                    // Re-stamp so post-swap crashes restore resolvers too.
                    EnforcementCheckpoint.Create("enforcement-enable",
                        driverFilesPresent: true,
                        proxyServer: snap.Server,
                        envVarCount: _env.GetSnapshot().VarCount,
                        hostsHadSection: false,
                        torExe: _proc.TorExePath,
                        dnsWasChanged: true);
                }
                catch
                {
                    try { _dnsFwd?.Dispose(); } catch { }
                    _dnsFwd = null;
                    try { div.Dispose(); } catch { }
                    try { EnforcementCheckpoint.Delete(); } catch { }
                    throw;
                }
                _divert = div;
                return "Enforcement ON: only Tor + loopback traffic leaves this PC now. " +
                       "Apps ignoring the proxy will fail (no leak) instead of going direct. " +
                       "Killing PTor restores normal traffic instantly — nothing persistent was changed.";
            }
        }

        public string DisableEnforcement()
        {
            if (!_lifecycleGate.Wait(GateWait))
                throw new InvalidOperationException("Engine is busy (start/stop in flight) — try again in a moment.");
            try { lock (_enforceGate) { return DisableEnforcementCore(); } }
            finally { _lifecycleGate.Release(); }
        }

        // Removal-grade ownership for the WinDivert service: checkpoint
        // marker ("created" only) PLUS live image-path corroboration, so a
        // planted/stale marker can never authorize deleting a FOREIGN
        // driver. Unknown/unreadable image fails open to the marker.
        bool OwnsDriverService()
        {
            try
            {
                var cp = EnforcementCheckpoint.Load();
                string? ourSys = null;
                try
                {
                    var dir = DivertEnforcement.LocateDriverDir(_appDir);
                    if (dir != null)
                        ourSys = System.IO.Path.Combine(dir,
                            Environment.Is64BitProcess ? "WinDivert64.sys" : "WinDivert32.sys");
                }
                catch { }
                string? image = null;
                try { image = DivertNative.GetServiceInfo()?.ImagePath; } catch { }
                return EnforcementCheckpoint.IsOursSafe(cp?.DriverService, ourSys, image);
            }
            catch { return false; }
        }

        // Synchronous OWN-service kill: stop + delete the WinDivert service
        // when (and only when) it is provably ours, bounded so a wedged SCM
        // can never park the exit (RunBounded: worst case the bound, then we
        // die and the checkpoint + kill-windivert.bat stay as backstops).
        // The checkpoint is deleted ONLY on verified-gone; anything else
        // keeps it for next-start repair. Never throws. Foreign/pre-existing
        // services are never touched.
        void RemoveOwnDriverServiceSync(List<string> notes)
        {
            void Note(string s) { try { notes.Add(s); } catch { } }
            try
            {
                bool owns = false;
                try { owns = OwnsDriverService(); } catch { owns = false; }
                bool? exists = null;
                try { exists = DivertNative.GetServiceInfo()?.Exists; } catch { }
                if (!owns)
                {
                    // No removal authority: drop a non-ours marker (if any)
                    // so it can never authorize a later delete, and hands off
                    // anything foreign/pre-existing untouched.
                    try
                    {
                        var cp = EnforcementCheckpoint.Load();
                        if (!EnforcementCheckpoint.IsOurs(cp?.DriverService))
                            EnforcementCheckpoint.Delete();
                    }
                    catch { }
                    if (exists == true)
                        Note("driver service left installed (not ours — foreign/pre-existing, never touched).");
                    return;
                }
                if (exists == false)
                {
                    try { EnforcementCheckpoint.Delete(); } catch { }
                    Note("driver service already gone.");
                    return;
                }
                // Ours (or SCM-unreadable with an ours marker): stop + delete
                // NOW, synchronously. There is no WinDivert user-mode process
                // to kill — the driver IS the service; ControlService(STOP) +
                // DeleteService is the kill. Our filter handle is already
                // closed by the caller, so nothing holds it open.
                bool gone = false;
                try
                {
                    var ok = RunBounded(() =>
                    {
                        try { DivertNative.RemoveService(); } catch { }
                        try { var after = DivertNative.GetServiceInfo(); gone = after == null || !after.Exists; }
                        catch { }
                    }, TimeSpan.FromSeconds(3));
                    if (!ok)
                    {
                        // Bound hit (wedged SCM): one instant re-read — the
                        // delete may still have landed underneath us.
                        try { var after = DivertNative.GetServiceInfo(); gone = after == null || !after.Exists; }
                        catch { }
                    }
                }
                catch { }
                if (gone)
                {
                    try { EnforcementCheckpoint.Delete(); } catch { }
                    Note("WinDivert driver service stopped + removed (was ours — no orphan left).");
                }
                else
                    Note("WARNING: own WinDivert service removal timed out — left installed (no filter is active without PTor; next start or kill-windivert.bat as admin removes it).");
            }
            catch (Exception ex) { try { notes.Add("driver removal issue: " + ex.Message); } catch { } }
        }

        string DisableEnforcementCore()
        {
            {
                try { _divert?.Dispose(); }
                catch (Exception ex) { return "Disabling enforcement failed: " + ex.Message; }
                finally { _divert = null; }
                ClearTransportPids();
                string dnsNote;
                try
                {
                    try { _dnsFwd?.Dispose(); } catch { }
                    _dnsFwd = null;
                    dnsNote = _dnsMgr.Disable();
                }
                catch (Exception ex) { dnsNote = "DNS restore failed: " + ex.Message; }
                // Our driver service entry goes too (it was installed for
                // THIS lockdown session): left behind it reads as "still
                // running" and piles up across toggles — and a later exit
                // finds no checkpoint and can no longer tell it is ours.
                // Foreign services are never touched.
                string driverNote = "driver service untouched (not ours or none).";
                try
                {
                    // Removal-grade check (marker + image corroboration):
                    // a stale marker alone never deletes a foreign driver.
                    bool owns = false;
                    try { owns = OwnsDriverService(); } catch { owns = false; }
                    if (owns)
                    {
                        // Handle already disposed above: the driver can unload
                        // so removal verifies instead of pending silently.
                        string res;
                        try { res = DivertNative.RemoveService(); }
                        catch (Exception ex) { res = "remove failed: " + ex.Message; }
                        bool gone = false;
                        try
                        {
                            var after = DivertNative.GetServiceInfo();
                            gone = after == null || !after.Exists;
                        }
                        catch { }
                        driverNote = "driver service: " + res +
                            (gone ? "" : " (WARNING: still present — run kill-windivert.bat as admin)");
                    }
                }
                catch { }
                EnforcementCheckpoint.Delete();
                return "Enforcement OFF: normal traffic restored (proxy routing continues). " + dnsNote + " " + driverNote;
            }
        }

        // Strict-mode self-heal (link-tick pool thread, never UI thread):
        // when lockdown is required but the filter is down/degraded, try to
        // re-engage detached (no gate block: Wait(0), throttled 60s). Repair
        // keeps resolvers at loopback throughout (no ISP-restore window, no
        // DNS leak). Never throws. No-op unless LockdownRequired.
        void TryRepairEnforcementDetached(string why)
        {
            try
            {
                if (!LockdownRequired) return;
                if (!RoutingActive) return;
                if (EnforcementActive && !EnforcementDegraded) return;
                var now = DateTime.UtcNow;
                try
                {
                    if ((now - _lastEnforceRepairUtc).TotalSeconds < 60) return;
                }
                catch { }
                _lastEnforceRepairUtc = now;
                _ = Task.Run(() =>
                {
                    bool taken = false;
                    try
                    {
                        try { taken = _lifecycleGate.Wait(TimeSpan.Zero); } catch { taken = false; }
                        if (!taken) return;
                        try
                        {
                            lock (_enforceGate)
                            {
                                if (EnforcementActive && !EnforcementDegraded) return;
                                string note;
                                try { note = EnableEnforcementCore(); }
                                catch (Exception ex)
                                {
                                    try { LogMessage?.Invoke(this, "Lockdown auto-repair failed (" + why + "): " + ex.Message + " — retrying on next tick. Traffic is NOT held while the filter is down."); } catch { }
                                    return;
                                }
                                try { LogMessage?.Invoke(this, "Lockdown auto-repaired (" + why + "): " + note); } catch { }
                            }
                        }
                        finally { if (taken) { try { _lifecycleGate.Release(); } catch { } } }
                    }
                    catch { }
                });
            }
            catch { }
        }

        // Strict-mode routing re-assert (pool thread, registry writes only,
        // no gate): rewrites APPLIED proxy/env/DNS without touching backups,
        // plus newcomer NICs. No-op unless LockdownRequired. Never throws.
        void ReassertRoutingDetached()
        {
            try
            {
                if (!LockdownRequired) return;
                if (!RoutingActive) return;
                // Proxy/env re-assert even when the filter is down: a diverged
                // proxy with routing ON sends proxy-aware apps direct RIGHT
                // NOW, while the filter repair (detached, throttled) may take
                // a minute. DNS re-assert needs the filter's forwarder, so it
                // stays gated on EnforcementActive.
                var fixed_ = new List<string>();
                try { if (_proxy.ReassertApplied()) fixed_.Add("proxy"); } catch { }
                try { if (_env.ReassertApplied()) fixed_.Add("env"); } catch { }
                if (!EnforcementActive)
                {
                    // Filter down: repair that detached; still report the
                    // proxy/env put-back (it stops an active direct leak now).
                    if (fixed_.Count > 0)
                    {
                        try { LogMessage?.Invoke(this, "Routing re-asserted mid-run (" + string.Join("+", fixed_) + " was overwritten externally — put back; filter repair continues detached)."); } catch { }
                    }
                    return;
                }
                try
                {
                    var dnsNote = _dnsMgr.ReassertNewInterfaces();
                    if (!string.IsNullOrEmpty(dnsNote)) fixed_.Add("dns-new-nic");
                }
                catch { }
                try { if (_dnsMgr.ReassertApplied()) fixed_.Add("dns"); } catch { }
                if (fixed_.Count > 0)
                {
                    try { LogMessage?.Invoke(this, "Routing re-asserted mid-run (" + string.Join("+", fixed_) + " was overwritten externally — put back; toggle routing off/on if you changed it on purpose)."); } catch { }
                }
            }
            catch { }
        }

        string RestoreCheckpointIfUnclean()
        {
            try
            {
                var cp = EnforcementCheckpoint.Load();
                if (cp == null) return "";
                var parts = new System.Text.StringBuilder();
                parts.Append($"Recovered from unclean shutdown (checkpoint {cp.CreatedUtc:yyyy-MM-dd HH:mm} UTC, {cp.Reason}): packet diversion was already gone with the dead process. ");
                if (EnforcementCheckpoint.IsOurs(cp.DriverService))
                {
                    if (AdminHelper.IsAdministrator())
                        parts.Append(DivertNative.RemoveService() + " ");
                    else
                        parts.Append("WinDivert driver service left installed (need admin to remove; harmless without PTor running). ");
                }
                else
                {
                    parts.Append("Driver service untouched (pre-existing or unknown origin). ");
                }
                parts.Append("Routing backups restore automatically the next time routing turns on.");
                if (cp.DnsWasChanged)
                {
                    try { parts.Append(" " + new SystemDnsManager().Disable()); }
                    catch (Exception dex) { parts.Append(" DNS restore issue: " + dex.Message + " "); }
                }
                EnforcementCheckpoint.Delete();
                return parts.ToString();
            }
            catch { return ""; }
        }

        public async Task<string> RollbackCheckpointAsync()
        {
            await _lifecycleGate.WaitAsync();
            try
            {
                var parts = new System.Text.StringBuilder();
                try
                {
                    try { _divert?.Dispose(); } catch { }
                    _divert = null;
                    try { _dnsFwd?.Dispose(); } catch { }
                    _dnsFwd = null;
                    parts.Append("Enforcement stopped. ");
                }
                catch (Exception ex) { parts.Append("Enforcement stop issue: " + ex.Message + " "); }

                var cp = EnforcementCheckpoint.Load();
                if (cp != null && EnforcementCheckpoint.IsOurs(cp.DriverService))
                {
                    if (AdminHelper.IsAdministrator())
                        parts.Append(DivertNative.RemoveService() + " ");
                    else
                        parts.Append("Driver service removal needs admin — left installed (harmless without PTor running). ");
                }
                else if (cp != null)
                {
                    parts.Append("Driver service untouched (pre-existing or unknown origin). ");
                }

                try { parts.Append(RestoreProxyNowCore() + " "); }
                catch (Exception ex) { parts.Append("Proxy/env restore issue: " + ex.Message + " "); }

                try { parts.Append(_dnsMgr.Disable() + " "); }
                catch (Exception ex) { parts.Append("DNS restore issue: " + ex.Message + " "); }

                EnforcementCheckpoint.Delete();
                return "Rollback complete: " + parts.ToString();
            }
            finally
            {
                _lifecycleGate.Release();
            }
        }

        public string SocksEndpoint => $"socks5://127.0.0.1:{RelayPort}";
        public string HttpEndpoint => $"http://127.0.0.1:{BridgePort}";

        public SystemProxyManager.ProxySnapshot GetProxySnapshot() => _proxy.GetSnapshot();

        // Recent tor daemon log lines (Config shows them; empty when tor never started).
        public List<string> GetTorLogTail()
        {
            try { return _proc.GetLogTail(); }
            catch { return new List<string>(); }
        }

        // First tor-log line that blames the circuit pin, or "" when none.
        // Lets the UI upgrade a generic bootstrap TimeoutException (e.g. a
        // control-connect timeout, which never scans the log) into a
        // pin-suspect rescue probe instead of giving up. Never throws.
        public string GetPinEvidenceFromLog()
        {
            try
            {
                var tail = GetTorLogTail();
                if (tail == null) return "";
                foreach (var line in tail)
                {
                    try
                    {
                        if (PinAutoRecovery.IsPinFailureLogLine(line))
                            return (line ?? "").Trim();
                    }
                    catch { }
                }
            }
            catch { }
            return "";
        }

        // How many recent tor-log lines blame the circuit pin (last 50).
        // The generic-failure upgrade path requires >= 2: a single line is
        // usually a stale/transient pre-consensus lookup on a healthy slow
        // boot, and upgrading on it wiped good pins. A genuinely dead
        // StrictNodes pin complains on every retry. Never throws.
        public int CountPinEvidenceFromLog()
        {
            try
            {
                var tail = GetTorLogTail();
                if (tail == null) return 0;
                int n = 0;
                int from = Math.Max(0, tail.Count - 50);
                for (var i = from; i < tail.Count; i++)
                {
                    try { if (PinAutoRecovery.IsPinFailureLogLine(tail[i])) n++; }
                    catch { }
                }
                return n;
            }
            catch { return 0; }
        }

        // Called by the UI after it finishes handling a PinRescueNeeded
        // signal (successfully or not): arms the next degraded episode.
        // Also called implicitly by Start/Stop. Never throws.
        public void ResetPinRescueSignal()
        {
            try
            {
                _pinDegradedLadders = 0;
                Volatile.Write(ref _pinRescueSignalInFlight, 0);
            }
            catch { }
        }

        public string HeaderSpoof
        {
            get { try { return _bridge.SpoofHost; } catch { return ""; } }
            set
            {
                try { _bridge.SpoofHost = (value ?? "").Trim(); } catch { }
                try { _socksRelay.SpoofHost = (value ?? "").Trim(); } catch { }
            }
        }

        // Manual user blocklist snapshot (lowercased, distinct). Published
        // once per edit; every relay reads it live through its provider, so
        // Config add/remove applies to proxied traffic instantly.
        volatile string[] _blockedSnapshot = Array.Empty<string>();

        public void SetBlockedDomains(System.Collections.Generic.IEnumerable<string>? domains)
        {
            try
            {
                if (domains == null) { _blockedSnapshot = Array.Empty<string>(); return; }
                var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var d in domains)
                {
                    if (string.IsNullOrWhiteSpace(d)) continue;
                    var norm = d.Trim().Trim('.').ToLowerInvariant();
                    if (norm.Length > 0) set.Add(norm);
                }
                _blockedSnapshot = set.ToArray();
            }
            catch { }
        }

        // Content policy state. Live: setters push straight into the running
        // relays (per-connection reads), so Config applies without a Tor
        // restart. StartRelays re-applies on every bind.
        bool _blockJs;
        bool _blockWebRtc;
        bool _blockCookies;
        bool _mitmEnabled;
        readonly MitmCaManager _mitmCa = new();

        public bool BlockJs
        {
            get => Volatile.Read(ref _blockJs);
            set
            {
                Volatile.Write(ref _blockJs, value);
                try { _bridge.BlockJs = value; } catch { }
                try { _socksRelay.BlockJs = value; } catch { }
            }
        }

        public bool BlockWebRtc
        {
            get => Volatile.Read(ref _blockWebRtc);
            set
            {
                Volatile.Write(ref _blockWebRtc, value);
                try { _bridge.BlockWebRtc = value; } catch { }
                try { _socksRelay.BlockWebRtc = value; } catch { }
            }
        }

        public bool BlockCookies
        {
            get => Volatile.Read(ref _blockCookies);
            set
            {
                Volatile.Write(ref _blockCookies, value);
                try { _bridge.BlockCookies = value; } catch { }
                try { _socksRelay.BlockCookies = value; } catch { }
            }
        }

        public bool MitmEnabled
        {
            get => Volatile.Read(ref _mitmEnabled);
            set
            {
                Volatile.Write(ref _mitmEnabled, value);
                try { _bridge.MitmEnabled = value; } catch { }
                try { if (value) _bridge.MitmCa = _mitmCa; } catch { }
                try { _socksRelay.MitmEnabled = value; } catch { }
                try { if (value) _socksRelay.MitmCa = _mitmCa; } catch { }
            }
        }

        // WebRTC UDP coverage, engaged automatically: proxies can only refuse
        // WebRTC-over-TCP, but WebRTC's UDP (and QUIC/HTTP3) bypasses every
        // proxy — Tor carries no UDP. The only correct cover is the packet
        // layer, so turning the WebRTC block on auto-engages Tor-only
        // lockdown when possible (admin + available + routing live). The
        // status line always says whether UDP is actually covered.
        public async Task<string> EnsureWebRtcCoverageAsync()
        {
            try
            {
                if (!BlockWebRtc) return "WebRTC block off.";
                if (EnforcementActive)
                    return "WebRTC: TCP refused at the proxies, UDP dropped by Tor-only lockdown.";
                if (!RoutingActive)
                    return "WebRTC: TCP refused at the proxies. UDP cover starts with routing + lockdown.";
                if (!EnforcementAvailable)
                    return "WebRTC: TCP refused at the proxies. UDP NOT covered (lockdown unavailable: WinDivert driver files missing).";
                if (!AdminHelper.IsAdministrator())
                    return "WebRTC: TCP refused at the proxies. UDP NOT covered (lockdown needs administrator rights — restart PTor as administrator).";
                try
                {
                    var msg = await Task.Run(() => EnableEnforcement());
                    return "WebRTC: TCP refused at the proxies. " + msg + " UDP is now dropped at the packet layer.";
                }
                catch (Exception ex)
                {
                    return "WebRTC: TCP refused at the proxies. UDP NOT covered (lockdown failed: " + ex.Message + ")";
                }
            }
            catch (Exception ex) { return "WebRTC coverage check failed: " + ex.Message; }
        }

        public string ContentPolicyStatus
        {
            get
            {
                try
                {
                    var mitm = MitmEnabled
                        ? "HTTPS inspection ON (local-CA decrypt → filter → re-encrypt via Tor; HTTP/2 and HTTP/1.1 both inspected natively, HTTP proxy + SOCKS)"
                        : "HTTPS inspection off (tunnels opaque — only host/port gate applies)";
                    var js = BlockJs
                        ? (MitmEnabled ? "BlockJS ON incl. inspected HTTPS (proxy + SOCKS)" : "BlockJS ON (plain-HTTP only — enable inspection for HTTPS)")
                        : "BlockJS off";
                    var rtc = !BlockWebRtc ? "WebRTC block off"
                        : EnforcementActive ? "WebRTC block ON (TCP refused + UDP dropped by lockdown)"
                        : "WebRTC block ON (TCP refused; UDP needs Tor-only lockdown)";
                    var ck = !BlockCookies ? "Cookie block off"
                        : MitmEnabled ? "Cookie block ON incl. inspected HTTPS (proxy + SOCKS)"
                        : "Cookie block ON (plain-HTTP only — enable inspection for HTTPS)";
                    return "Content policy: " + mitm + " · " + js + " · " + rtc + " · " + ck + ".";
                }
                catch { return "Content policy: unknown."; }
            }
        }

        public string MitmCaStatus
        {
            get
            {
                try
                {
                    var fp = _mitmCa.CaFingerprintSha256();
                    var installed = _mitmCa.IsCaInstalled();
                    var machine = _mitmCa.IsCaInstalledInMachineStore();
                    return "Local CA: " + (installed ? "trusted" : "NOT trusted yet")
                        + " (Windows user trust" + (machine ? " + machine trust" : "") + ") · SHA-256 " + fp
                        + " · public copy: %AppData%\\PTor\\mitm\\ca.crt"
                        + " · Firefox/Thunderbird profiles auto-configured on install"
                        + (MitmEnabled
                            ? (installed ? " · inspecting HTTPS now." : " · WARNING: inspection is ON but the CA is not trusted — browsers will show certificate errors until you install it.")
                            : " · inspection off.");
                }
                catch { return "Local CA: unknown."; }
            }
        }

        // Pool-thread entry points for the Config UI (never call on the UI
        // thread: store access + RSA generation block).
        public string EnsureMitmCa() { try { _mitmCa.EnsureCa(); return "Local CA ready."; } catch (Exception ex) { throw new InvalidOperationException("CA setup failed: " + ex.Message, ex); } }
        public string InstallMitmCa() => _mitmCa.InstallCa();
        public string RemoveMitmCa() => _mitmCa.RemoveCa();
        public string RegenerateMitmCa() => _mitmCa.RegenerateCa();

        public string GetEnvStatus()
        {
            try
            {
                var s = _env.GetSnapshot();
                return s.Managed
                    ? $"Env proxy: ON ({s.VarCount} vars) — newly launched apps inherit HTTP_PROXY/HTTPS_PROXY (browsers fall back to it, Node/Electron/Go/Python/curl read it); loopback stays direct via NO_PROXY. NOT covered: SOCKS-only tools (no ALL_PROXY is published — SOCKS consumers often ignore NO_PROXY, which once shoved apps' own 127.0.0.1 backend calls into Tor). Restart running apps + their terminal."
                    : "Env proxy: off.";
            }
            catch { return "Env proxy: unknown."; }
        }

        string RestoreProxyNowCore()
        {
            // LIFO vs Start (proxy then env): tear down env first, proxy last
            // so a mid-restore crash never leaves proxy pointing at a dead
            // bridge while env still advertises it. Matches StopCoreSync.
            string envNote;
            try { envNote = _env.Disable(); }
            catch (Exception ex) { envNote = "Env restore failed: " + ex.Message; }
            var note = _proxy.Disable();
            RoutingActive = false;
            RoutingStartedUtc = null;
            // System state is back: the boot safety net has nothing to fix.
            try { BootRestore.Remove(); } catch { }
            return envNote + " " + note + " (Running apps keep their launch-time env: env-carrying ones stay on live Tor until restarted.)";
        }

        async Task StopCoreAsync()
        {

            DateTime? windowSince = null;
            try { windowSince = RoutingStartedUtc; } catch { }

            // Cancel first: in-flight reconnect observes the stop instead of resurrecting tor.
            try { _lifetimeCts?.Cancel(); } catch { }

            // The teardown below blocks synchronously (driver Join, process
            // waits, ipconfig): never on the UI thread.
            await Task.Run(() => StopCoreSync(windowSince));
        }

        void StopCoreSync(DateTime? windowSince)
        {
            StopLinkChecks();
            _linkFails = 0;
            _softRecoverStreak = 0;
            _pinDegradedLadders = 0;
            Volatile.Write(ref _pinRescueSignalInFlight, 0);
            // A stop ends all reconnect interest, including a backoff
            // sleeping elsewhere (its generation check makes it stand down).
            _reconnecting = false;
            _reconnectAttempt = 0;
            Interlocked.Increment(ref _runSeq);
            ClearTransportPids();
            // Routing flips OFF first: link/intact ticks stop judging
            // mid-teardown, and any exception below can't strand it ON.
            RoutingActive = false;
            RoutingStartedUtc = null;

            // Tor FIRST (matches the barbaric quit path): killing the daemon
            // + loopback relays before opening the packet filter means no
            // live tor overlaps a direct-open window, and relay clients fail
            // closed (502/refused) instead of leaking during teardown.
            _maintenance?.Dispose();
            _maintenance = null;
            try { _control?.Dispose(); } catch { }
            _control = null;
            try { _bridge.Dispose(); } catch { }
            try { _socksRelay.Dispose(); } catch { }
            try { _proc.StopAsync().GetAwaiter().GetResult(); }
            catch (Exception ex) { ExitTrace.Log("engine stop: tor stop threw " + ex.GetType().Name); }
            SetExitInfo("", "");

            try
            {
                if (_divert != null)
                {
                    // Gate held: core directly (wrapper would deadlock on reentry).
                    LogMessage?.Invoke(this, DisableEnforcementCore());
                }
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, "Stopping enforcement failed: " + ex.Message);
            }

            try
            {
                LogMessage?.Invoke(this, _env.Disable());
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, "Restoring env proxy failed: " + ex.Message);
            }
            try
            {
                var note = _proxy.Disable();
                LogMessage?.Invoke(this, note);
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, "Restoring system proxy failed: " + ex.Message);
            }
            // System state is back: the boot safety net has nothing to fix.
            try { BootRestore.Remove(); } catch { }

            if (windowSince != null)
            {
                try
                {
                    var (shown, total) = RunningAppEnumerator.GetLaunchedSince(windowSince.Value);
                    if (total > 0)
                        LogMessage?.Invoke(this,
                            $"HEADS-UP: {total} app(s) launched while routing was on keep Tor proxy env and stay offline until restarted: " +
                            string.Join(", ", shown) + (total > shown.Count ? $" (+{total - shown.Count} more)" : ""));
                }
                catch { }
            }

            ExitTrace.Log("engine stop: tor already stopped above; verifying");
            VerifyStoppedSync();
            ExitTrace.Log("engine stop: core sync done");
        }

        // Trust-but-verify: a stop that leaves a live tor or managed system
        // settings behind strands the machine (dead proxy/DNS, lingering
        // daemon). Runs inside StopAsync's gate, on a pool thread. Every
        // repair here is idempotent, so clean stops observe nothing to do.
        void VerifyStoppedSync()
        {
            try
            {
                if (_proc.IsRunning)
                {
                    LogMessage?.Invoke(this, "Tor survived stop — force killing...");
                    try { _proc.ForceKill(); } catch { }
                }
            }
            catch { }
            var leftovers = new List<string>();
            try
            {
                if (_divert?.Running == true)
                {
                    try { _divert.Dispose(); } catch { }
                    _divert = null;
                    leftovers.Add("enforcement");
                }
                if (_dnsFwd != null)
                {
                    try { _dnsFwd.Dispose(); } catch { }
                    _dnsFwd = null;
                }
                if (_proxy.GetSnapshot().ManagedByPTor)
                {
                    RestoreProxyNowCore();
                    leftovers.Add("proxy/env");
                }
                if (_dnsMgr.GetSnapshot().Managed)
                {
                    try { _dnsMgr.Disable(); } catch { }
                    leftovers.Add("DNS");
                }
                if (leftovers.Count > 0)
                    LogMessage?.Invoke(this,
                        "Stop verification repaired leftover state (" + string.Join(", ", leftovers) + ").");
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, "Stop verification issue: " + ex.Message);
            }
        }

        public async Task<List<string>> RepairNetworkAsync()
        {
            // Headless recovery for a machine left offline by a killed PTor
            // (proxy/DNS/env are registry state: they survive reboots until
            // something puts them back — this is that something). Best-effort
            // per item; reports what it did. Close PTor first if running.
            // Refuses while lockdown is live: it owns DNS right now, and
            // restoring system resolvers underneath it would just break
            // resolution (direct DNS is dropped under lockdown by design).
            // Refuses while lockdown is live: it owns DNS right now, and
            // restoring system resolvers underneath it would just break
            // resolution (direct DNS is dropped under lockdown by design).
            // Checked INSIDE the gate so lockdown can't engage mid-repair.
            await _lifecycleGate.WaitAsync();
            try
            {
                if (_divert?.Running == true)
                {
                    return new List<string>
                    {
                        "Refused: Tor-only lockdown is currently ON and owns DNS — turn it off first, then repair."
                    };
                }
                return await Task.Run(() =>
                {
                    var lines = new List<string>();
                    try { lines.Add(RestoreProxyNowCore()); }
                    catch (Exception ex) { lines.Add("Proxy/env repair failed: " + ex.Message); }
                    try { lines.Add(_dnsMgr.Disable()); }
                    catch (Exception ex) { lines.Add("DNS repair failed: " + ex.Message); }
                    try { EnforcementCheckpoint.Delete(); lines.Add("Stale checkpoint cleared."); }
                    catch (Exception ex) { lines.Add("Checkpoint clear failed: " + ex.Message); }
                    return lines;
                });
            }
            finally
            {
                _lifecycleGate.Release();
            }
        }

        public async ValueTask DisposeAsync()
        {
            await StopAsync();
            _proc.Dispose();
            try { _lifetimeCts?.Dispose(); } catch { }
            _lifetimeCts = null;
            try { _lifecycleGate.Dispose(); } catch { }
            try { _reconnectGate.Dispose(); } catch { }
        }
    }
}