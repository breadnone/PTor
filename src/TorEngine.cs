using System;
using System.Collections.Generic;
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
        ResolvedBridges? _lastResolved;
        readonly BridgeHealthStore _bridgeHealth = new(BridgeHealthStore.DefaultPath());
        readonly Dictionary<int, DateTime> _ptKnown = new();
        readonly object _ptGate = new();
        static readonly HashSet<string> TransportExeNames = new(StringComparer.OrdinalIgnoreCase)
            { "lyrebird.exe", "conjure-client.exe" };

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

        public TorEngine(string appDir, int socksPort = 9050, int controlPort = 9051, int bridgePort = 9080, int relayPort = 9060, int dnsPort = 9053)
        {
            _appDir = appDir;
            SocksPort = socksPort;
            ControlPort = controlPort;
            BridgePort = bridgePort;
            RelayPort = relayPort;
            DnsPort = dnsPort;

            _proc = new TorProcessManager(appDir, socksPort, controlPort, dnsPort);
            _proc.StateChanged += (_, e) => StateChanged?.Invoke(this, e);
            _proc.UnexpectedExit += async (_, __) => await HandleUnexpectedExit();

            _bridge = new HttpToSocksBridge("127.0.0.1", socksPort, bridgePort);
            _bridge.Relayed += (_, e) =>
            {
                try { TrafficRelayed?.Invoke(this, e); } catch { }
            };

            _socksRelay = new SocksRelay("127.0.0.1", socksPort, relayPort);
            _socksRelay.Relayed += (_, e) =>
            {
                try { TrafficRelayed?.Invoke(this, e); } catch { }
            };
        }

        public async Task StartAsync(
            int rotateEverySec,
            BridgeConfig? bridges = null,
            bool stableConnection = false,
            List<string>? exitCountries = null)
        {
            await _lifecycleGate.WaitAsync();
            try
            {
                _bridges = bridges ?? BridgeConfig.DirectOnly();
                _stableConnection = stableConnection;
                try
                {
                    _proc.MaxCircuitDirtinessSec = stableConnection ? 86400 : 600;
                    _proc.ExitCountries = exitCountries ?? new List<string>();
                }
                catch { }
                if (stableConnection)
                    LogMessage?.Invoke(this, "Stable connection mode: exits hop as rarely as possible (no scheduled rotation).");
                else if ((_proc.ExitCountries?.Count ?? 0) > 0)
                {
                    LogMessage?.Invoke(this,
                        "Entry/exit path: exit preference: " + string.Join(",", _proc.ExitCountries) + " (fallback: any).");
                }
                await StartCoreAsync(rotateEverySec);
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
            await _lifecycleGate.WaitAsync();
            try
            {
                await StopCoreAsync();
            }
            finally
            {
                _lifecycleGate.Release();
            }
        }

        async Task StartCoreAsync(int rotateEverySec)
        {
            _lifetimeCts = new CancellationTokenSource();
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

        async Task StartCoreInnerAsync(int rotateEverySec)
        {

            try
            {
                var report = RestoreCheckpointIfUnclean();
                if (!string.IsNullOrEmpty(report)) LogMessage?.Invoke(this, report);
            }
            catch { }

            PtDefaults? bridgeDefaults = null;
            try
            {
                bridgeDefaults = BridgeConfigEngine.LoadDefaults(
                    Path.Combine(_appDir, "tools", "tor", "pluggable_transports", "pt_config.json"));
            }
            catch { }

            if (_bridges.Mode == BridgeMode.Direct)
            {
                var direct = BridgeConfigEngine.Resolve(BridgeConfig.DirectOnly(), PtToolsDir, bridgeDefaults);
                _proc.Start(null);
                _lastResolved = direct;
                StartRelays();
                await WaitForBootstrapAndConnectControl(40);
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
                    resolved = BridgeConfigEngine.Resolve(_bridges, PtToolsDir, bridgeDefaults);
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

            try
            {
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
            }
            catch (Exception ex)
            {
                // Half-built stack teardown: StopCoreAsync is idempotent.
                await StopCoreAsync();
                throw new InvalidOperationException(
                    "Tor start failed — routing is OFF, tor.exe and internal relays stopped. " +
                    "Details: " + ex.Message, ex);
            }

            _maintenance = new TorMaintenance(_control!) { RotateIntervalSec = rotateEverySec, KeepAliveIntervalSec = LinkCheckPeriodSec };
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

        // One candidate per attempt (best-ranked first); health persists, so steady state burns one bridge per start.
        async Task StartWithBridgeFallbackAsync(ResolvedBridges resolved)
        {
            var ordered = _bridgeHealth.OrderForAttempt(resolved.BridgeLines);
            if (ordered.Count == 0)
                throw new InvalidOperationException("No bridge candidates available.");
            StartRelays();
            Exception? last = null;
            foreach (var line in ordered)
            {
                ThrowIfStopping();
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
                    LogMessage?.Invoke(this,
                        $"Bridge candidate {BridgeHealthStore.ShortName(line)} failed to launch — trying next.");
                    continue;
                }
                try
                {
                    await WaitForBootstrapAndConnectControl(AttemptsForLine(line));
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
                catch (Exception ex)
                {
                    last = ex;
                    _bridgeHealth.RecordResult(line, false);
                    try { await _proc.StopAsync(); } catch { }
                    LogMessage?.Invoke(this,
                        $"Bridge candidate {BridgeHealthStore.ShortName(line)} failed — trying next.");
                    ThrowIfStopping();
                }
            }
            throw new InvalidOperationException(
                "All bridge candidates failed. " + ShortError(last), last);
        }

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
                        return;
                    }
                    catch (OperationCanceledException) { throw; }
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
                _reconnecting = true;
            }
            finally { _reconnectGate.Release(); }

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
                if (_lifetimeCts?.IsCancellationRequested == true)
                {
                    _reconnectAttempt = 0;
                    _reconnecting = false;
                    return;
                }

                await _lifecycleGate.WaitAsync();
                try
                {
                    if (_lifetimeCts?.IsCancellationRequested == true)
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

                _maintenance = new TorMaintenance(_control!) { RotateIntervalSec = SetRotateIntervalCache, KeepAliveIntervalSec = LinkCheckPeriodSec };
                _maintenance.Died += async (_, __) => await HandleUnexpectedExit();
                _maintenance.Start();

                _reconnectAttempt = 0;
                _reconnecting = false;

                LogMessage?.Invoke(this, "Reconnected to Tor — user routing continues.");
            }
            catch (Exception ex)
            {
                _reconnecting = false;
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
            SetRotateIntervalCache = seconds;
            if (_stableConnection)
            {
                LogMessage?.Invoke(this,
                    "Scheduled rotation is paused while stable-connection mode is on (it would defeat the purpose).");
                return;
            }
            if (_maintenance != null)
            {
                _maintenance.RotateIntervalSec = seconds;
                _maintenance.RestartRotationTimer();
            }
        }

        const int NewNymMinGapSec = 10;
        DateTime _lastNewNymUtc = DateTime.MinValue;

        public async Task<(bool ok, string message)> RotateNowAsync()
        {
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
                RecreateLinkClient();
                _ = RefreshExitInfoAsync();
                try { CircuitRotated?.Invoke(this, EventArgs.Empty); } catch { }
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

        void ScheduleNextLinkTick(int gen)
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
                }, null, NextLinkDelay(), Timeout.InfiniteTimeSpan);
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
                using var resp = await client.GetAsync(LinkCheckUrl);
                resp.EnsureSuccessStatusCode();
                _lastLinkOkUtc = DateTime.UtcNow;
                _softRecoverStreak = 0;

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
                LogMessage?.Invoke(this, $"Tor link check failed ({_linkFails}/{LinkFailThreshold}): {ex.GetType().Name}");
                if (_linkFails >= LinkFailThreshold)
                {
                    _linkFails = 0;
                    var aggravated = ++_softRecoverStreak >= 3;
                    if (aggravated) _softRecoverStreak = 0;

                    if (aggravated)
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

        void CheckRoutingIntact()
        {
            try
            {
                if (!RoutingActive) { _routingDiverged = false; return; }
                var intact = _proxy.MatchesApplied() && _env.MatchesApplied();
                if (intact && EnforcementActive) intact = _dnsMgr.MatchesApplied();
                if (!intact && !_routingDiverged)
                {
                    _routingDiverged = true;
                    LogMessage?.Invoke(this,
                        "WARNING: system proxy, env vars, or DNS changed externally (VPN connected? another tool?) — " +
                        "apps may be bypassing Tor right now. Toggle routing off/on to re-apply PTor's settings.");
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

        public bool EnforcementAvailable => DivertEnforcement.DriverFilesPresent(_appDir);
        public bool EnforcementActive => _divert?.Running == true;

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
        {    get
            {
                try
                {
                    if (_divert?.Running == true)
                    {
                        var dns = _dnsFwd;
                        var dnsPart = dns != null ? $" · dns {dns.Forwarded:N0} via Tor / {dns.Failed:N0} failed" : "";
                        return $"Enforcement: ON · allowed {_divert.Allowed:N0} · dropped {_divert.Dropped:N0} (non-Tor, non-loopback) · ttl {_divert.TtlNormalized:N0} normalized" + dnsPart;
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
            try { lock (_enforceGate) { return EnableEnforcementCore(); } }
            finally { _lifecycleGate.Release(); }
        }

        string EnableEnforcementCore()
        {
            // Caller holds gate + enforce lock; guard below is backstop.
            {
                if (EnforcementActive) return "Enforcement already on.";
                if (!AdminHelper.IsAdministrator())
                    throw new NeedAdminException("Packet enforcement needs administrator rights — restart PTor as administrator.");
                if (!_proc.IsRunning || !RoutingActive)
                    throw new InvalidOperationException("Start Tor + routing first — enforcement without a working Tor underneath would take the whole machine offline.");
                if (!DivertEnforcement.DriverFilesPresent(_appDir))
                    throw new FileNotFoundException("WinDivert driver files not found (expected tools\\WinDivert\\x64 or \\x86).");

                var snap = GetProxySnapshot();
                // hostsHadSection is always false: PTor never touches the OS
                // hosts file (field kept for old-checkpoint compat).
                EnforcementCheckpoint.Create("enforcement-enable",
                    driverFilesPresent: true,
                    proxyServer: snap.Server,
                    envVarCount: _env.GetSnapshot().VarCount,
                    hostsHadSection: false,
                    torExe: _proc.TorExePath);

                var div = new DivertEnforcement(TorPidForFilter, msg => LogMessage?.Invoke(this, msg), GetTransportPids);
                DnsForwarder? dns = null;
                try
                {
                    div.Start(_appDir);
                    dns = new DnsForwarder("127.0.0.1", DnsPort);
                    dns.Start();
                    _dnsFwd = dns;
                    LogMessage?.Invoke(this, _dnsMgr.Enable());
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

        string DisableEnforcementCore()
        {
            {
                try { _divert?.Dispose(); }
                catch (Exception ex) { return "Disabling enforcement failed: " + ex.Message; }
                finally { _divert = null; }
                string dnsNote;
                try
                {
                    try { _dnsFwd?.Dispose(); } catch { }
                    _dnsFwd = null;
                    dnsNote = _dnsMgr.Disable();
                }
                catch (Exception ex) { dnsNote = "DNS restore failed: " + ex.Message; }
                EnforcementCheckpoint.Delete();
                return "Enforcement OFF: normal traffic restored (proxy routing continues). " + dnsNote;
            }
        }

        string RestoreCheckpointIfUnclean()
        {
            try
            {
                var cp = EnforcementCheckpoint.Load();
                if (cp == null) return "";
                var parts = new System.Text.StringBuilder();
                parts.Append($"Recovered from unclean shutdown (checkpoint {cp.CreatedUtc:yyyy-MM-dd HH:mm} UTC, {cp.Reason}): packet diversion was already gone with the dead process. ");
                if (cp.DriverService == "created")
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
                if (cp != null && cp.DriverService == "created")
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

        public string HeaderSpoof
        {
            get { try { return _bridge.SpoofHost; } catch { return ""; } }
            set { try { _bridge.SpoofHost = (value ?? "").Trim(); } catch { } }
        }

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
            var note = _proxy.Disable();
            string envNote;
            try { envNote = _env.Disable(); }
            catch (Exception ex) { envNote = "Env restore failed: " + ex.Message; }
            RoutingActive = false;
            RoutingStartedUtc = null;
            return note + " " + envNote + " (Running apps keep their launch-time env: env-carrying ones stay on live Tor until restarted.)";
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
            SetExitInfo("", "");

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
                RoutingActive = false;
                RoutingStartedUtc = null;
                LogMessage?.Invoke(this, note);
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, "Restoring system proxy failed: " + ex.Message);
            }

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

            _maintenance?.Dispose();
            _control?.Dispose();
            _control = null;

            try { _bridge.Dispose(); } catch { }
            try { _socksRelay.Dispose(); } catch { }
            try { _proc.StopAsync().GetAwaiter().GetResult(); } catch { }

            VerifyStoppedSync();
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
        }
    }
}
