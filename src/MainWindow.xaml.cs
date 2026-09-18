using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace PTor
{
    public partial class MainWindow : Window
    {

        // Modern dark dashboard palette. Semantic colors (accent, good,
        // danger, warn, text) keep their exact values — status meaning never
        // shifts with a theme tweak. Surfaces use a cool slate ramp with a
        // dedicated hairline border brush so cards read as elevated.
        static readonly SolidColorBrush BgBrush = new SolidColorBrush(Color.FromRgb(0x19, 0x1C, 0x22));
        static readonly SolidColorBrush PanelBrush = new SolidColorBrush(Color.FromRgb(0x22, 0x26, 0x2E));
        static readonly SolidColorBrush CardBorderBrush = new SolidColorBrush(Color.FromRgb(0x34, 0x3A, 0x46));
        static readonly SolidColorBrush RowAltBrush = new SolidColorBrush(Color.FromRgb(0x26, 0x2B, 0x34));
        static readonly SolidColorBrush AccentBrush = new SolidColorBrush(Color.FromRgb(0x60, 0xCD, 0xFF));
        static readonly SolidColorBrush AccentHoverBrush = new SolidColorBrush(Color.FromRgb(0x7E, 0xD4, 0xFF));
        static readonly SolidColorBrush AccentPressedBrush = new SolidColorBrush(Color.FromRgb(0x3F, 0xA8, 0xD6));
        static readonly SolidColorBrush TextBrush = Brushes.WhiteSmoke;
        static readonly SolidColorBrush DimBrush = new SolidColorBrush(Color.FromRgb(0x9A, 0xA3, 0xB2));
        static readonly SolidColorBrush DangerBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0x6B, 0x6B));
        static readonly SolidColorBrush GoodBrush = new SolidColorBrush(Color.FromRgb(0x4C, 0xD9, 0x64));
        static readonly SolidColorBrush WarnBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0xC1, 0x4C));
        static readonly SolidColorBrush DarkGreenBrush = new SolidColorBrush(Color.FromRgb(0x1E, 0x7F, 0x56));
        static readonly SolidColorBrush DarkGreenHoverBrush = new SolidColorBrush(Color.FromRgb(0x23, 0x90, 0x61));
        static readonly SolidColorBrush DarkGreenPressedBrush = new SolidColorBrush(Color.FromRgb(0x14, 0x66, 0x3F));
        static readonly SolidColorBrush DisabledBrush = new SolidColorBrush(Color.FromRgb(0x2A, 0x2E, 0x37));
        static readonly SolidColorBrush OverlayBrush = new SolidColorBrush(Color.FromArgb(0xE6, 0x19, 0x1C, 0x22));
        static readonly SolidColorBrush FieldBorderBrush = new SolidColorBrush(Color.FromRgb(0x3A, 0x41, 0x50));

        // These brushes are created once and never mutated (all UI updates
        // assign them, never write into them): freeze for cheaper rendering
        // and safe cross-thread reads. TextBrush is a framework frozen brush.
        static MainWindow()
        {
            try
            {
                BgBrush.Freeze(); PanelBrush.Freeze(); CardBorderBrush.Freeze(); RowAltBrush.Freeze();
                AccentBrush.Freeze(); AccentHoverBrush.Freeze(); AccentPressedBrush.Freeze();
                DimBrush.Freeze(); DangerBrush.Freeze(); GoodBrush.Freeze();
                WarnBrush.Freeze(); DarkGreenBrush.Freeze();
                DarkGreenHoverBrush.Freeze(); DarkGreenPressedBrush.Freeze();
                DisabledBrush.Freeze(); OverlayBrush.Freeze(); FieldBorderBrush.Freeze();
            }
            catch { }
        }

        readonly ObservableCollection<RequestLogEntry> _log = new ObservableCollection<RequestLogEntry>();
        readonly ObservableCollection<string> _blockedDomains = new ObservableCollection<string>();
        readonly DomainRoutingHandler _routingHandler;
        readonly HttpClient _client;
        readonly TorEngine _engine;

        readonly Dictionary<string, DateTime> _relayLoggedAt = new();
        const int MaxLogRows = 300;

        NativeTrayIcon _trayIcon;
        ToggleSwitch _torToggle;
        ListView _logView;
        ListView _appsView;
        Button _reqTabBtn;
        Button _appsTabBtn;
        DockPanel _testRow;
        readonly ObservableCollection<MonitoredApp> _appRows = new ObservableCollection<MonitoredApp>();
        // Live engine PIDs (tor.exe + transports), refreshed every monitor
        // tick. UI thread only, like every other _appRows touch. Rows in this
        // set render the Engine verdict and are excluded from Direct verdicts
        // by construction (see the tick below, kind != 2).
        readonly HashSet<int> _enginePids = new HashSet<int>();
        readonly DirectStreakTracker _streakTracker = new DirectStreakTracker();
        // Last enforcement state seen by the 1s monitor tick. The divert
        // loop can die (or degrade) at any moment mid-run; nothing else
        // refreshes the badge then, so the tick watches for transitions and
        // re-badges + logs immediately instead of leaving a stale LOCKDOWN
        // badge over a dead filter (which reads as a silent leak).
        bool? _lastEnforcementSeen;
        bool _lastEnforcementDegradedSeen;
        long _lastRelayEmitTicks;
        DispatcherTimer _appMonitorTimer;
        int _appTick;
        bool _appBusy;
        TextBox _testUrlInput;
        TextBox _rotateSecondsInput;
        Button _newIdentityBtn;
        Button _proxySetupBtn;
        Button _updateBundleBtn;
        readonly TorUpdater _updater;
        readonly AppSettings _settings;
        TextBlock _statusText;
        TextBlock _proxyBadge;
        Border _badgePill;
        Ellipse _statusDot;
        Border _busyOverlay;
        TextBlock _busyText;
        ProgressBar _busyBar;
        Button _forceRetryBtn;
        Button _busyConfigBtn;
        Button _busyStopBtn;
        bool _forceRetrying;
        bool _configOpen;
        readonly List<Control> _busyLockControls = new List<Control>();

        bool _useTor = true;
        bool _shuttingDown;
        bool _updating;
        bool _startingTor;
        bool _watchdogRun;
        string _lastStartError = "";
        int _watchTick;

        // Pin auto-recovery state (UI owns the rescue: settings + restarts).
        // Single-flight across bootstrap + runtime triggers; cooldown stops
        // the start watchdog / link ladder from machine-gunning tor when
        // the whole network is down.
        bool _pinRescuing;
        DateTime _lastPinRescueUtc = DateTime.MinValue;

        // Secret diagnostics panel (Ctrl+Shift+Esc): single live instance,
        // never referenced by any button/menu/Config surface.
        DebugWindow? _debugWindow;

        public MainWindow()
        {
            InitializeComponent();

            _routingHandler = new DomainRoutingHandler(_blockedDomains, OnRequestLogged)
            {
                UseTor = _useTor
            };
            _client = new HttpClient(_routingHandler) { Timeout = TimeSpan.FromSeconds(20) };

            var appDir = AppDomain.CurrentDomain.BaseDirectory;
            _engine = new TorEngine(appDir);
            _updater = new TorUpdater(appDir);
            // Never synchronously Invoke from background threads (shutdown Join/Wait deadlock); BeginInvoke only.
            _engine.StateChanged += (_, e) => SafeBeginInvoke(() => UpdateEngineStatus(e));
            _engine.LogMessage += (_, msg) => SafeBeginInvoke(() => AppendStatusLine(msg));
            _engine.TrafficRelayed += (_, e) => OnTrafficRelayed(e.Host, e.Port, e.Mode, e.SpoofedHost, e.Sni);
            _engine.ExitInfoChanged += (_, __) => SafeBeginInvoke(() => RefreshRoutingBadge());
            _engine.CircuitRotated += (_, __) => _ = PostRotationDirectCheckAsync();
            // Runtime half of pin self-healing: engine signals (pool
            // thread) after consecutive degraded ladders while pinned; the
            // UI marshals to itself and runs the unpin -> re-pin rescue.
            _engine.PinRescueNeeded += (_, e) => SafeBeginInvoke(() => _ = HandlePinRescueSignalAsync(e));

            BuildUi();
            BuildTrayIcon();

            _settings = AppSettings.Load();
            foreach (var d in _settings.BlockedDomains ?? new List<string>())
                if (!string.IsNullOrWhiteSpace(d) && !_blockedDomains.Contains(d.Trim().ToLowerInvariant()))
                    _blockedDomains.Add(d.Trim().ToLowerInvariant());
            try { _engine.SetBlockedDomains(_blockedDomains); } catch { }
            try { _engine.HeaderSpoof = _settings.HeaderSpoof ?? ""; } catch { }
            try { _engine.BlockJs = _settings.BlockJs; } catch { }
            try { _engine.BlockWebRtc = _settings.BlockWebRtc; } catch { }
            try { _engine.BlockCookies = _settings.BlockCookies; } catch { }
            try { _engine.MitmEnabled = _settings.MitmEnabled; } catch { }
            if (_settings.MitmEnabled)
            {
                // RSA CA generation blocks: keep it off the UI thread. If the
                // CA is missing/trustless the Config status line says so.
                _ = System.Threading.Tasks.Task.Run(() =>
                {
                    try { _engine.EnsureMitmCa(); }
                    catch (Exception ex) { SafeBeginInvoke(() => AppendStatusLine("MITM CA setup failed: " + ex.Message)); }
                });
            }
            var uaErr = ApplyUserAgent(_settings.UserAgent ?? "");
            if (uaErr != null) AppendStatusLine(uaErr);
            try { RefreshPinMainUi(); } catch { }
            // Stopped-state title tag must name the SAVED mode on first
            // paint (the engine defaults to Direct until the first start).
            try
            {
                _engine.SyncConfiguredBridges(new BridgeConfig(_settings.BridgeMode,
                    new System.Collections.Generic.List<string>(_settings.CustomBridgeLines ?? new System.Collections.Generic.List<string>())));
            }
            catch { }
            try { RefreshWindowTitle(); } catch { }

            RepopulateAppRows();
            _appMonitorTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _appMonitorTimer.Tick += (_, __) => MainAppMonitorTick();
            _appMonitorTimer.Start();

            _log.CollectionChanged += (_, __) => Dispatcher.BeginInvoke(DispatcherPriority.Background, () =>
            {
                if (_logView.Items.Count > 0)
                    _logView.ScrollIntoView(_logView.Items[_logView.Items.Count - 1]);
            });

            Closing += MainWindow_Closing;
            // Safety net: never leave a ghost tray icon behind, whatever path closed us.
            Closed += (_, __) => { try { _trayIcon.Dispose(); } catch { } };
            try { Application.Current.SessionEnding += (_, __) => OnSystemSessionEnding(); } catch { }
            // Sleep/wake and ISP-flap recovery: without these, a dead guard
            // connection is found only by the passive ~30s link ladder
            // (minutes of dead internet after every wake). Both handlers are
            // fire-and-forget into the engine's debounced probe; never block.
            try
            {
                Microsoft.Win32.SystemEvents.PowerModeChanged += (_, e) =>
                {
                    try { if (e.Mode == Microsoft.Win32.PowerModes.Resume) _ = _engine.ResumeRecoveryAsync(); }
                    catch { }
                };
            }
            catch { }
            try
            {
                System.Net.NetworkInformation.NetworkChange.NetworkAvailabilityChanged += (_, e) =>
                {
                    try { if (e.IsAvailable) _ = _engine.ResumeRecoveryAsync(); }
                    catch { }
                };
            }
            catch { }
            StateChanged += MainWindow_StateChanged;

            _routingHandler.TorSocksHost = "127.0.0.1";
            _routingHandler.TorSocksPort = _engine.SocksPort;

            Loaded += async (_, __) =>
            {
                RemoveLegacyBlocklistCache();
                // Logon-startup self-heal: versioned Release folders move the
                // exe every update, so an ON entry pointing at the old folder
                // must be repointed here; a stale OFF leftover must go.
                try
                {
                    var note = StartupManager.Sync(_settings.StartOnStartup);
                    if (!string.IsNullOrEmpty(note)) AppendStatusLine(note);
                }
                catch { }
                // --minimized (logon startup): land in the tray, tor still
                // auto-starts below. Set before StartTor so the busy overlay
                // progress is visible on restore, not on boot.
                try
                {
                    if (App.StartMinimized)
                    {
                        Hide();
                        try { _trayIcon.Show(); } catch { }
                        try { _trayIcon.SetTooltip("PTor: running in tray — right-click → Exit quits"); } catch { }
                    }
                }
                catch { }
                // Logon-startup grace period: right after logon the network
                // stack is often not ready yet (DHCP, Wi-Fi, VPN) and an
                // instant tor bootstrap dies in TLS handshakes on slow
                // systems. 5s lets the uplink settle; normal launches skip it.
                if (App.StartMinimized && App.IsPrimaryInstance)
                {
                    try
                    {
                        AppendStatusLine("Logon startup: waiting 5s for the network to settle...");
                        await System.Threading.Tasks.Task.Delay(TimeSpan.FromSeconds(5));
                    }
                    catch { }
                    if (_shuttingDown) return;
                }
                _ = BootDivertAuditAsync();
                try { WarnIfStaleStateAtStartup(); } catch { }
                // Primary instance only: rejected second copies never reach
                // for tor (they own no lock and must die without a trace).
                if (_torToggle.IsOn && App.IsPrimaryInstance) await StartTor();
            };
        }

        // One-time cleanup: the filter-list feature is gone; drop its
        // leftover download cache (%AppData%\PTor\blocklists) if a previous
        // version left it behind.
        static void RemoveLegacyBlocklistCache()
        {
            try
            {
                var dir = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PTor", "blocklists");
                if (System.IO.Directory.Exists(dir)) System.IO.Directory.Delete(dir, recursive: true);
            }
            catch { }
        }

        // Stale-state watchdog for the unclean-shutdown hangover (power loss,
        // kill, BSOD with routing on): loopback proxy/DNS/env + markers
        // survive the reboot. Runs once per app boot, primary instance only.
        // When routing is about to auto-start it stays silent (the start flow
        // repairs inline and reports there). Otherwise it says the quiet part
        // out loud — the user may be offline RIGHT NOW with no other signal —
        // and re-arms the boot safety net, so the next logon is covered even
        // if the old net is gone (pre-net version, scrubbed task, ...).
        // Read-only except the re-arm. Never throws.
        void WarnIfStaleStateAtStartup()
        {
            try
            {
                if (!App.IsPrimaryInstance) return;
                bool proxyStale = false, envStale = false, dnsStale = false, cpStale = false;
                try { proxyStale = new SystemProxyManager().WasLeftManaged(); } catch { }
                try { envStale = new UserEnvManager().GetSnapshot().Managed; } catch { }
                try { dnsStale = new SystemDnsManager().WasLeftManaged(); } catch { }
                try { cpStale = EnforcementCheckpoint.Exists(); } catch { }
                if (!proxyStale && !envStale && !dnsStale && !cpStale) return;
                string? netNote = null;
                try { netNote = BootRestore.Ensure(AppDomain.CurrentDomain.BaseDirectory); } catch { }
                bool willAutoStart = false;
                try { willAutoStart = _torToggle.IsOn; } catch { }
                if (willAutoStart) return;
                var bits = new System.Collections.Generic.List<string>();
                if (proxyStale) bits.Add("system proxy");
                if (envStale) bits.Add("env vars");
                if (dnsStale) bits.Add("system DNS");
                if (cpStale) bits.Add("driver checkpoint");
                AppendStatusLine("WARNING: previous session ended uncleanly — " + string.Join(", ", bits) +
                    " still point at PTor, so the internet may be down. Click Start to repair automatically (stale state is restored first), or Config → Repair network." +
                    (string.IsNullOrEmpty(netNote) ? "" : " " + netNote));
            }
            catch { }
        }

        // Every boot: verify WinDivert driver state (single service, ours vs
        // foreign, stale leftovers) BEFORE anything could install or remove a
        // driver. Read-only — this changes nothing on the system.
        async System.Threading.Tasks.Task BootDivertAuditAsync()
        {
            try
            {
                var audit = await System.Threading.Tasks.Task.Run(
                    () => DivertBootAudit.Run(AppDomain.CurrentDomain.BaseDirectory));
                AppendStatusLine(audit.Summary);
            }
            catch (Exception ex)
            {
                AppendStatusLine("WinDivert check failed (no changes made): " + ex.Message);
            }
        }

        void BuildUi()
        {
            Title = "Tor Traffic Router";
            try
            {
                var logo = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "logo.png");
                if (System.IO.File.Exists(logo))
                {
                    var bmp = new System.Windows.Media.Imaging.BitmapImage(new Uri(logo));
                    try { if (bmp.CanFreeze) bmp.Freeze(); } catch { }
                    Icon = bmp;
                }
            }
            catch { }
            Width = 820;
            Height = 660;
            MinWidth = 640;
            MinHeight = 480;
            Background = BgBrush;
            FontFamily = new FontFamily("Segoe UI Variable, Segoe UI");
            WindowStartupLocation = WindowStartupLocation.CenterScreen;

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Content = root;

            var header = new Border
            {
                Background = PanelBrush,
                BorderBrush = CardBorderBrush,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(22, 16, 22, 16)
            };
            Grid.SetRow(header, 0);
            root.Children.Add(header);

            var headerGrid = new Grid();
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            header.Child = headerGrid;

            var titleStack = new StackPanel { Orientation = Orientation.Horizontal };
            _statusDot = new Ellipse { Width = 12, Height = 12, Fill = AccentBrush, Margin = new Thickness(0, 0, 12, 0), VerticalAlignment = VerticalAlignment.Center };
            titleStack.Children.Add(_statusDot);
            titleStack.Children.Add(new TextBlock
            {
                Text = "Tor Traffic Router",
                Foreground = TextBrush,
                FontSize = 20,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });

            _proxyBadge = new TextBlock
            {
                Text = "",
                Foreground = DimBrush,
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center
            };
            // Pill wrapper: hidden while empty (see RefreshRoutingBadge), so
            // no stray outline sits next to the title before first start.
            _badgePill = new Border
            {
                Background = BgBrush,
                BorderBrush = CardBorderBrush,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(10, 3, 10, 4),
                Margin = new Thickness(12, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center,
                Visibility = Visibility.Collapsed,
                Child = _proxyBadge
            };
            titleStack.Children.Add(_badgePill);
            Grid.SetColumn(titleStack, 0);
            headerGrid.Children.Add(titleStack);

            var togglePanel = new StackPanel { Orientation = Orientation.Horizontal };
            togglePanel.Children.Add(new TextBlock
            {
                Text = "Route via Tor",
                Foreground = DimBrush,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 10, 0)
            });
            _torToggle = new ToggleSwitch(AccentBrush) { IsOn = _useTor };
            _torToggle.Toggled += async (_, on) =>
            {
                _useTor = on;
                _routingHandler.UseTor = on;
                if (on) await StartTor();
                else await StopTor();
            };
            togglePanel.Children.Add(_torToggle);
            Grid.SetColumn(togglePanel, 1);
            headerGrid.Children.Add(togglePanel);

            var controlStrip = new Border
            {
                Background = PanelBrush,
                BorderBrush = CardBorderBrush,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(16, 10, 16, 10),
                Margin = new Thickness(16, 12, 16, 0)
            };
            Grid.SetRow(controlStrip, 1);
            root.Children.Add(controlStrip);

            var controlRow = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            controlStrip.Child = controlRow;

            controlRow.Children.Add(new TextBlock
            {
                Text = "Change server every",
                Foreground = DimBrush,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0)
            });

            _rotateSecondsInput = MakeTextBox("0");
            _rotateSecondsInput.Width = 60;
            _busyLockControls.Add(_rotateSecondsInput);
            _rotateSecondsInput.LostFocus += (_, __) => ApplyRotationInterval();
            _rotateSecondsInput.KeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) ApplyRotationInterval(); };
            controlRow.Children.Add(_rotateSecondsInput);

            controlRow.Children.Add(new TextBlock
            {
                Text = "seconds (0 = never)",
                Foreground = DimBrush,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 0, 20, 0)
            });

            _newIdentityBtn = MakeFlatButton("New ID", DarkGreenBrush, TextBrush);
            _newIdentityBtn.Margin = new Thickness(0, 0, 12, 0);
            _busyLockControls.Add(_newIdentityBtn);
            _newIdentityBtn.Click += async (_, __) =>
            {
                // PIN OVERRIDE (UI layer): the pin exists to stop IP hops
                // and NEWNYM is an IP hop, so the engine blocks this too —
                // the dialog below explains why + how to get New ID back
                // (a status line alone is too easy to miss).
                if (IsPinActiveFromSettings() || _engine.PinnedCircuitActive)
                {
                    AppendStatusLine("New identity is disabled while circuit pin is on — turn pin off to rotate (pin keeps one path to stop IP hops).");
                    ShowPinBlocksNewIdDialog();
                    return;
                }
                AppendStatusLine("Requesting new circuit...");
                var (ok, message) = await _engine.RotateNowAsync();
                if (ok) _routingHandler.DropPooledConnections();
                AppendStatusLine(message);
            };
            controlRow.Children.Add(_newIdentityBtn);

            _proxySetupBtn = MakeFlatButton("Config...", DarkGreenBrush, TextBrush);
            _proxySetupBtn.Click += (_, __) => ShowRoutingInfo();
            controlRow.Children.Add(_proxySetupBtn);
            _busyLockControls.Add(_proxySetupBtn);

            _updateBundleBtn = MakeFlatButton("Update", DarkGreenBrush, TextBrush);
            _updateBundleBtn.Margin = new Thickness(12, 0, 0, 0);
            _updateBundleBtn.Click += async (_, __) => await UpdateTorBundle();
            controlRow.Children.Add(_updateBundleBtn);
            _busyLockControls.Add(_updateBundleBtn);

            var restartAppBtn = MakeFlatButton("Restart", DarkGreenBrush, TextBrush);
            restartAppBtn.Margin = new Thickness(12, 0, 0, 0);
            restartAppBtn.Click += async (_, __) => await RestartAppAsync();
            controlRow.Children.Add(restartAppBtn);
            _busyLockControls.Add(restartAppBtn);

            // Discoverable exit: X minimizes to the tray by design (and always
            // has), which reads as "exit doesn't work, tor still runs". This
            // button quits for real — same path as tray → Exit.
            var exitAppBtn = MakeFlatButton("Exit", DarkGreenBrush, TextBrush);
            exitAppBtn.Margin = new Thickness(12, 0, 0, 0);
            exitAppBtn.ToolTip = "Restore network, stop tor.exe (verified), and quit. X only minimizes to the tray.";
            exitAppBtn.Click += (_, __) => ExitApplication();
            controlRow.Children.Add(exitAppBtn);
            _busyLockControls.Add(exitAppBtn);

            var body = new Grid { Margin = new Thickness(16, 12, 16, 12) };
            Grid.SetRow(body, 2);
            root.Children.Add(body);

            var logPanel = new Border
            {
                Background = PanelBrush,
                BorderBrush = CardBorderBrush,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(16)
            };
            body.Children.Add(logPanel);

            var logStack = new DockPanel();
            logPanel.Child = logStack;

            var logTitle = new TextBlock { Text = "Request Log", Foreground = TextBrush, FontWeight = FontWeights.SemiBold, FontSize = 15, Margin = new Thickness(0, 0, 0, 10) };
            DockPanel.SetDock(logTitle, Dock.Top);
            logStack.Children.Add(logTitle);

            var tabRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
            DockPanel.SetDock(tabRow, Dock.Top);
            logStack.Children.Add(tabRow);
            _reqTabBtn = MakeTabButton("Requests", selected: true);
            _reqTabBtn.Click += (_, __) => ShowLogTab(requests: true);
            tabRow.Children.Add(_reqTabBtn);
            _appsTabBtn = MakeTabButton("Apps", selected: false);
            _appsTabBtn.Margin = new Thickness(8, 0, 0, 0);
            _appsTabBtn.Click += (_, __) => ShowLogTab(requests: false);
            tabRow.Children.Add(_appsTabBtn);
            // Locked during updates like everything else behind the overlay.
            _busyLockControls.Add(_reqTabBtn);
            _busyLockControls.Add(_appsTabBtn);

            _testRow = new DockPanel { Margin = new Thickness(0, 0, 0, 10) };
            DockPanel.SetDock(_testRow, Dock.Top);
            logStack.Children.Add(_testRow);

            var goBtn = MakeButton("Send", AccentBrush, Brushes.Black);
            DockPanel.SetDock(goBtn, Dock.Right);
            goBtn.Margin = new Thickness(8, 0, 0, 0);
            goBtn.Click += async (_, __) => await SendTestRequest();
            _testRow.Children.Add(goBtn);
            _busyLockControls.Add(goBtn);

            _testUrlInput = MakeTextBox("https://check.torproject.org");
            _testRow.Children.Add(_testUrlInput);
            _busyLockControls.Add(_testUrlInput);

            _logView = new ListView
            {
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Foreground = TextBrush,
                ItemsSource = _log,
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment = VerticalAlignment.Stretch,
                HorizontalContentAlignment = HorizontalAlignment.Stretch
            };
            ScrollViewer.SetHorizontalScrollBarVisibility(_logView, ScrollBarVisibility.Disabled);
            var gridView = new GridView();
            gridView.Columns.Add(new GridViewColumn { Header = "Time", DisplayMemberBinding = new System.Windows.Data.Binding("Time"), Width = 70 });
            gridView.Columns.Add(new GridViewColumn { Header = "Method", DisplayMemberBinding = new System.Windows.Data.Binding("Method"), Width = 75 });
            gridView.Columns.Add(new GridViewColumn { Header = "Host", DisplayMemberBinding = new System.Windows.Data.Binding("Host"), Width = 175 });
            gridView.Columns.Add(new GridViewColumn { Header = "Route", DisplayMemberBinding = new System.Windows.Data.Binding("Route"), Width = 60 });
            gridView.Columns.Add(new GridViewColumn { Header = "Status", DisplayMemberBinding = new System.Windows.Data.Binding("Status"), Width = 140 });
            _logView.View = gridView;
            StyleGridHeaders(_logView);
            StyleListRows(_logView);

            _appsView = new ListView
            {
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Foreground = TextBrush,
                ItemsSource = _appRows,
                Visibility = Visibility.Collapsed,
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment = VerticalAlignment.Stretch,
                HorizontalContentAlignment = HorizontalAlignment.Stretch
            };
            ScrollViewer.SetHorizontalScrollBarVisibility(_appsView, ScrollBarVisibility.Disabled);
            var appsGrid = new GridView();
            appsGrid.Columns.Add(new GridViewColumn { Header = "PID", DisplayMemberBinding = new System.Windows.Data.Binding("Pid"), Width = 50 });
            appsGrid.Columns.Add(new GridViewColumn { Header = "Name", DisplayMemberBinding = new System.Windows.Data.Binding("Name"), Width = 120 });
            appsGrid.Columns.Add(MonitoredApp.CreateHealthColumn(70));
            appsGrid.Columns.Add(new GridViewColumn { Header = "Detail", DisplayMemberBinding = new System.Windows.Data.Binding("Detail"), Width = 150 });
            _appsView.View = appsGrid;
            StyleGridHeaders(_appsView);
            StyleListRows(_appsView);
            // Both lists share one filling host cell: in a DockPanel only the
            // last child fills, so adding two ListViews directly left the
            // Requests list docked to content width (empty dark gap on the
            // right in the screenshot). A single host Grid fills instead and
            // both lists stretch inside it, toggled by Visibility.
            var listHost = new Grid
            {
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment = VerticalAlignment.Stretch
            };
            listHost.Children.Add(_logView);
            listHost.Children.Add(_appsView);
            // Last child of the DockPanel fills remaining space.
            logStack.Children.Add(listHost);
            FillLastColumn(_logView);
            FillLastColumn(_appsView);

            var footer = new Border
            {
                Background = PanelBrush,
                BorderBrush = CardBorderBrush,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(22, 10, 22, 12)
            };
            Grid.SetRow(footer, 3);
            root.Children.Add(footer);

            _statusText = new TextBlock { Foreground = DimBrush, FontSize = 12, TextWrapping = TextWrapping.Wrap };
            footer.Child = _statusText;
            _statusText.Text = "Idle. Toggle \"Route via Tor\" to start tor.exe.";

            // Boot modal: hit-testable overlay swallows mouse; strip locked for keyboard.
            _busyText = new TextBlock
            {
                Foreground = TextBrush,
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                HorizontalAlignment = HorizontalAlignment.Center,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 14)
            };
            _busyBar = new ProgressBar
            {
                Width = 300,
                Height = 8,
                Minimum = 0,
                Maximum = 100,
                IsIndeterminate = true,
                HorizontalAlignment = HorizontalAlignment.Center
            };
            var busyStack = new StackPanel
            {
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            busyStack.Children.Add(_busyText);
            busyStack.Children.Add(_busyBar);
            // Boot-stuck escape hatches: they live ON the overlay (the only
            // layer clickable while starting). Force Retry kills stuck
            // tor/helpers/own driver and reboots with current settings;
            // Config opens the settings even mid-bootstrap so a bad bridge
            // mode can be reverted without killing the app; Stop aborts the
            // in-flight start back to idle. All three show only while a
            // start/rescue is in flight — never during bundle updates.
            var busyBtnRow = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 12, 0, 0)
            };
            _forceRetryBtn = MakeFlatButton("Force Retry", DarkGreenBrush, TextBrush);
            // Fixed size: it lives in an auto-width StackPanel, so without
            // this it stretches to the widest sibling (busy text / bar) and
            // jitters in and out as the status line changes length.
            _forceRetryBtn.Width = 110;
            _forceRetryBtn.HorizontalAlignment = HorizontalAlignment.Center;
            _forceRetryBtn.Visibility = Visibility.Collapsed;
            _forceRetryBtn.ToolTip = "Boot stuck? Barbarically kill tor + helpers + our driver (a foreign driver is never touched) and restart with current settings.";
            _forceRetryBtn.Click += async (_, __) => await ForceRetryFromUiAsync();
            busyBtnRow.Children.Add(_forceRetryBtn);
            _busyConfigBtn = MakeFlatButton("Config...", DarkGreenBrush, TextBrush);
            _busyConfigBtn.Width = 110;
            _busyConfigBtn.Margin = new Thickness(10, 0, 0, 0);
            _busyConfigBtn.HorizontalAlignment = HorizontalAlignment.Center;
            _busyConfigBtn.Visibility = Visibility.Collapsed;
            _busyConfigBtn.ToolTip = "Open Config even while starting — revert a bad bridge mode, then Force Retry to apply it.";
            _busyConfigBtn.Click += (_, __) => OpenConfigSafe();
            busyBtnRow.Children.Add(_busyConfigBtn);
            _busyStopBtn = MakeFlatButton("Stop", DarkGreenBrush, TextBrush);
            _busyStopBtn.Width = 110;
            _busyStopBtn.Margin = new Thickness(10, 0, 0, 0);
            _busyStopBtn.HorizontalAlignment = HorizontalAlignment.Center;
            _busyStopBtn.Visibility = Visibility.Collapsed;
            _busyStopBtn.ToolTip = "Abort the in-flight start and go back to idle (routing OFF).";
            _busyStopBtn.Click += async (_, __) => await StopStartFromBusyAsync();
            busyBtnRow.Children.Add(_busyStopBtn);
            busyStack.Children.Add(busyBtnRow);
            // Card around the busy content so the modal reads as a dialog,
            // not floating text on a dim layer.
            var busyCard = new Border
            {
                Background = PanelBrush,
                BorderBrush = CardBorderBrush,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(32, 26, 32, 26),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Child = busyStack
            };
            _busyOverlay = new Border
            {
                Background = OverlayBrush,
                Visibility = Visibility.Collapsed,
                Child = busyCard
            };
            Grid.SetRowSpan(_busyOverlay, 4);
            Panel.SetZIndex(_busyOverlay, 100);
            root.Children.Add(_busyOverlay);
        }

        Button MakeTabButton(string text, bool selected)
        {
            var btn = new Button
            {
                Content = text,
                Background = selected ? AccentBrush : PanelBrush,
                Foreground = selected ? Brushes.Black : TextBrush,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(10, 3, 10, 3),
                MinWidth = 64,
                FontWeight = FontWeights.SemiBold,
                Cursor = System.Windows.Input.Cursors.Hand
            };
            // Slim chrome; Background/Foreground stay live properties so
            // ShowLogTab keeps working by assignment. Unselected tabs read
            // as outlined via the hairline border.
            var template = new ControlTemplate(typeof(Button));
            var border = new FrameworkElementFactory(typeof(Border));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(2));
            border.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Button.BackgroundProperty));
            border.SetValue(Border.BorderBrushProperty, CardBorderBrush);
            border.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            border.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Button.PaddingProperty));
            var content = new FrameworkElementFactory(typeof(ContentPresenter));
            content.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            content.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            border.AppendChild(content);
            template.VisualTree = border;

            var hover = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hover.Setters.Add(new Setter(Control.OpacityProperty, 0.85));
            template.Triggers.Add(hover);
            var disabled = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
            disabled.Setters.Add(new Setter(Button.BackgroundProperty, DisabledBrush));
            disabled.Setters.Add(new Setter(Button.ForegroundProperty, DimBrush));
            template.Triggers.Add(disabled);

            btn.Template = template;
            return btn;
        }

        static void FillLastColumn(ListView lv)
        {
            if (lv.View is not GridView gv || gv.Columns.Count == 0) return;
            void Update()
            {
                try
                {
                    if (!lv.IsVisible || lv.ActualWidth <= 0) return;
                    double used = 0;
                    for (var i = 0; i < gv.Columns.Count - 1; i++)
                        used += gv.Columns[i].ActualWidth;
                    var last = gv.Columns[gv.Columns.Count - 1];
                    var avail = lv.ActualWidth - used - SystemParameters.VerticalScrollBarWidth - 10;
                    var target = Math.Max(60, avail);
                    if (Math.Abs(last.Width - target) > 1)
                        last.Width = target;
                }
                catch { }
            }
            lv.SizeChanged += (_, __) => Update();
            lv.IsVisibleChanged += (_, e) => { if ((bool)e.NewValue) Update(); };
            lv.Loaded += (_, __) => Update();
            lv.Dispatcher.BeginInvoke(
                System.Windows.Threading.DispatcherPriority.Loaded,
                new Action(Update));
        }

        void ShowLogTab(bool requests)
        {
            _logView.Visibility = requests ? Visibility.Visible : Visibility.Collapsed;
            _testRow.Visibility = requests ? Visibility.Visible : Visibility.Collapsed;
            _appsView.Visibility = requests ? Visibility.Collapsed : Visibility.Visible;
            _reqTabBtn.Background = requests ? AccentBrush : PanelBrush;
            _reqTabBtn.Foreground = requests ? Brushes.Black : TextBrush;
            _appsTabBtn.Background = requests ? PanelBrush : AccentBrush;
            _appsTabBtn.Foreground = requests ? TextBrush : Brushes.Black;
        }

        Button MakeButton(string text, Brush bg, Brush fg)
        {
            var btn = new Button
            {
                Content = text,
                Background = bg,
                Foreground = fg,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(10, 3, 10, 3),
                FontWeight = FontWeights.SemiBold,
                Cursor = System.Windows.Input.Cursors.Hand
            };
            btn.Template = BuildRoundedButtonTemplate(AccentHoverBrush, AccentPressedBrush);
            return btn;
        }

        // Shared rounded chrome for buttons. Hover/pressed brushes are
        // parameters so the accent (Send) and emerald (actions) variants
        // keep their own ramps; disabled + border stay uniform. Background
        // and Foreground remain live Button properties — every existing
        // assignment (ShowLogTab, disabled triggers) keeps working.
        static ControlTemplate BuildRoundedButtonTemplate(Brush hoverBrush, Brush pressedBrush)
        {
            var template = new ControlTemplate(typeof(Button));
            var border = new FrameworkElementFactory(typeof(Border));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(2));
            border.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Button.BackgroundProperty));
            border.SetValue(Border.BorderBrushProperty, CardBorderBrush);
            border.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            // Without this the Button.Padding above is silently dropped by
            // the custom chrome and the text touches the edges.
            border.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Button.PaddingProperty));
            var content = new FrameworkElementFactory(typeof(ContentPresenter));
            content.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            content.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            border.AppendChild(content);
            template.VisualTree = border;

            var hover = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hover.Setters.Add(new Setter(Button.BackgroundProperty, hoverBrush));
            template.Triggers.Add(hover);
            var pressed = new Trigger { Property = Button.IsPressedProperty, Value = true };
            pressed.Setters.Add(new Setter(Button.BackgroundProperty, pressedBrush));
            template.Triggers.Add(pressed);
            var disabled = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
            disabled.Setters.Add(new Setter(Button.BackgroundProperty, DisabledBrush));
            disabled.Setters.Add(new Setter(Button.ForegroundProperty, DimBrush));
            template.Triggers.Add(disabled);
            return template;
        }

        Button MakeFlatButton(string text, Brush bg, Brush fg)
        {
            var btn = new Button
            {
                Content = text,
                Background = bg,
                Foreground = fg,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(10, 3, 10, 3),
                Cursor = System.Windows.Input.Cursors.Hand
            };
            btn.Template = BuildRoundedButtonTemplate(DarkGreenHoverBrush, DarkGreenPressedBrush);
            return btn;
        }

        // Rounded field chrome. The PART_ContentHost name is load-bearing:
        // a TextBox template without it cannot edit. Focus ring uses the
        // accent so keyboard users can see where they are.
        static ControlTemplate BuildTextBoxTemplate()
        {
            var template = new ControlTemplate(typeof(TextBox));
            var border = new FrameworkElementFactory(typeof(Border));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(7));
            border.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(TextBox.BackgroundProperty));
            border.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(TextBox.BorderBrushProperty));
            border.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            border.SetValue(Border.PaddingProperty, new TemplateBindingExtension(TextBox.PaddingProperty));
            var host = new FrameworkElementFactory(typeof(ScrollViewer), "PART_ContentHost");
            host.SetValue(ScrollViewer.VerticalAlignmentProperty, VerticalAlignment.Center);
            border.AppendChild(host);
            template.VisualTree = border;

            var focused = new Trigger { Property = UIElement.IsKeyboardFocusedProperty, Value = true };
            focused.Setters.Add(new Setter(TextBox.BorderBrushProperty, AccentBrush));
            template.Triggers.Add(focused);
            var disabled = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
            disabled.Setters.Add(new Setter(TextBox.BackgroundProperty, DisabledBrush));
            disabled.Setters.Add(new Setter(TextBox.ForegroundProperty, DimBrush));
            template.Triggers.Add(disabled);
            return template;
        }

        TextBox MakeTextBox(string initialText)
        {
            var box = new TextBox
            {
                Text = initialText,
                Background = BgBrush,
                Foreground = TextBrush,
                CaretBrush = TextBrush,
                BorderBrush = FieldBorderBrush,
                Padding = new Thickness(10, 6, 10, 6),
                VerticalContentAlignment = VerticalAlignment.Center
            };
            box.Template = BuildTextBoxTemplate();
            return box;
        }

        // Quiet GridView headers: small caps-ish dim labels on the app
        // background instead of the default gray button chrome. Applied via
        // the ListView's own resources so it scopes to that list only.
        // Selection/hover behavior is untouched.
        static void StyleGridHeaders(ListView lv)
        {
            try
            {
                var style = new Style(typeof(GridViewColumnHeader));
                style.Setters.Add(new Setter(Control.BackgroundProperty, BgBrush));
                style.Setters.Add(new Setter(Control.ForegroundProperty, DimBrush));
                style.Setters.Add(new Setter(Control.FontSizeProperty, 11.0));
                style.Setters.Add(new Setter(Control.FontWeightProperty, FontWeights.SemiBold));
                style.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(6, 5, 6, 5)));
                style.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
                style.Setters.Add(new Setter(Control.HorizontalContentAlignmentProperty, HorizontalAlignment.Left));
                lv.Resources[typeof(GridViewColumnHeader)] = style;
            }
            catch { }
        }

        // Subtle zebra rows + preserved selection/hover feedback. Nothing
        // here is read by logic (selection is display-only: no SelectedItem
        // consumers exist), but feedback stays so the lists don't feel dead.
        static void StyleListRows(ListView lv)
        {
            try
            {
                lv.AlternationCount = 2;
                var style = new Style(typeof(ListViewItem));
                style.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.Transparent));
                style.Setters.Add(new Setter(Control.ForegroundProperty, TextBrush));
                style.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(2)));
                var alt = new Trigger { Property = ItemsControl.AlternationIndexProperty, Value = 1 };
                alt.Setters.Add(new Setter(Control.BackgroundProperty, RowAltBrush));
                style.Triggers.Add(alt);
                var hover = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
                hover.Setters.Add(new Setter(Control.BackgroundProperty, CardBorderBrush));
                style.Triggers.Add(hover);
                var selected = new Trigger { Property = ListViewItem.IsSelectedProperty, Value = true };
                selected.Setters.Add(new Setter(Control.BackgroundProperty, FieldBorderBrush));
                selected.Setters.Add(new Setter(Control.ForegroundProperty, TextBrush));
                style.Triggers.Add(selected);
                lv.ItemContainerStyle = style;
            }
            catch { }
        }

        // Single-flight: overlapping starts (tray double-fire, watcher vs
        // user) previously raced the busy overlay off while a bootstrap was
        // still running. Returns whether a start actually ran.
        // Single rule for the main window: toggle ON plus at least one
        // valid node across the three positions. Mirrors
        // TorProcessManager.IsPinActiveRaw (kept local so the UI never
        // depends on engine run state — settings are the source of truth
        // for what the NEXT start will do).
        bool IsPinActiveFromSettings()
        {
            try
            {
                return TorProcessManager.IsPinActiveRaw(
                    _settings.PinnedCircuitEnabled,
                    _settings.PinnedEntryNodes, _settings.PinnedMiddleNodes, _settings.PinnedExitNodes);
            }
            catch { return false; }
        }

        // Secret hotkey: Ctrl+Shift+Esc toggles the diagnostics panel.
        // NOTE: this combo is owned by Windows (Task Manager opens too —
        // no app can suppress that); e.Handled only stops in-app bubbling.
        // Window-focused only: a global hook could never win against the OS.
        protected override void OnPreviewKeyDown(KeyEventArgs e)
        {
            try
            {
                if (e.Key == Key.Escape && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
                {
                    try { e.Handled = true; } catch { }
                    try { ToggleDebugWindow(); } catch { }
                    return;
                }
            }
            catch { }
            base.OnPreviewKeyDown(e);
        }

        void ToggleDebugWindow()
        {
            try
            {
                var w = _debugWindow;
                if (w != null)
                {
                    try
                    {
                        if (w.IsLoaded)
                        {
                            try { w.Close(); } catch { }
                            _debugWindow = null;
                            return;
                        }
                    }
                    catch { _debugWindow = null; }
                }
                var fresh = new DebugWindow(_engine) { Owner = this };
                _debugWindow = fresh;
                try { fresh.Closed += (_, __) => { try { if (ReferenceEquals(_debugWindow, fresh)) _debugWindow = null; } catch { } }; } catch { }
                try { fresh.Show(); } catch { _debugWindow = null; }
            }
            catch { }
        }

        // While pin is active the rotation box is overridden to 0 — it is
        // disabled so the override is visible. New ID stays ENABLED on
        // purpose: a disabled button can't be pressed, and the press is
        // what surfaces the red "why + how to get it back" dialog.
        // Called after Config closes and after starts.
        void RefreshPinMainUi()
        {
            try
            {
                var pin = IsPinActiveFromSettings();
                try
                {
                    _rotateSecondsInput.IsEnabled = !pin;
                    _rotateSecondsInput.ToolTip = pin
                        ? "Scheduled rotation is forced OFF while circuit pin is on."
                        : null;
                }
                catch { }
                try
                {
                    _newIdentityBtn.IsEnabled = true;
                    _newIdentityBtn.ToolTip = pin
                        ? "New ID is blocked while circuit pin is on — press for details (turn pin off + restart Tor to re-enable)."
                        : "Request a new identity (fresh circuits, new exit IP).";
                }
                catch { }
            }
            catch { }
        }

        // Red-header modal shown when New ID is pressed while the circuit
        // pin is on. MessageBox can't carry a red header, so this builds a
        // small themed Window inline (same dark palette as the rest of the
        // app). Owner only when actually visible: a modal parented to a
        // hidden window waits for an answer nobody can see (freeze).
        // Never throws.
        void ShowPinBlocksNewIdDialog()
        {
            try
            {
                var visible = false;
                try { visible = IsVisible; } catch { }
                var dlg = new Window
                {
                    Title = "New ID unavailable",
                    Width = 470,
                    SizeToContent = SizeToContent.Height,
                    MinWidth = 380,
                    MaxWidth = 540,
                    Background = BgBrush,
                    FontFamily = new FontFamily("Segoe UI Variable, Segoe UI"),
                    WindowStartupLocation = visible ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen,
                    ResizeMode = ResizeMode.NoResize,
                    ShowInTaskbar = false
                };
                if (visible) { try { dlg.Owner = this; } catch { } }

                var root = new DockPanel { LastChildFill = true };

                var header = new Border
                {
                    Background = DangerBrush,
                    Padding = new Thickness(14, 10, 14, 10)
                };
                DockPanel.SetDock(header, Dock.Top);
                header.Child = new TextBlock
                {
                    Text = "⚠ New ID unavailable while pinning is on",
                    Foreground = Brushes.White,
                    FontWeight = FontWeights.Bold,
                    FontSize = 15,
                    TextWrapping = TextWrapping.Wrap
                };
                root.Children.Add(header);

                var body = new StackPanel { Margin = new Thickness(14, 12, 14, 12) };
                root.Children.Add(body);
                body.Children.Add(new TextBlock
                {
                    Foreground = TextBrush,
                    FontSize = 13,
                    TextWrapping = TextWrapping.Wrap,
                    Text = "New ID closes your circuits and builds new ones — a new exit IP. " +
                           "The circuit pin exists to prevent exactly that (one stable path, no IP hops), " +
                           "so New ID stays blocked while the pin is on."
                });
                body.Children.Add(new TextBlock
                {
                    Foreground = TextBrush,
                    FontSize = 13,
                    FontWeight = FontWeights.SemiBold,
                    Margin = new Thickness(0, 10, 0, 4),
                    Text = "To use New ID again:"
                });
                body.Children.Add(new TextBlock
                {
                    Foreground = DimBrush,
                    FontSize = 13,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(8, 0, 0, 2),
                    Text = "1. Open Config → entry/exit path → turn the circuit pin OFF."
                });
                body.Children.Add(new TextBlock
                {
                    Foreground = DimBrush,
                    FontSize = 13,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(8, 0, 0, 2),
                    Text = "2. Restart Tor (toggle off/on) — or restart the app — so the unpinned path takes effect."
                });
                body.Children.Add(new TextBlock
                {
                    Foreground = DimBrush,
                    FontSize = 13,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(8, 0, 0, 0),
                    Text = "3. Press New ID again."
                });

                var buttons = new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    HorizontalAlignment = HorizontalAlignment.Right,
                    Margin = new Thickness(0, 14, 0, 0)
                };
                body.Children.Add(buttons);
                var openConfig = false;
                var configBtn = MakeFlatButton("Open Config...", DarkGreenBrush, TextBrush);
                configBtn.Margin = new Thickness(0, 0, 8, 0);
                configBtn.Click += (_, __) => { openConfig = true; try { dlg.Close(); } catch { } };
                buttons.Children.Add(configBtn);
                var okBtn = MakeButton("OK", AccentBrush, Brushes.Black);
                okBtn.IsDefault = true;
                okBtn.IsCancel = true;
                okBtn.Click += (_, __) => { try { dlg.Close(); } catch { } };
                buttons.Children.Add(okBtn);

                dlg.Content = root;
                try { dlg.ShowDialog(); } catch { }
                if (openConfig)
                {
                    try { ShowRoutingInfo(); } catch { }
                }
            }
            catch { }
        }

        async System.Threading.Tasks.Task<bool> StartTor()
        {
            if (_startingTor) return false;
            _startingTor = true;
            // Generation claim: if a Force Retry supersedes this run, the
            // catch/finally below stand down silently (no toggle/overlay
            // teardown under the successor).
            var gen = _engine.BeginStart();
            _torToggle.IsEnabled = false;
            SetBusy(true, "Starting Tor…");
            try
            {
                var (rotateSecs, bridges, exitCountries, pinEnabled, pinEntry, pinMiddle, pinExit) = GetStartArgs();
                bool requireLockdown = false;
                try { requireLockdown = _settings.EnforceTorOnly || _settings.BlockWebRtc; } catch { }
                try { _engine.LockdownRequired = requireLockdown; } catch { }
                await _engine.StartAsync(rotateEverySec: rotateSecs, bridges: bridges,
                    stableConnection: _settings.StableExitEnabled, exitCountries: exitCountries,
                    maxCircuitDirtinessSec: _settings.CircuitDirtinessSec,
                    circuitStreamTimeoutSec: _settings.CircuitStreamTimeoutSec,
                    restrictiveFirewall: _settings.RestrictiveFirewallOnly,
                    pinnedCircuitEnabled: pinEnabled,
                    pinnedEntryNodes: pinEntry, pinnedMiddleNodes: pinMiddle, pinnedExitNodes: pinExit,
                    requireLockdown: requireLockdown);
                RefreshPinMainUi();
                await MaybeEnableEnforcementAsync();
                _ = WarnAboutSecureDnsAsync();
            }
            catch (OperationCanceledException)
            {
                if (gen != _engine.CurrentStartGeneration) return false;
                // Intentional stop landed mid-start: not a failure, just release the UI.
                AppendStatusLine("Start cancelled (stop requested).");
                _torToggle.IsOn = false;
                _useTor = false;
                _routingHandler.UseTor = false;
            }
            catch (Exception ex)
            {
                if (gen != _engine.CurrentStartGeneration) return false;
                // Watchdog retries every 15s: don't spam the same failure line.
                if (!_watchdogRun || ex.Message != _lastStartError)
                    AppendStatusLine("Failed to start Tor: " + ex.Message);
                _lastStartError = ex.Message;
                _statusDot.Fill = DangerBrush;
                _torToggle.IsOn = false;
                _useTor = false;
                _routingHandler.UseTor = false;
                // BOOTSTRAP HALF of pin self-healing (bug: yesterday's pinned
                // relay retired overnight -> stuck bootstrap forever): if the
                // failure is pin-suspect, probe once unpinned inside this
                // same start (busy overlay stays up) instead of leaving the
                // user dark. Success flips the toggle back on below.
                try
                {
                    if (await TryPinBootstrapRescueAsync(ex))
                    {
                        _lastStartError = "";
                        var on = _engine.RoutingActive;
                        _useTor = on;
                        _routingHandler.UseTor = on;
                        try { _torToggle.IsOn = on; } catch { }
                    }
                }
                catch { }
            }
            finally
            {
                if (gen == _engine.CurrentStartGeneration)
                {
                    SetBusy(false);
                    _torToggle.IsEnabled = true;
                    _startingTor = false;
                }
            }
            return _engine.RoutingActive;
        }

        (int rotateSecs, BridgeConfig bridges, System.Collections.Generic.List<string> exitCountries, bool pinEnabled, System.Collections.Generic.List<string> pinEntry, System.Collections.Generic.List<string> pinMiddle, System.Collections.Generic.List<string> pinExit) GetStartArgs()
        {
            var rotateSecs = ParseRotateSeconds();
            var bridges = new BridgeConfig(_settings.BridgeMode,
                new System.Collections.Generic.List<string>(_settings.CustomBridgeLines ?? new System.Collections.Generic.List<string>()));
            var exitCountries = _settings.ExitGeoEnabled
                ? TorPathOptions.ResolveExitCountries(_settings.ExitRegion, _settings.ExitCustomCountries)
                : new System.Collections.Generic.List<string>();
            // PIN OVERRIDE (source layer): parse once here so every start
            // path (normal + force-retry) carries the same sanitized lists.
            // When active, scheduled rotation is forced to 0 at the source
            // (engine re-forces it too — defense in depth) and geo is
            // cleared (torrc would skip it anyway — belt and suspenders).
            var pinEntry = TorProcessManager.ParsePinnedNodes(_settings.PinnedEntryNodes);
            var pinMiddle = TorProcessManager.ParsePinnedNodes(_settings.PinnedMiddleNodes);
            var pinExit = TorProcessManager.ParsePinnedNodes(_settings.PinnedExitNodes);
            var pinEnabled = _settings.PinnedCircuitEnabled;
            var pinActive = pinEnabled && (pinEntry.Count + pinMiddle.Count + pinExit.Count) > 0;
            if (pinActive)
            {
                rotateSecs = 0;
                exitCountries = new System.Collections.Generic.List<string>();
            }
            return (rotateSecs, bridges, exitCountries, pinEnabled, pinEntry, pinMiddle, pinExit);
        }

        async System.Threading.Tasks.Task MaybeEnableEnforcementAsync()
        {
            RefreshRoutingBadge();
            // Lockdown engages at start when the user asked for it directly
            // (EnforceTorOnly) OR when the WebRTC block needs its UDP cover:
            // proxies can't touch WebRTC/QUIC UDP, so BlockWebRtc implies
            // lockdown whenever possible. The engine already engages it
            // inline during Start (same gate, no window) when elevated; this
            // is the backstop for repairs + non-elevated warnings. Runs after
            // every start (and force retry), so enabling the WebRTC block
            // while stopped still gets its UDP cover on the next start.
            var wantLockdown = _settings.EnforceTorOnly || _settings.BlockWebRtc;
            if (wantLockdown && !_engine.EnforcementActive)
            {
                if (_engine.EnforcementAvailable && AdminHelper.IsAdministrator())
                {
                    try { AppendStatusLine(await System.Threading.Tasks.Task.Run(() => _engine.EnableEnforcement())); }
                    catch (Exception ex) { AppendStatusLine("Tor-only lockdown wanted but failed to engage: " + ex.Message); }
                    RefreshRoutingBadge();
                }
                else if (!AdminHelper.IsAdministrator())
                {
                    AppendStatusLine("Tor-only lockdown wanted"
                        + (_settings.BlockWebRtc ? " (WebRTC block needs its UDP cover)" : "")
                        + " — skipped (needs administrator rights). Flip it in Config when elevated.");
                }
            }
        }

        // Secure-DNS (DoH) tripwire, once per successful start: DoH bypasses
        // Tor DNS without lockdown (hostname leak to the DoH provider) and
        // breaks page loads under lockdown (direct DoH is dropped by design).
        // Read-only check (never writes browser prefs); warns only on Bad
        // rows so automatic/off profiles stay silent. Pool thread. Never throws.
        System.Threading.Tasks.Task WarnAboutSecureDnsAsync()
        {
            return System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    if (_shuttingDown || _updating) return;
                    if (!_engine.RoutingActive) return;
                    var notes = BrowserDnsCheck.Run();
                    if (notes == null) return;
                    var bad = new System.Collections.Generic.List<string>();
                    foreach (var n in notes)
                    {
                        try { if (n != null && n.Bad) bad.Add(n.Browser + ": " + n.Detail); }
                        catch { }
                        if (bad.Count >= 3) break;
                    }
                    if (bad.Count == 0) return;
                    SafeBeginInvoke(() => AppendStatusLine("WARNING (DNS leak): " + string.Join(" · ", bad) +
                        " — Secure DNS bypasses Tor DNS without lockdown and breaks under it. Set it to off/automatic so names resolve via Tor."));
                }
                catch { }
            });
        }

        // Barbaric unstick for a wedged boot, from the busy overlay's Force
        // Retry button (the only entry point; hidden unless a start is in
        // flight). Owns the busy UI from here: the superseded StartTor
        // stands down silently via the start generation. Single-flight.
        async System.Threading.Tasks.Task ForceRetryFromUiAsync()
        {
            if (_forceRetrying) return;
            if (_pinRescuing)
            {
                AppendStatusLine("Force retry refused — pin auto-recovery is running. Wait for it to finish.");
                return;
            }
            _forceRetrying = true;
            // The start watchdog only watches _startingTor: without this it
            // launches a second StartTor mid-retry (gate-serialized into a
            // double bootstrap — the boot-loop shape on both pinned and
            // unpinned runs). The finally below already clears it.
            _startingTor = true;
            _torToggle.IsEnabled = false;
            try
            {
                var (rotateSecs, bridges, exitCountries, pinEnabled, pinEntry, pinMiddle, pinExit) = GetStartArgs();
                SetBusy(true, "Force retry: killing stuck tor + helpers + own driver…");
                AppendStatusLine("Force retry: killing stuck tor + helpers + own driver, then restarting with current settings…");
                bool requireLockdownFR = false;
                try { requireLockdownFR = _settings.EnforceTorOnly || _settings.BlockWebRtc; } catch { }
                try { _engine.LockdownRequired = requireLockdownFR; } catch { }
                var report = await _engine.ForceRetryAsync(rotateEverySec: rotateSecs, bridges: bridges,
                    stableConnection: _settings.StableExitEnabled, exitCountries: exitCountries,
                    maxCircuitDirtinessSec: _settings.CircuitDirtinessSec,
                    circuitStreamTimeoutSec: _settings.CircuitStreamTimeoutSec,
                    restrictiveFirewall: _settings.RestrictiveFirewallOnly,
                    pinnedCircuitEnabled: pinEnabled,
                    pinnedEntryNodes: pinEntry, pinnedMiddleNodes: pinMiddle, pinnedExitNodes: pinExit,
                    requireLockdown: requireLockdownFR);
                AppendStatusLine("Force retry done: " + report);
                RefreshPinMainUi();
                await MaybeEnableEnforcementAsync();
                var on = _engine.RoutingActive;
                _useTor = on;
                _routingHandler.UseTor = on;
                try { _torToggle.IsOn = on; } catch { }
            }
            catch (Exception ex)
            {
                AppendStatusLine("Force retry failed: " + ex.Message);
            }
            finally
            {
                _forceRetrying = false;
                _startingTor = false;
                try { _torToggle.IsEnabled = true; } catch { }
                SetBusy(false);
            }
        }

        // PIN SELF-HEALING, bootstrap half: called from StartTor's failure
        // path (busy overlay already up, _startingTor true). Returns true
        // when the rescue left routing ON. Never throws; all outcomes are
        // status lines. Single attempt, no recursion: inner starts call the
        // engine directly, never StartTor.
        async System.Threading.Tasks.Task<bool> TryPinBootstrapRescueAsync(Exception startFailure)
        {
            try
            {
                if (_shuttingDown || _updating) return false;
                if (_pinRescuing || _forceRetrying) return false;
                if (!IsPinActiveFromSettings()) return false;
                // Live-run guard (same as the runtime half): settings alone
                // must never rescue a run whose pin cannot be the cause
                // (entry-only pin under bridges, or settings toggled without
                // restart). BootstrapPinActive is bridge-aware; a PinSuspect
                // exception already implies it, but generic timeouts need the
                // explicit check so a slow unpinned launch is never framed.
                try { if (!_engine.IsEffectivePinForRescue()) return false; } catch { return false; }
                // Only bootstrap-type failures qualify: cancellations are
                // user stops, never a pin verdict.
                if (startFailure is OperationCanceledException) return false;
                var suspect = startFailure as PinSuspectBootstrapException;
                string evidence = suspect?.Evidence ?? "";
                bool explicitEvidence = suspect?.HasExplicitPinEvidence ?? false;
                if (suspect == null)
                {
                    // Generic failure while pinned (e.g. control-connect
                    // timeout, bridge exhaustion): upgrade to suspect ONLY
                    // with tor-log evidence or a stall-shaped timeout.
                    // Anything else (bad torrc, bad bridge config, missing
                    // tor.exe) must surface as-is — rescuing would hide a
                    // real config error behind pin churn.
                    if (!IsRescuableBootstrapFailure(startFailure, out evidence, out explicitEvidence))
                        return false;
                }
                if (!PinAutoRecovery.IsCooldownElapsed(_lastPinRescueUtc, DateTime.UtcNow)) return false;
                return await RunPinRescueAsync(
                    explicitEvidence
                        ? "bootstrap pins blamed by Tor's log (" + evidence + ")"
                        : "bootstrap stalled with pin ON" + (string.IsNullOrEmpty(evidence) ? "" : " (" + evidence + ")"));
            }
            catch { return false; }
        }

        // Decides whether a NON-pin-suspect bootstrap exception is still
        // worth one unpinned probe. Strict allowlist: timeouts/stalls only.
        // Returns the tor-log pin evidence when it upgrades the verdict.
        bool IsRescuableBootstrapFailure(Exception ex, out string evidence, out bool explicitEvidence)
        {
            evidence = "";
            explicitEvidence = false;
            try
            {
                if (ex == null) return false;
                var msg = (ex.Message ?? "").ToLowerInvariant();
                bool stallShaped = ex is TimeoutException ||
                    msg.Contains("stalled") || msg.Contains("stuck") ||
                    msg.Contains("bootstrap") || msg.Contains("bridge") ||
                    msg.Contains("control port");
                if (!stallShaped) return false;
                try { evidence = _engine.GetPinEvidenceFromLog() ?? ""; } catch { evidence = ""; }
                if (!string.IsNullOrEmpty(evidence)) explicitEvidence = true;
                // Generic (non-pin-suspect) failures need SUSTAINED explicit
                // tor-log pin blame to justify a rescue (>= 2 recent lines).
                // An unproven stall-shaped timeout (slow control-connect on
                // AV-scanned launches, bridge exhaustion, censored network)
                // is not a pin verdict — the dedicated pin waits already
                // throw PinSuspect for genuinely pin-shaped stalls (repeat
                // explicit lines inside one freeze). A single stale line is
                // usually a transient pre-consensus lookup on a healthy slow
                // boot: rescuing on it churned healthy pins through extra
                // restarts on every slow boot ("loop on app boot"), with the
                // symmetric probe then wiping the pin on check-URL slowness.
                // Surface unproven generics as-is (pin kept, watchdog/user
                // retries with pin intact).
                if (string.IsNullOrEmpty(evidence)) return false;
                try
                {
                    int hits = 0;
                    try { hits = _engine.CountPinEvidenceFromLog(); } catch { hits = 0; }
                    if (hits < 2) return false;
                }
                catch { return false; }
                return true;
            }
            catch { return false; }
        }

        // PIN SELF-HEALING, runtime half: engine's link ladder signals (pool
        // thread, marshalled here) after consecutive degraded ladders while
        // pinned. No-ops unless routing is actually up and pinned; every
        // decline path re-arms the engine signal so the next episode can
        // fire again. Never throws.
        async System.Threading.Tasks.Task HandlePinRescueSignalAsync(PinRescueNeededEventArgs e)
        {
            try
            {
                // Every decline below re-arms the engine signal: the link
                // ladder is single-flight per episode (CompareExchange), so a
                // decline WITHOUT a reset parks all future rescues — routing
                // stays up but dead with no further rescue or retry (the
                // "stuck dead after one declined episode" shape). Resetting
                // only clears the episode flag, never the rescue cooldown.
                if (_shuttingDown || _updating) { try { _engine.ResetPinRescueSignal(); } catch { } return; }
                if (_startingTor || _forceRetrying || _pinRescuing) { try { _engine.ResetPinRescueSignal(); } catch { } return; }
                if (!_engine.RoutingActive) { try { _engine.ResetPinRescueSignal(); } catch { } return; }
                // BOTH must hold: the user still wants the pin (settings) AND
                // the live run's pin can be the cause (bridge-aware effective
                // flag). Settings-without-run (toggled ON without restart on
                // a healthy unpinned run) must never rescue a run that isn't
                // pinned; run-without-settings (toggled OFF without restart)
                // must not re-pin against the user's OFF choice. Every decline
                // re-arms the engine signal for the next episode.
                if (!IsPinActiveFromSettings())
                {
                    try { _engine.ResetPinRescueSignal(); } catch { }
                    return;
                }
                try
                {
                    if (!_engine.IsEffectivePinForRescue())
                    {
                        try { _engine.ResetPinRescueSignal(); } catch { }
                        return;
                    }
                }
                catch { try { _engine.ResetPinRescueSignal(); } catch { } return; }
                if (!PinAutoRecovery.IsCooldownElapsed(_lastPinRescueUtc, DateTime.UtcNow))
                {
                    // Cooldown decline must still re-arm: otherwise the first
                    // declined episode wedges the ladder until the next link
                    // success (which may never come while the path is dead).
                    try { _engine.ResetPinRescueSignal(); } catch { }
                    return;
                }
                _startingTor = true;
                _torToggle.IsEnabled = false;
                SetBusy(true, "Pin auto-recovery: testing without pin…");
                try
                {
                    var ok = await RunPinRescueAsync("data path dead while pinned (" + (e?.Reason ?? "link monitor") + ")");
                    try { if (ok) _ = WarnAboutSecureDnsAsync(); } catch { }
                    var on = _engine.RoutingActive;
                    _useTor = on;
                    _routingHandler.UseTor = on;
                    try { _torToggle.IsOn = on; } catch { }
                    if (!ok && on)
                    {
                        // Rescue stayed unpinned but online (re-pin
                        // impossible): still a success for connectivity.
                        _useTor = true;
                        _routingHandler.UseTor = true;
                        try { _torToggle.IsOn = true; } catch { }
                    }
                }
                finally
                {
                    _startingTor = false;
                    try { _torToggle.IsEnabled = true; } catch { }
                    SetBusy(false);
                }
            }
            catch { try { _engine.ResetPinRescueSignal(); } catch { } }
        }

        // The shared rescue body. Flow (max 3 tor restarts, bounded):
        //   1. Snapshot + log the OLD pin (never silently dropped).
        //   2. RESTART UNPINNED (torrc StrictNodes gone). Failure here means
        //      the whole network is down -> keep the user's pin untouched,
        //      report, return false (still offline, watchdog will retry).
        //   2b. SYMMETRIC probe: the unpinned run must carry data too, or a
        //      slow check URL frames a healthy pin. Unproven (no data either
        //      side) -> RESTORE the original pinned run and leave routing UP
        //      for the link ladder (never strand routing OFF: that loops the
        //      watchdog back into the same verdict).
        //   3. Read the LIVE circuit. Nothing built yet -> stay unpinned
        //      ONLINE with the pin turned OFF (returning to the dead pin
        //      would re-brick the next start), user re-pins later by hand.
        //   4. Save the NEW pin, RESTART PINNED to apply it. Failure here ->
        //      fall back to unpinned ONLINE with the pin OFF (connectivity
        //      beats a pin that died twice in a row).
        // Step 1's old pin is logged in full so a user who preferred it can
        // restore it from the status line. Every settings write is atomic
        // (AppSettings.Save) + followed by RefreshPinMainUi.
        // Returns true when routing is ON afterwards (pinned or unpinned).
        // Never throws.
        async System.Threading.Tasks.Task<bool> RunPinRescueAsync(string triggerDetail)
        {
            if (_pinRescuing) return _engine.RoutingActive;
            _pinRescuing = true;
            _lastPinRescueUtc = DateTime.UtcNow;
            var oldEntryRaw = "";
            var oldMiddleRaw = "";
            var oldExitRaw = "";
            try
            {
                try { SetBusy(true, "Pin auto-recovery: restarting without pin…"); } catch { }
                // Snapshot BEFORE touching anything (settings are the source
                // of truth; the engine's run lists mirror them).
                try
                {
                    oldEntryRaw = _settings.PinnedEntryNodes ?? "";
                    oldMiddleRaw = _settings.PinnedMiddleNodes ?? "";
                    oldExitRaw = _settings.PinnedExitNodes ?? "";
                }
                catch { }
                var oldEntry = TorProcessManager.ParsePinnedNodes(oldEntryRaw);
                var oldMiddle = TorProcessManager.ParsePinnedNodes(oldMiddleRaw);
                var oldExit = TorProcessManager.ParsePinnedNodes(oldExitRaw);
                bool bridgesInUse = false;
                try { bridgesInUse = _settings.BridgeMode != BridgeMode.Direct; } catch { }
                if (!PinAutoRecovery.HasEffectivePin(true, oldEntry.Count, oldMiddle.Count, oldExit.Count, bridgesInUse))
                {
                    AppendStatusLine("Pin auto-recovery skipped: entry-only pin is ignored while bridges are in use — the pin cannot be the cause.");
                    return _engine.RoutingActive;
                }
                // Live-run guard: settings alone must never trigger a rescue
                // against a run whose pin cannot be the cause (e.g. user
                // toggled pin ON after boot without restarting — the live
                // tor is unpinned and healthy). The engine's bridge-aware
                // effective-pin flag is the source of truth for THIS run.
                try
                {
                    if (!_engine.IsEffectivePinForRescue())
                    {
                        AppendStatusLine("Pin auto-recovery skipped: the live Tor run is not effectively pinned (settings changed without restart, or entry-only pin under bridges) — no pin verdict possible.");
                        return _engine.RoutingActive;
                    }
                }
                catch { }
                AppendStatusLine("Pin auto-recovery (" + triggerDetail + "): old pin " +
                    PinAutoRecovery.FormatPins(oldEntry, oldMiddle, oldExit) +
                    " looks dead — restarting once WITHOUT the pin to test…");
                // Step 2: unpinned probe. FAIL-CLOSED: tor-only restarts keep
                // proxy (502) + lockdown (drops) + Tor-DNS up throughout —
                // never the old Stop (direct proxy + ISP DNS = leak window).
                // Runtime case (routing ON): RestartTorOnly preserves routing.
                // Bootstrap case (already stopped by rollback): cold StartAsync.
                // PIN OVERRIDE (rescue layer): the unpinned probe must carry
                // the user's NON-pin path exactly (stable / lifetime / geo /
                // rotation as saved) — hardcoding stable=false / rotate=0 here
                // would leave a fallback run with the wrong torrc + timer.
                // torrc itself re-enforces the pin override, so passing the
                // saved values is safe in both directions.
                var bridges = new BridgeConfig(_settings.BridgeMode,
                    new System.Collections.Generic.List<string>(_settings.CustomBridgeLines ?? new System.Collections.Generic.List<string>()));
                var exitCountries = _settings.ExitGeoEnabled
                    ? TorPathOptions.ResolveExitCountries(_settings.ExitRegion, _settings.ExitCustomCountries)
                    : new System.Collections.Generic.List<string>();
                int userRotateSecs = 0;
                bool userStable = false;
                bool requireLockdown = false;
                try { userRotateSecs = ParseRotateSeconds(); } catch { userRotateSecs = 0; }
                try { userStable = _settings.StableExitEnabled; } catch { userStable = false; }
                try { requireLockdown = _settings.EnforceTorOnly || _settings.BlockWebRtc; } catch { }
                try { _engine.LockdownRequired = requireLockdown; } catch { }
                bool coldBootstrapCase = false;
                try { coldBootstrapCase = !_engine.RoutingActive; } catch { coldBootstrapCase = false; }
                try
                {
                    if (coldBootstrapCase)
                    {
                        await _engine.StartAsync(rotateEverySec: userRotateSecs, bridges: bridges,
                            stableConnection: userStable, exitCountries: exitCountries,
                            maxCircuitDirtinessSec: _settings.CircuitDirtinessSec,
                            circuitStreamTimeoutSec: _settings.CircuitStreamTimeoutSec,
                            restrictiveFirewall: _settings.RestrictiveFirewallOnly,
                            pinnedCircuitEnabled: false,
                            pinnedEntryNodes: new System.Collections.Generic.List<string>(),
                            pinnedMiddleNodes: new System.Collections.Generic.List<string>(),
                            pinnedExitNodes: new System.Collections.Generic.List<string>(),
                            requireLockdown: requireLockdown);
                    }
                    else
                    {
                        await _engine.RestartTorOnlyAsync(rotateEverySec: userRotateSecs, bridges: bridges,
                            stableConnection: userStable, exitCountries: exitCountries,
                            maxCircuitDirtinessSec: _settings.CircuitDirtinessSec,
                            circuitStreamTimeoutSec: _settings.CircuitStreamTimeoutSec,
                            restrictiveFirewall: _settings.RestrictiveFirewallOnly,
                            pinnedCircuitEnabled: false,
                            pinnedEntryNodes: new System.Collections.Generic.List<string>(),
                            pinnedMiddleNodes: new System.Collections.Generic.List<string>(),
                            pinnedExitNodes: new System.Collections.Generic.List<string>(),
                            requireLockdown: requireLockdown);
                    }
                }
                catch (OperationCanceledException)
                {
                    AppendStatusLine("Pin auto-recovery cancelled (stop requested) — pin kept: " +
                        PinAutoRecovery.FormatPins(oldEntry, oldMiddle, oldExit) + ".");
                    return false;
                }
                catch (Exception ex)
                {
                    // Whole network down (or bridges dead): the pin is
                    // UNPROVEN — keep it exactly as the user had it. Runtime
                    // case stays FAIL-CLOSED (routing ON, tor dead: 502s +
                    // drops, no direct) and re-syncs the live tor toward the
                    // old pin so the next episode can still judge it; cold
                    // case stays OFF for the watchdog to retry with pin intact.
                    AppendStatusLine("Pin auto-recovery: unpinned restart also failed (" + ex.Message +
                        ") — the whole path looks down, NOT just the pin. Your pin was kept untouched: " +
                        PinAutoRecovery.FormatPins(oldEntry, oldMiddle, oldExit) + ".");
                    if (!coldBootstrapCase)
                    {
                        try
                        {
                            await _engine.RestartTorOnlyAsync(rotateEverySec: userRotateSecs, bridges: bridges,
                                stableConnection: userStable, exitCountries: exitCountries,
                                maxCircuitDirtinessSec: _settings.CircuitDirtinessSec,
                                circuitStreamTimeoutSec: _settings.CircuitStreamTimeoutSec,
                                restrictiveFirewall: _settings.RestrictiveFirewallOnly,
                                pinnedCircuitEnabled: true,
                                pinnedEntryNodes: oldEntry, pinnedMiddleNodes: oldMiddle, pinnedExitNodes: oldExit,
                                requireLockdown: requireLockdown);
                        }
                        catch { }
                        try { await MaybeEnableEnforcementAsync(); } catch { }
                        return _engine.RoutingActive;
                    }
                    return false;
                }
                if (!_engine.RoutingActive || !_engine.IsTorRunning)
                {
                    AppendStatusLine("Pin auto-recovery: unpinned restart finished but routing is off — pin kept untouched.");
                    return false;
                }
                // SYMMETRIC verdict (the "always unpinned after reboot" fix):
                // the pinned run needed 3x20s end-to-end probes to fail before
                // it was blamed — the unpinned probe must pass the SAME bar,
                // or a slow check URL / cold circuits frame a healthy pin
                // (pinned fails its probe, unpinned never probes, rescue
                // concludes "pin dead" on zero evidence). Only an unpinned
                // run that ALSO carries data proves the pin was the cause.
                bool unpinnedCarriesData = false;
                try
                {
                    for (var i = 1; i <= 3; i++)
                    {
                        try
                        {
                            if (await _engine.ProbeDataPathAsync(TimeSpan.FromSeconds(PinAutoRecovery.PostBootstrapProbeSec)))
                            { unpinnedCarriesData = true; break; }
                        }
                        catch { }
                        if (i < 3)
                            try { await System.Threading.Tasks.Task.Delay(TimeSpan.FromSeconds(2)); } catch { break; }
                    }
                }
                catch { unpinnedCarriesData = false; }
                if (!unpinnedCarriesData)
                {
                    // Unproven either way (slow check URL looks exactly like
                    // this): stopping here strands routing OFF and the
                    // watchdog just reboots the same pin into the same
                    // verdict — a boot loop. Restore the ORIGINAL pinned run
                    // instead (settings AND live tor match again, pin kept
                    // untouched) and leave routing UP for the link ladder,
                    // which re-judges with a fresh symmetric probe.
                    AppendStatusLine("Pin auto-recovery: unpinned restart bootstrapped but carries no data either (probe failed like the pinned run) — the whole path looks down, NOT just the pin. Restoring your original pin (kept untouched: " +
                        PinAutoRecovery.FormatPins(oldEntry, oldMiddle, oldExit) + ") and leaving routing up for the link monitor to judge...");
                    try
                    {
                        // FAIL-CLOSED restore: tor-only, routing stays ON
                        // (no direct window). PIN OVERRIDE: the user's saved
                        // non-pin path (stable/rotation/geo) is passed through
                        // and the engine + torrc force pin values over it.
                        await _engine.RestartTorOnlyAsync(rotateEverySec: userRotateSecs, bridges: bridges,
                            stableConnection: userStable, exitCountries: exitCountries,
                            maxCircuitDirtinessSec: _settings.CircuitDirtinessSec,
                            circuitStreamTimeoutSec: _settings.CircuitStreamTimeoutSec,
                            restrictiveFirewall: _settings.RestrictiveFirewallOnly,
                            pinnedCircuitEnabled: true,
                            pinnedEntryNodes: oldEntry, pinnedMiddleNodes: oldMiddle, pinnedExitNodes: oldExit,
                            requireLockdown: requireLockdown);
                    }
                    catch (Exception ex2)
                    {
                        AppendStatusLine("Pin auto-recovery restore failed: " + ex2.Message + " — pin kept in settings, toggle to retry.");
                        return false;
                    }
                    await MaybeEnableEnforcementAsync();
                    try { RefreshPinMainUi(); } catch { }
                    AppendStatusLine("Pin auto-recovery: back on your original pin (unproven verdict) — link monitor keeps watching.");
                    return _engine.RoutingActive;
                }
                await MaybeEnableEnforcementAsync();
                AppendStatusLine("Pin auto-recovery: unpinned connection WORKS — the old pin was the problem. Reading the live circuit to re-pin…");
                // Step 3: live circuit -> new pin. Retry: a GENERAL circuit
                // builds lazily right after bootstrap — a single immediate
                // read usually finds nothing yet and would wipe the pin
                // ("online without pin") on a run that simply needed seconds.
                string? liveEntry = null, liveMiddle = null, liveExit = null;
                try
                {
                    for (var i = 0; i < 4; i++)
                    {
                        try { (liveEntry, liveMiddle, liveExit) = await _engine.GetLiveCircuitNodesAsync(); } catch { }
                        if (!string.IsNullOrWhiteSpace(liveEntry) || !string.IsNullOrWhiteSpace(liveMiddle) || !string.IsNullOrWhiteSpace(liveExit))
                            break;
                        if (i < 3)
                            try { await System.Threading.Tasks.Task.Delay(TimeSpan.FromSeconds(5)); } catch { break; }
                    }
                }
                catch { }
                if (string.IsNullOrWhiteSpace(liveEntry) && string.IsNullOrWhiteSpace(liveMiddle) && string.IsNullOrWhiteSpace(liveExit))
                {
                    // Connected but no BUILT circuit readable yet (too early
                    // or control hiccup): stay ONLINE unpinned rather than
                    // gambling another restart. Pin OFF so the next start
                    // doesn't re-brick; the old values are in the log above.
                    try
                    {
                        _settings.PinnedCircuitEnabled = false;
                        _settings.Save();
                    }
                    catch { }
                    try { RefreshPinMainUi(); } catch { }
                    AppendStatusLine("Pin auto-recovery: online WITHOUT pin (no live circuit readable yet to re-pin safely) — pin turned OFF so the next start connects. Old pin was " +
                        PinAutoRecovery.FormatPins(oldEntry, oldMiddle, oldExit) + ". Use Config → 'Use current circuit' to re-pin later.");
                    return true;
                }
                // The new pin is EXACTLY the proven live circuit — every
                // position is set from it (missing => cleared to "any"),
                // never merged with the OLD (proven-dead) values. Merging
                // kept a dead old middle/exit alongside fresh hops
                // (franken-pin): the next start re-bricked on the same dead
                // relay and the rescue looped every boot. While bridged the
                // live "entry" hop is the bridge itself (not a guard pick)
                // and Tor ignores EntryNodes anyway — so the user's saved
                // entry pick is kept as-is there instead of persisting a
                // bridge fingerprint that would fail when bridges go off.
                try
                {
                    if (bridgesInUse)
                    {
                        try { _settings.PinnedEntryNodes = oldEntryRaw ?? ""; } catch { }
                    }
                    else
                    {
                        _settings.PinnedEntryNodes = string.IsNullOrWhiteSpace(liveEntry) ? "" : liveEntry.Trim();
                    }
                    _settings.PinnedMiddleNodes = string.IsNullOrWhiteSpace(liveMiddle) ? "" : liveMiddle.Trim();
                    _settings.PinnedExitNodes = string.IsNullOrWhiteSpace(liveExit) ? "" : liveExit.Trim();
                    _settings.PinnedCircuitEnabled = true;
                    _settings.Save();
                }
                catch (Exception ex)
                {
                    AppendStatusLine("Pin auto-recovery: online WITHOUT pin (could not save new pin: " + ex.Message + ") — staying unpinned.");
                    try { RefreshPinMainUi(); } catch { }
                    return true;
                }
                try { RefreshPinMainUi(); } catch { }
                AppendStatusLine("Pin auto-recovery: re-pinned to live circuit " +
                    PinAutoRecovery.FormatPins(
                        TorProcessManager.ParsePinnedNodes(_settings.PinnedEntryNodes),
                        TorProcessManager.ParsePinnedNodes(_settings.PinnedMiddleNodes),
                        TorProcessManager.ParsePinnedNodes(_settings.PinnedExitNodes)) +
                    (bridgesInUse ? " (entry kept as saved — Tor ignores it while bridged; middle/exit apply now)" : "") +
                    " — restarting Tor to apply the new pin…");
                // Step 4: restart INTO the new pin (torrc needs a restart).
                // FAIL-CLOSED: tor-only, routing stays ON (no direct window).
                // PIN OVERRIDE: the user's saved non-pin path is passed
                // through and the engine + torrc force pin values over it
                // (rotation 0, huge dirtiness, geo cleared) — defense in
                // depth, and the run keeps the user's stable flag honestly.
                var newEntry = TorProcessManager.ParsePinnedNodes(_settings.PinnedEntryNodes);
                var newMiddle = TorProcessManager.ParsePinnedNodes(_settings.PinnedMiddleNodes);
                var newExit = TorProcessManager.ParsePinnedNodes(_settings.PinnedExitNodes);
                try
                {
                    try { SetBusy(true, "Pin auto-recovery: restarting with new pin…"); } catch { }
                    await _engine.RestartTorOnlyAsync(rotateEverySec: userRotateSecs, bridges: bridges,
                        stableConnection: userStable, exitCountries: exitCountries,
                        maxCircuitDirtinessSec: _settings.CircuitDirtinessSec,
                        circuitStreamTimeoutSec: _settings.CircuitStreamTimeoutSec,
                        restrictiveFirewall: _settings.RestrictiveFirewallOnly,
                        pinnedCircuitEnabled: true,
                        pinnedEntryNodes: newEntry, pinnedMiddleNodes: newMiddle, pinnedExitNodes: newExit,
                        requireLockdown: requireLockdown);
                }
                catch (Exception ex)
                {
                    // New pin died between read and restart (relay flapped):
                    // fall back to ONLINE unpinned with the pin OFF, carrying
                    // the user's saved non-pin path (stable/rotation/geo).
                    // Do NOT restore the old dead pin, do NOT retry pinned.
                    // FAIL-CLOSED fallback: tor-only again, routing stays ON.
                    AppendStatusLine("Pin auto-recovery: new pin failed to apply (" + ex.Message +
                        ") — falling back ONLINE without pin (pin OFF). Old pin was " +
                        PinAutoRecovery.FormatPins(oldEntry, oldMiddle, oldExit) + ".");
                    try
                    {
                        await _engine.RestartTorOnlyAsync(rotateEverySec: userRotateSecs, bridges: bridges,
                            stableConnection: userStable, exitCountries: exitCountries,
                            maxCircuitDirtinessSec: _settings.CircuitDirtinessSec,
                            circuitStreamTimeoutSec: _settings.CircuitStreamTimeoutSec,
                            restrictiveFirewall: _settings.RestrictiveFirewallOnly,
                            pinnedCircuitEnabled: false,
                            pinnedEntryNodes: new System.Collections.Generic.List<string>(),
                            pinnedMiddleNodes: new System.Collections.Generic.List<string>(),
                            pinnedExitNodes: new System.Collections.Generic.List<string>(),
                            requireLockdown: requireLockdown);
                    }
                    catch (Exception ex2)
                    {
                        AppendStatusLine("Pin auto-recovery fallback also failed: " + ex2.Message);
                        try
                        {
                            _settings.PinnedCircuitEnabled = false;
                            _settings.Save();
                        }
                        catch { }
                        try { RefreshPinMainUi(); } catch { }
                        return false;
                    }
                    try
                    {
                        _settings.PinnedCircuitEnabled = false;
                        _settings.Save();
                    }
                    catch { }
                    try { RefreshPinMainUi(); } catch { }
                    await MaybeEnableEnforcementAsync();
                    AppendStatusLine("Pin auto-recovery: online WITHOUT pin (new pin flapped) — pin turned OFF. Re-pin from Config when stable.");
                    return _engine.RoutingActive;
                }
                if (!_engine.RoutingActive)
                {
                    AppendStatusLine("Pin auto-recovery: re-pinned restart finished but routing is off — staying offline with the NEW pin saved. Toggle to retry.");
                    return false;
                }
                await MaybeEnableEnforcementAsync();
                try { RefreshPinMainUi(); } catch { }
                AppendStatusLine("Pin auto-recovery COMPLETE: connected with the new pin (old dead pin was " +
                    PinAutoRecovery.FormatPins(oldEntry, oldMiddle, oldExit) + "). Exit IP should now stay stable again.");
                return true;
            }
            catch (Exception ex)
            {
                try { AppendStatusLine("Pin auto-recovery issue: " + ex.Message + " — pin kept as-is."); } catch { }
                return _engine.RoutingActive;
            }
            finally
            {
                _pinRescuing = false;
                try { _engine.ResetPinRescueSignal(); } catch { }
                try { RefreshPinMainUi(); } catch { }
                try { SetBusy(false); } catch { }
            }
        }

        async System.Threading.Tasks.Task StopTor()
        {
            _torToggle.IsEnabled = false;
            try
            {
                var (proceed, affected) = await ConfirmStopRoutingAsync("Stop routing");
                if (!proceed)
                {

                    _torToggle.IsOn = true;
                    _useTor = true;
                    _routingHandler.UseTor = true;
                    AppendStatusLine("Stop cancelled — routing still on.");
                    return;
                }
                await _engine.StopAsync();
                RefreshRoutingBadge();

                _statusText.Text = affected > 0
                    ? $"Stopped. Restart the {affected} listed app(s) — they keep Tor env until restarted."
                    : "Stopped. System proxy restored — user apps connect directly again.";
                _statusDot.Fill = DimBrush;
            }
            catch (Exception ex)
            {
                AppendStatusLine("Error stopping Tor: " + ex.Message);
            }
            finally
            {
                _torToggle.IsEnabled = true;
            }
        }

        // The process-table walk (every PID + exe path + start time) can take
        // seconds on loaded machines: never on the UI thread, and never
        // unbounded — the exit path must not park here. On timeout the
        // confirm still asks, just without the app list. The MessageBox
        // itself stays on UI (it must).
        async System.Threading.Tasks.Task<(bool proceed, int affected)> ConfirmStopRoutingAsync(string actionNoun)
        {
            try
            {
                // Single snapshot: RoutingActive is flipped on a pool thread
                // during stop, so read both once and decide off that (a torn
                // read here can only fail safe to "no confirm").
                var routingSince = _engine.RoutingStartedUtc;
                if (!_engine.RoutingActive || routingSince == null)
                    return (true, 0);
                List<string>? shown = null;
                var total = 0;
                try
                {
                    var snapTask = System.Threading.Tasks.Task.Run(
                        () => RunningAppEnumerator.GetLaunchedSince(routingSince.Value));
                    var done = await System.Threading.Tasks.Task.WhenAny(
                        snapTask, System.Threading.Tasks.Task.Delay(TimeSpan.FromSeconds(2)));
                    if (done == snapTask)
                        (shown, total) = await snapTask;
                }
                catch { shown = null; }
                string text;
                if (shown == null)
                {
                    // Snapshot took too long (wedged drive/share): ask anyway
                    // with a generic warning instead of blocking the exit.
                    text = $"Apps launched while routing was on keep Tor proxy env until restarted.\n\n" +
                        $"They will go OFFLINE until you restart them. {actionNoun} anyway? (App list unavailable — check took too long.)";
                    total = 0;
                }
                else
                {
                    if (total == 0)
                        return (true, 0);
                    var names = string.Join("\n", shown.Select(s => "  • " + s))
                        + (total > shown.Count ? $"\n  • …and {total - shown.Count} more" : "");
                    text = $"{total} app(s) were launched while routing was on and keep Tor proxy env until restarted:\n{names}\n\n" +
                        $"They will go OFFLINE until you restart them. {actionNoun} anyway?";
                }
                // Owner only when actually visible: a modal dialog parented to
                // a hidden window waits for an answer nobody can see (freeze).
                var visible = false;
                try { visible = IsVisible; } catch { }
                var answer = visible
                    ? MessageBox.Show(this, text, "Apps will go offline", MessageBoxButton.YesNo, MessageBoxImage.Warning)
                    : MessageBox.Show(text, "Apps will go offline", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                return (answer == MessageBoxResult.Yes, total);
            }
            catch { return (true, 0); }
        }

        void UpdateEngineStatus(TorStateChangedEventArgs e)
        {
            var pct = e.BootstrapPercent.HasValue ? $" ({e.BootstrapPercent}%)" : "";
            _statusText.Text = e.Message + pct;
            try { _trayIcon?.SetTooltip("Tor: " + e.Message + pct); } catch { }
            RefreshBusyOverlay(e);
            try { RefreshWindowTitle(); } catch { }

            _statusDot.Fill = e.State switch
            {
                TorState.Connected => GoodBrush,
                TorState.Bootstrapping => AccentBrush,
                TorState.Starting => DimBrush,
                TorState.Reconnecting => WarnBrush,
                TorState.Error => DangerBrush,
                TorState.Stopped => DimBrush,
                _ => DimBrush
            };

            if (e.State == TorState.Error && !_shuttingDown)
                AppendStatusLine("Tor error: " + e.Message);
        }

        void SetBusy(bool busy, string? note = null)
        {
            try
            {
                _busyOverlay.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
                foreach (var c in _busyLockControls)
                {
                    try { c.IsEnabled = !busy; } catch { }
                }
                if (busy)
                {
                    _busyText.Text = note ?? "Working…";
                    _busyBar.IsIndeterminate = true;
                }
                // Boot escape row shows while ANY start/rescue/retry is in
                // flight (boot stuck) — never during bundle updates or idle
                // busy. Config is the unstick path for a bad bridge mode: it
                // opens even mid-bootstrap, then Force Retry applies the new
                // mode. Stop cancels whatever is in flight back to idle
                // (including a wedged force-retry: the engine observes the
                // cancel via the lifetime CTS).
                try
                {
                    var showEscapes = (busy && (_startingTor || _forceRetrying || _pinRescuing) && !_updating)
                        ? Visibility.Visible : Visibility.Collapsed;
                    _forceRetryBtn.Visibility = showEscapes;
                    _busyConfigBtn.Visibility = showEscapes;
                    _busyStopBtn.Visibility = showEscapes;
                }
                catch { }
            }
            catch { }
        }

        void RefreshBusyOverlay(TorStateChangedEventArgs e)
        {
            try
            {
                if (_busyOverlay.Visibility != Visibility.Visible) return;
                var pct = e.BootstrapPercent;
                _busyText.Text = e.Message + (pct.HasValue ? $" ({pct}%)" : "");
                if (pct.HasValue)
                {
                    _busyBar.IsIndeterminate = false;
                    _busyBar.Value = Math.Max(0, Math.Min(100, pct.Value));
                }
                else
                {
                    _busyBar.IsIndeterminate = true;
                }
            }
            catch { }
        }

        void AppendStatusLine(string msg)
        {

            _statusText.Text = msg;
        }

        void ApplyRotationInterval()
        {
            // PIN OVERRIDE (UI layer): engine also forces 0 in
            // SetRotationInterval — this early check keeps the status line
            // honest instead of promising a rotation that will never fire.
            // NOTE: the textbox value is the user's SAVED interval and is
            // deliberately left untouched (GetStartArgs forces 0 at the
            // source while pinned) — overwriting it to "0" here destroyed
            // the saved interval on every pin toggle.
            if (IsPinActiveFromSettings())
            {
                _engine.SetRotationInterval(0);
                AppendStatusLine("Scheduled rotation stays OFF while circuit pin is on (it would hop IPs). Turn pin off to rotate.");
                return;
            }
            var secs = ParseRotateSeconds();
            _engine.SetRotationInterval(secs);
            AppendStatusLine(secs == 0
                ? "Circuit rotation disabled."
                : $"Circuit will rotate every {secs}s.");
        }

        int ParseRotateSeconds()
        {
            // Clamped: overflow on this UI path would take the app down.
            if (int.TryParse(_rotateSecondsInput.Text.Trim(), out var secs) && secs >= 0)
                return Math.Min(secs, 30 * 24 * 3600);
            _rotateSecondsInput.Text = "0";
            return 0;
        }

        void ShowRoutingInfo()
        {
            if (_configOpen) return;
            _configOpen = true;
            try
            {
                new RoutingInfoDialog(_engine, _blockedDomains, _settings, CurrentUserAgent, ApplyUserAgent, AppendStatusLine, RestartAsAdminAsync) { Owner = this }.ShowDialog();
            }
            finally
            {
                _configOpen = false;
            }
            RefreshRoutingBadge();
            // Bridge mode may have changed in Config: mirror it into the
            // engine so the stopped-state title tag names the SELECTED mode
            // (no-op while routing — the live run owns it till next start).
            try
            {
                _engine.SyncConfiguredBridges(new BridgeConfig(_settings.BridgeMode,
                    new System.Collections.Generic.List<string>(_settings.CustomBridgeLines ?? new System.Collections.Generic.List<string>())));
            }
            catch { }
            // Pin may have been toggled in Config: rotation box + New ID
            // must reflect the new override state immediately (the torrc
            // itself still needs a restart — the dialog says so).
            RefreshPinMainUi();
            if (IsPinActiveFromSettings() && _engine.RoutingActive && !_engine.PinnedCircuitActive)
                AppendStatusLine("Circuit pin saved — restart Tor (toggle off/on) to apply: rotation + New ID are already held off.");
            // Config edited mid-start (bad bridge mode reverted on a stuck
            // boot): the in-flight start still carries the OLD settings.
            // Say so out loud so Force Retry is the obvious next step.
            if (_startingTor && !_updating)
                AppendStatusLine("Config saved — a start is still in flight with the previous settings. Hit Force Retry (or Stop, then start again) to apply the new ones.");
        }

        // Config entry point that works even when the busy overlay covers
        // the main window (stuck obfs4 bootstrap) or the window is hidden
        // in the tray. Restores the window first when hidden so the modal
        // dialog is never parented to an invisible owner (which reads as a
        // freeze: the app waits for an answer nobody can see).
        void OpenConfigSafe()
        {
            if (_shuttingDown) return;
            if (_configOpen) return;
            try
            {
                try
                {
                    if (!IsVisible)
                    {
                        Show();
                        WindowState = WindowState.Normal;
                        ShowInTaskbar = true;
                        try { Activate(); } catch { }
                    }
                    else if (WindowState == WindowState.Minimized)
                    {
                        Show();
                        WindowState = WindowState.Normal;
                        try { Activate(); } catch { }
                    }
                }
                catch { }
                ShowRoutingInfo();
            }
            catch { }
        }

        // Busy-overlay abort: cancels the in-flight start (long obfs4
        // bootstrap, pin rescue, force retry) back to idle. The owning
        // StartTor/rescue/retry observes the cancel and tears down the
        // overlay/toggle itself, so this only issues the stop — never touches
        // _startingTor/SetBusy directly, or it would race the owner's finally.
        // Always allowed while something is in flight: refusing during a
        // wedged force-retry/pin-rescue is exactly the "stuck with no way
        // out" shape (the engine's bootstrap waits observe the stop's cancel
        // and abort within seconds).
        async System.Threading.Tasks.Task StopStartFromBusyAsync()
        {
            try
            {
                if (_updating) return;
                if (!_startingTor && !_forceRetrying && !_pinRescuing) return;
                AppendStatusLine("Cancelling start — stopping tor, back to idle...");
                try { await _engine.StopAsync(); }
                catch (Exception ex) { AppendStatusLine("Stop issue: " + ex.Message); }
            }
            catch { }
        }

        void RefreshRoutingBadge()
        {
            // Degraded is still fail-closed (drops, not leaks) but must not
            // read as healthy LOCKDOWN: badge names it so a parked filter is
            // never mistaken for a live one.
            bool degraded = false;
            try { degraded = _engine.EnforcementDegraded; } catch { }
            _proxyBadge.Text = _engine.RoutingActive
                ? $"● User apps → Tor · {_engine.ExitLabel}" + (_engine.EnforcementActive ? (degraded ? " · LOCKDOWN DEGRADED" : " · LOCKDOWN") : "")
                : "";
            // The pill wrapper hides while empty so no stray outline sits
            // next to the title before the first start / after stop.
            try { _badgePill.Visibility = string.IsNullOrEmpty(_proxyBadge.Text) ? Visibility.Collapsed : Visibility.Visible; } catch { }
            try { _trayIcon?.SetRoutingOn(_engine.RoutingActive); } catch { }
            try { RefreshWindowTitle(); } catch { }
        }

        // Window title always names the bridge path: the EFFECTIVE one while
        // routing (with [FB:...] when a fallback won instead of the
        // configured mode), the configured mode while stopped. Runs on the
        // UI thread via the status/badge refresh paths. Never throws.
        void RefreshWindowTitle()
        {
            try
            {
                string tag = "";
                try { tag = _engine.ActiveBridgeTag ?? ""; } catch { }
                Title = string.IsNullOrEmpty(tag)
                    ? "Tor Traffic Router"
                    : "Tor Traffic Router " + tag;
            }
            catch { }
        }

        // Guaranteed death: Environment.Exit runs finalizers and WPF shutdown,
        // either of which can wedge indefinitely on a sick system (that exact
        // hang is the "exiting stalls, tor lingers" bug — the fallback Kill
        // below it never runs because Exit never returns AND never throws).
        // Arm this FIRST on every dying path: after <ms> the process is
        // TerminateProcess-killed no matter where the teardown parked. Tor is
        // always killed in the first milliseconds of the teardown, so by the
        // time this fires there can be no orphan — only our own death remains.
        static System.Threading.CancellationTokenSource? _selfDestructCts;
        static void ArmSelfDestruct(int ms)
        {
            try
            {
                try { _selfDestructCts?.Cancel(); } catch { }
                try { _selfDestructCts?.Dispose(); } catch { }
                var cts = new System.Threading.CancellationTokenSource();
                _selfDestructCts = cts;
                _ = System.Threading.Tasks.Task.Run(async () =>
                {
                    try { await System.Threading.Tasks.Task.Delay(ms, cts.Token); } catch { return; }
                    if (cts.IsCancellationRequested) return;
                    try { ExitTrace.Log("exit watchdog firing, force-killing self"); } catch { }
                    try { System.Diagnostics.Process.GetCurrentProcess().Kill(); } catch { }
                    try { Environment.FailFast("PTor exit watchdog"); } catch { }
                });
            }
            catch { }
        }

        static void DisarmSelfDestruct()
        {
            try { _selfDestructCts?.Cancel(); } catch { }
        }

        // Deterministic death for exit/restart paths: shared state is already
        // restored and tor is already dead by the time this runs. Never
        // returns. Environment.Exit first (clean CLR shutdown when healthy),
        // TerminateProcess immediately after (cannot be parked by finalizers).
        static void DieNow()
        {
            ArmSelfDestruct(3000);
            try { Environment.Exit(0); } catch { }
            try { Process.GetCurrentProcess().Kill(); } catch { }
            try { Environment.FailFast("PTor exit"); } catch { }
        }

        // Bounded teardown for exit/restart handover paths: tor is killed in
        // the first milliseconds inside FastTeardownForExit, then instant
        // registry restores put direct internet back. Teardown itself is
        // wait-free by design (no WaitForExit, no flush wait, driver removal
        // detached), so this bound is a backstop only — expect milliseconds.
        // RESTORE IS NEVER SKIPPED: on timeout or error a final restore
        // (idempotent, no gate, on a pool thread — never blocking the UI
        // thread that must reach DieNow) runs before dying, so the user is
        // never left offline. Backstops beyond that: rescue-internet.bat in
        // the Release folder, and next-start self-heal (every Enable
        // recovers a stale marker first).
        async System.Threading.Tasks.Task<string> TeardownForExitBoundedAsync(bool handover = false)
        {
            try
            {
                var teardown = System.Threading.Tasks.Task.Run(() => _engine.FastTeardownForExit(handover));
                var done = await System.Threading.Tasks.Task.WhenAny(
                    teardown, System.Threading.Tasks.Task.Delay(TimeSpan.FromSeconds(4)));
                if (done == teardown)
                    return await teardown;
                // Timed out: the restore may be partial — run the critical
                // restores on a pool thread (idempotent) so the user is never
                // left without internet, then die anyway. Bounded too: the
                // exit must reach DieNow even if THIS wedges as well.
                string final;
                try
                {
                    var finTask = System.Threading.Tasks.Task.Run(() => _engine.RestoreCriticalNow());
                    var finDone = await System.Threading.Tasks.Task.WhenAny(
                        finTask, System.Threading.Tasks.Task.Delay(TimeSpan.FromSeconds(3)));
                    final = finDone == finTask ? await finTask : "final restore timed out after 3s (dying anyway)";
                }
                catch (Exception ex) { final = "final restore issue: " + ex.Message; }
                ExitTrace.Log("exit teardown timeout, final restore: " + final);
                return "teardown timed out after 4s — ran final restore (" + final + ")";
            }
            catch (Exception ex)
            {
                // Teardown itself threw before finishing: same guarantee —
                // attempt the restore once more before reporting, bounded.
                string final;
                try
                {
                    var finTask = System.Threading.Tasks.Task.Run(() => _engine.RestoreCriticalNow());
                    var finDone = await System.Threading.Tasks.Task.WhenAny(
                        finTask, System.Threading.Tasks.Task.Delay(TimeSpan.FromSeconds(3)));
                    final = finDone == finTask ? await finTask : "final restore timed out after 3s (dying anyway)";
                }
                catch (Exception ex2) { final = "final restore issue: " + ex2.Message; }
                return "fast teardown issue: " + ex.Message + " — ran final restore (" + final + ")";
            }
        }

        async System.Threading.Tasks.Task RestartAppAsync()
        {
            // Comfort reset after settings changes: stop cleanly (restores
            // proxy/DNS/env) then relaunch the same binary. The Release
            // manifest re-prompts for elevation automatically.
            if (_engine.RoutingActive || _engine.EnforcementActive)
            {
                var confirm = MessageBox.Show(this,
                    "Restart PTor now? Routing stops and the app relaunches.",
                    "Restart app", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes) return;
            }
            string? exe = null;
            try { exe = Environment.ProcessPath; } catch { }
            if (string.IsNullOrEmpty(exe))
            {
                try { exe = Process.GetCurrentProcess().MainModule?.FileName; } catch { }
            }
            if (string.IsNullOrEmpty(exe))
            {
                AppendStatusLine("Restart failed: could not locate own executable.");
                return;
            }
            AppendStatusLine("Restarting...");
            // Like Exit: no watchdog resurrections and no minimize-to-tray
            // interference while tearing down for the handover.
            _shuttingDown = true;
            try { _appMonitorTimer?.Stop(); } catch { }
            try
            {
                // The new copy waits for THIS pid to exit (releasing the
                // single-instance lock with it) via --takeover-from.
                var me = Process.GetCurrentProcess().Id;
                Process.Start(new ProcessStartInfo
                {
                    FileName = exe,
                    Arguments = $"{SingleInstance.TakeoverArg} {me}",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                AppendStatusLine("Restart failed to relaunch: " + ex.Message);
                // Stay usable: relaunch didn't happen, so resume supervision.
                _shuttingDown = false;
                try { _appMonitorTimer?.Start(); } catch { }
                return;
            }
            ArmSelfDestruct(10000);
            string report;
            try { report = await TeardownForExitBoundedAsync(handover: true); }
            catch (Exception ex) { report = "fast teardown issue: " + ex.Message; }
            ExitTrace.Log("restart restored: " + report);
            try { _trayIcon.Hide(); } catch { }
            ExitTrace.Log("restart bye");
            DieNow();
        }

        async System.Threading.Tasks.Task RestartAsAdminAsync()
        {
            // Refuse mid-update: the engine/files belong to the installer right now.
            if (_updating)
            {
                AppendStatusLine("Restart refused — a Tor bundle update is installing. Wait for it to finish.");
                MessageBox.Show(this,
                    "A Tor bundle update is installing right now — wait for it to finish before restarting.",
                    "Update in progress", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            AppendStatusLine("Stopping Tor and restarting as administrator...");
            _shuttingDown = true;
            try { _appMonitorTimer?.Stop(); } catch { }
            try
            {
                var me = Process.GetCurrentProcess().Id;
                AdminHelper.RestartElevated($"{SingleInstance.TakeoverArg} {me}");
            }
            catch (Exception ex)
            {
                AppendStatusLine("Elevation failed (UAC declined?): " + ex.Message);
                // Stay usable: no new copy is coming, resume supervision.
                _shuttingDown = false;
                try { _appMonitorTimer?.Start(); } catch { }
                return;
            }
            ArmSelfDestruct(10000);
            string report;
            try { report = await TeardownForExitBoundedAsync(handover: true); }
            catch (Exception ex) { report = "fast teardown issue: " + ex.Message; }
            ExitTrace.Log("elevated restart restored: " + report);
            try { _trayIcon.Hide(); } catch { }
            ExitTrace.Log("elevated restart bye");
            DieNow();
        }

        async System.Threading.Tasks.Task UpdateTorBundle()
        {
            const string updateWarning =
                "WARNING: Tor network re-routing is OFF during the update — apps connect directly right now. " +
                "Routing turns back on automatically when the update finishes.";
            _updateBundleBtn.IsEnabled = false;
            _torToggle.IsEnabled = false;
            var wasRunning = _torToggle.IsOn || _engine.RoutingActive;
            // Update metadata via Tor while routing is up (torproject.org may itself be censored).
            _updater.UseTorRoute = _engine.RoutingActive;
            _updater.TorSocksPort = _engine.SocksPort;

            try
            {
                AppendStatusLine("Checking for the latest Tor Expert Bundle...");
                var (url, version) = await _updater.GetLatestStableUrlAsync();
                AppendStatusLine($"Latest stable: tor expert bundle {version}");

                // Skip when already latest (unknown versions proceed: safe direction, one redundant update max).
                var installed = _updater.GetInstalledBundleVersion();
                if (TorUpdater.IsSameBundleVersion(installed, version) && _updater.HasTorExecutable())
                {
                    AppendStatusLine($"Tor Expert Bundle already latest ({installed?.Trim()}) — skipping update.");
                    return;
                }

                var proceed = MessageBox.Show(this,
                    $"Download and install Tor Expert Bundle {version}?\n\n" +
                    (wasRunning
                        ? "Tor WILL BE STOPPED for the update — re-routing goes OFF and comes back on automatically when done."
                        : "Routing is currently off and stays off."),
                    "Update Tor Bundle", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (proceed != MessageBoxResult.Yes)
                {
                    AppendStatusLine("Update cancelled.");
                    return;
                }

                _updating = true;
                SetBusy(true, updateWarning);
                if (wasRunning)
                {
                    AppendStatusLine("Stopping Tor for update — re-routing is now OFF...");
                    await _engine.StopAsync();
                    _torToggle.IsOn = false;
                    RefreshRoutingBadge();
                    // Tor is down from here on: the updater must go direct.
                    // (Left on Tor-route, every fetch would die on a refused
                    // SOCKS port and abort the update.)
                    _updater.UseTorRoute = false;
                }

                // tor.exe must be gone first: Windows locks running binaries.
                if (_engine.IsTorRunning)
                {
                    AppendStatusLine("Update ABORTED: tor.exe is still running and would lock its files — kill it in Task Manager and retry. Nothing was changed.");
                    MessageBox.Show(this,
                        "Tor is still running and must be stopped before updating.\n\nKill tor.exe in Task Manager and retry. Nothing was changed.",
                        "Tor still running", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var progress = new Progress<UpdateProgress>(p =>
                {
                    // Defensive: producers must send finite 0..100, but a NaN/
                    // Infinity (e.g. 0-byte Content-Length division) must never
                    // reach the bar (Value = NaN throws) or print "NaN%"/"∞%".
                    // Non-finite reads as indeterminate, like unknown length.
                    var v = p.PercentOfStage;
                    var finite = v.HasValue && double.IsFinite(v.Value);
                    var pct = finite ? $" ({Math.Max(0.0, Math.Min(100.0, v!.Value)):0}%)" : "";
                    AppendStatusLine(p.Stage + pct);
                    _busyText.Text = updateWarning + "\n\n" + p.Stage + pct;
                    if (finite)
                    {
                        _busyBar.IsIndeterminate = false;
                        _busyBar.Value = Math.Max(0, Math.Min(100, v!.Value));
                    }
                    else
                    {
                        _busyBar.IsIndeterminate = true;
                    }
                });

                await _updater.InstallAsync(url, progress, version);
                AppendStatusLine($"Tor Expert Bundle updated to {version}.");

                // wasRunning is the intent (the toggle was forced off by us
                // for the update, so it can't signal anything here): resume.
                if (wasRunning)
                {
                    _useTor = true;
                    _routingHandler.UseTor = true;
                    _torToggle.IsOn = true;
                    AppendStatusLine("Restarting Tor with the updated binary — re-routing back on...");
                    await StartTor();
                    if (!_engine.RoutingActive)
                        AppendStatusLine("Tor did not come up after the update — use the Tor toggle to retry.");
                }
            }
            catch (Exception ex)
            {
                AppendStatusLine("Update failed: " + ex.Message);
                MessageBox.Show(this, $"Tor Expert Bundle update failed:\n\n{ex.Message}",
                    "Update failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                _updating = false;
                SetBusy(false);
                _updateBundleBtn.IsEnabled = true;
                _torToggle.IsEnabled = true;
            }
        }

        public string CurrentUserAgent => _settings.UserAgent ?? "";

        public string? ApplyUserAgent(string value)
        {
            var v = (value ?? "").Trim();
            try
            {
                _client.DefaultRequestHeaders.UserAgent.Clear();
                var okClient = string.IsNullOrEmpty(v) ||
                    _client.DefaultRequestHeaders.UserAgent.TryParseAdd(v);
                var okUpdater = _updater.SetUserAgent(v);
                if (!okClient || !okUpdater)
                    return "Invalid User-Agent string — not applied, previous/default kept.";
                _settings.UserAgent = v;
                _settings.Save();
                return null;
            }
            catch (Exception ex)
            {
                return "Could not apply User-Agent: " + ex.Message;
            }
        }

        async System.Threading.Tasks.Task SendTestRequest()
        {
            var url = _testUrlInput.Text.Trim();
            if (url.Length == 0) return;
            try
            {
                using var resp = await _client.GetAsync(url);
            }
            catch
            {

            }
        }

        void OnRequestLogged(RequestLogEntry entry)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                _log.Add(entry);
                TrimLog();
            }));
        }

        void MainAppMonitorTick()
        {
            if (_appBusy) return;
            if (!IsVisible)
            {
                // Hidden in tray: no sampling, but never retain rows or
                // streaks for processes that died while we weren't looking.
                try { DropDeadRows(); } catch { }
                try { _streakTracker.Clear(); } catch { }
                return;
            }
            _appBusy = true;
            _ = MainAppMonitorTickAsync();
            if (++_watchTick % 15 == 0) _ = WatchdogTickAsync();
        }

        // Dead man's switch for dead networks: toggle-on-but-not-routing
        // (boot with no ISP, ISP flap killing a start) retries on its own
        // instead of sitting dark until the user notices.
        async System.Threading.Tasks.Task WatchdogTickAsync()
        {
            // Toggle-on-but-dark (boot with no ISP, start killed by a flap)
            // retries on its own. Toggle state IS the intent flag.
            try
            {
                // Single-flight with every lifecycle owner: a watchdog
                // StartTor racing a force-retry or pin rescue serializes on
                // the engine gate into back-to-back bootstraps (the
                // reconnect-over-and-over shape). All three set _startingTor,
                // but check the explicit flags too — belt and suspenders.
                if (_shuttingDown || _updating || _startingTor || _forceRetrying || _pinRescuing) return;
                if (!_torToggle.IsOn || _engine.RoutingActive) { _lastStartError = ""; return; }
                _watchdogRun = true;
                try { await StartTor(); }
                finally { _watchdogRun = false; }
            }
            catch { }
        }

        async System.Threading.Tasks.Task MainAppMonitorTickAsync()
        {
            try
            {
                _appTick++;
                // Process-table walks (every PID + exe path) can stall on
                // wedged drives/shares: enumerate on pool, merge on UI.
                if (_appTick % 5 == 0)
                {
                    Dictionary<int, RunningAppInfo>? current = null;
                    try
                    {
                        current = await System.Threading.Tasks.Task.Run(
                            () => RunningAppEnumerator.GetNonSystemUserApps()
                                .ToDictionary(a => a.Pid));
                    }
                    catch { }
                    if (current != null) MergeMainAppRows(current);
                    else DropDeadRows();
                }
                else DropDeadRows();
                // Engine PIDs (tor + transports) refresh every tick on pool:
                // their rows appear within a second of spawn and their
                // verdict below is always Engine, never Direct.
                try
                {
                    var engine = await System.Threading.Tasks.Task.Run(() => _engine.GetEnginePids());
                    _enginePids.Clear();
                    var known = new HashSet<int>();
                    foreach (var row in _appRows) known.Add(row.Pid);
                    foreach (var e in engine)
                    {
                        _enginePids.Add(e.pid);
                        if (!known.Contains(e.pid))
                            _appRows.Add(new MonitoredApp(e.pid, e.name, e.exePath));
                    }
                }
                catch { }
                // Table walk off-UI (grows with socket counts); rows update back on UI context.
                var traffic = await System.Threading.Tasks.Task.Run(
                    () => AppTrafficMonitor.Snapshot(_engine.SocksPort, _engine.BridgePort));
                foreach (var row in _appRows)
                {
                    // Engine rows skip the table verdict: tor's guard/tunnel
                    // egress would read as Direct, which it is not — it IS
                    // the tunnel. EngineVerdict is kind 1, so these rows can
                    // never trip the Direct warnings or streaks (kind == 2).
                    if (_enginePids.Contains(row.Pid))
                    {
                        var (elabel, ekind, edetail) = TorEngine.EngineVerdict(row.Name);
                        row.SetHealth(elabel, ekind, edetail);
                        continue;
                    }
                    traffic.TryGetValue(row.Pid, out var stats);
                    var (label, kind, detail) = AppTrafficMonitor.Verdict(stats);
                    // Under a LIVE lockdown a "Direct" row is a dropped
                    // attempt, not a delivered bypass: the packet filter
                    // drops non-Tor egress, but the TCP table still shows the
                    // SYN. Rendering it red "Direct" (and streak-warning it
                    // as "bypassing Tor") is a false leak alarm — the exact
                    // confusion reported with pin + lockdown on. Render as
                    // Blocked (kind 3: never trips Direct streaks) while the
                    // filter holds. When the filter is DOWN the rows stay
                    // red Direct and the transition watch below alarms.
                    try
                    {
                        if (kind == 2 && _engine.EnforcementActive)
                        {
                            row.SetHealth("Blocked", 3, detail + " — dropped by lockdown (not delivered)");
                            continue;
                        }
                    }
                    catch { }
                    row.SetHealth(label, kind, detail);
                }
                WatchEnforcementTransitions();
                WarnNewlyDirect();
            }
            catch { }
            finally { _appBusy = false; }
        }

        void DropDeadRows()
        {
            try
            {
                for (var i = _appRows.Count - 1; i >= 0; i--)
                    if (RunningAppEnumerator.IsPidDead(_appRows[i].Pid))
                        _appRows.RemoveAt(i);
            }
            catch { }
        }

        // The Apps list is display-only info: it is cleared whenever the
        // window hides (no stale/dead rows accumulate unseen) and rebuilt
        // from a fresh enumeration on every restore. Single-flight: overlapping
        // restores converge on exactly one rebuild, and the UI callback always
        // clears before adding, so duplicates are impossible by construction
        // (merges elsewhere only ever add PIDs missing from current rows).
        bool _repopulating;

        void RepopulateAppRows()
        {
            if (_repopulating) return;
            _repopulating = true;
            _ = System.Threading.Tasks.Task.Run(() =>
            {
                List<RunningAppInfo> list;
                try { list = RunningAppEnumerator.GetNonSystemUserApps(); }
                catch { list = new List<RunningAppInfo>(); }
                SafeBeginInvoke(() =>
                {
                    try
                    {
                        _appRows.Clear();
                        foreach (var a in list)
                            _appRows.Add(new MonitoredApp(a.Pid, a.Name, a.ExePath));
                    }
                    catch { }
                    finally { _repopulating = false; }
                });
            });
        }

        void MergeMainAppRows(Dictionary<int, RunningAppInfo> current)
        {
            try
            {
                for (var i = _appRows.Count - 1; i >= 0; i--)
                {
                    var row = _appRows[i];
                    if (!current.TryGetValue(row.Pid, out var app))
                        _appRows.RemoveAt(i);
                    else if (!string.Equals(row.ExePath, app.ExePath, StringComparison.OrdinalIgnoreCase))
                    {
                        row.Name = app.Name;
                        row.ExePath = app.ExePath;
                    }
                }
                var known = new HashSet<int>(_appRows.Select(r => r.Pid));
                foreach (var app in current.Values)
                    if (!known.Contains(app.Pid))
                        _appRows.Add(new MonitoredApp(app.Pid, app.Name, app.ExePath));
            }
            catch { }
        }

        DateTime _lastUdpWarnUtc = DateTime.MinValue;

        // 1s enforcement transition watch (see _lastEnforcementSeen): the
        // link-tick watchdog (~30s) also covers this, but a dead filter
        // under "routing on" is a live leak window — badge + log it within
        // a second. UI thread only. Never throws.
        void WatchEnforcementTransitions()
        {
            try
            {
                if (!_engine.RoutingActive)
                {
                    _lastEnforcementSeen = null;
                    _lastEnforcementDegradedSeen = false;
                    return;
                }
                bool active = false, degraded = false;
                try { active = _engine.EnforcementActive; } catch { }
                try { degraded = _engine.EnforcementDegraded; } catch { }
                if (_lastEnforcementSeen == null)
                {
                    _lastEnforcementSeen = active;
                    _lastEnforcementDegradedSeen = degraded;
                    return;
                }
                if (active != _lastEnforcementSeen || degraded != _lastEnforcementDegradedSeen)
                {
                    _lastEnforcementSeen = active;
                    _lastEnforcementDegradedSeen = degraded;
                    try { RefreshRoutingBadge(); } catch { }
                    // Neutral wording on purpose: this also fires when the
                    // user deliberately turns lockdown off in Config (not
                    // just when the filter dies) — don't accuse them of a
                    // failure, but make the exposure window unmistakable.
                    if (!active)
                        AppendStatusLine("Tor-only lockdown is OFF while routing stays ON — non-proxy apps can go DIRECT right now. (If you didn't turn it off, the filter died: toggle lockdown off/on in Config to recover.)");
                    else if (degraded)
                        AppendStatusLine("Lockdown DEGRADED (filter held, traffic fails closed/drops — NOT leaking direct). Toggle lockdown off/on to recover.");
                    else
                        AppendStatusLine("Tor-only lockdown back ON — direct bypasses blocked again.");
                }
            }
            catch { }
        }

        void WarnNewlyDirect()
        {
            try
            {
                if (!_engine.RoutingActive) return;
                // Live lockdown drops non-Tor egress, so a kind-2 row here
                // can only be a snapshot race with the Blocked remap above
                // (or the filter died between the two reads) — never a
                // confirmed bypass. Stay silent while held; the transition
                // watch alarms if the filter actually went down. Streaks are
                // cleared so a later real outage starts counting fresh.
                try { if (_engine.EnforcementActive) { try { _streakTracker.Clear(); } catch { } return; } } catch { }
                var offenders = _streakTracker.Update(CollectDirectFlags(), threshold: 3);
                if (offenders.Count > 0)
                {
                    var byPid = new Dictionary<int, string>();
                    foreach (var row in _appRows) byPid[row.Pid] = row.Name;
                    var names = new List<string>();
                    foreach (var pid in offenders)
                        names.Add(byPid.TryGetValue(pid, out var n) ? $"{n} (PID {pid})" : $"PID {pid}");
                    AppendStatusLine("WARNING: " + string.Join(", ", names) +
                        " talking DIRECT (bypassing Tor) for 3s+ — check its own proxy settings / QUIC (see Config). Tor-only lockdown prevents this class entirely.");
                }
                // UDP-only rows never reach kind 2 (a bound UDP socket is not
                // proof of traffic), so QUIC/WebRTC/DNS-over-UDP bypasses are
                // invisible to the streak above — yet Tor carries no UDP, so
                // without lockdown every such socket bypasses Tor by design
                // and "starts leaking after some time" when the browser
                // upgrades TCP-via-Tor to QUIC-direct (Alt-Svc / HTTP/3
                // discovery typically lands minutes into a session — the
                // classic out-of-nowhere report). Throttled info, not a
                // per-app warning: bound != active, so don't name names here.
                // 5min cadence (was 10min): the leak starts the moment the
                // upgrade happens, so the note must land close to it.
                try
                {
                    if (!_engine.EnforcementActive &&
                        (DateTime.UtcNow - _lastUdpWarnUtc).TotalMinutes >= 5)
                    {
                        var udpHolders = new List<string>();
                        foreach (var row in _appRows)
                        {
                            if (_enginePids.Contains(row.Pid)) continue;
                            var d = row.Detail ?? "";
                            if (d.Contains("UDP direct"))
                                udpHolders.Add($"{row.Name} (PID {row.Pid})");
                        }
                        if (udpHolders.Count > 0)
                        {
                            _lastUdpWarnUtc = DateTime.UtcNow;
                            AppendStatusLine("NOTE: " + string.Join(", ", udpHolders.Take(3)) +
                                (udpHolders.Count > 3 ? $" (+{udpHolders.Count - 3} more)" : "") +
                                " hold direct UDP sockets (QUIC/WebRTC/DNS — Tor carries no UDP). Without Tor-only lockdown this bypasses Tor; " +
                                "with lockdown it is dropped at the packet layer. Enable lockdown in Config (admin) to close it.");
                        }
                    }
                }
                catch { }
            }
            catch { }
        }

        DateTime _lastRotationWarnUtc = DateTime.MinValue;

        // Rotation kills in-flight circuits: proxy clients see errors, and
        // apps with their own proxy-failure fallback go direct in that
        // window. Sweep shortly after every rotation and name names.
        async System.Threading.Tasks.Task PostRotationDirectCheckAsync()
        {
            try
            {
                await System.Threading.Tasks.Task.Delay(TimeSpan.FromSeconds(8));
                if (_shuttingDown || !_engine.RoutingActive) return;
                if (_engine.EnforcementActive) return; // divert makes direct impossible; skip noise
                if ((DateTime.UtcNow - _lastRotationWarnUtc).TotalSeconds < 30) return;
                await Dispatcher.InvokeAsync(() =>
                {
                    try
                    {
                        var direct = new System.Collections.Generic.List<string>();
                        foreach (var row in _appRows)
                            if (row.HealthKind == 2)
                                direct.Add($"{row.Name} (PID {row.Pid})");
                        if (direct.Count == 0) return;
                        _lastRotationWarnUtc = DateTime.UtcNow;
                        AppendStatusLine("WARNING right after circuit rotation: " + string.Join(", ", direct) +
                            " talking DIRECT — fell back during the rotation window. Tor-only lockdown (Config) makes this impossible.");
                    }
                    catch { }
                });
            }
            catch { }
        }

        System.Collections.Generic.IEnumerable<(int pid, bool direct)> CollectDirectFlags()
        {
            foreach (var row in _appRows)
                yield return (row.Pid, row.HealthKind == 2);
        }

        void OnTrafficRelayed(string host, int port, string mode, string spoofedHost = "", string sni = "")
        {
            // Per-connection pool-thread events: sample at 5Hz so floods can't queue the UI dead.
            var now = DateTime.UtcNow.Ticks;
            var last = System.Threading.Interlocked.Read(ref _lastRelayEmitTicks);
            if (now - last < System.TimeSpan.FromMilliseconds(200).Ticks) return;
            System.Threading.Interlocked.Exchange(ref _lastRelayEmitTicks, now);
            Dispatcher.BeginInvoke(new Action(() =>
            {
                var key = mode + "://" + host + ":" + port + "|" + spoofedHost + "|" + sni;
                var now = DateTime.UtcNow;
                lock (_relayLoggedAt)
                {
                    if (_relayLoggedAt.TryGetValue(key, out var last) && (now - last).TotalSeconds < 3)
                        return;
                    _relayLoggedAt[key] = now;
                    if (_relayLoggedAt.Count > 1000)
                    {
                        foreach (var k in new List<string>(_relayLoggedAt.Keys))
                            if ((now - _relayLoggedAt[k]).TotalMinutes > 5)
                                _relayLoggedAt.Remove(k);
                    }
                }

                var extra = "";
                if (!string.IsNullOrEmpty(spoofedHost)) extra += $" (Host:{TruncateStatus(spoofedHost)})";
                if (!string.IsNullOrEmpty(sni) && !sni.Equals(host, StringComparison.OrdinalIgnoreCase))
                    extra += $" (SNI:{TruncateStatus(sni)})";
                _log.Add(new RequestLogEntry
                {
                    Time = DateTime.Now.ToString("HH:mm:ss"),
                    Method = mode,
                    Host = host,
                    Route = "Relay",
                    Status = "→ Tor" + extra
                });
                TrimLog();
            }));
        }

        static string TruncateStatus(string v) => v.Length <= 24 ? v : v.Substring(0, 24) + "…";

        void TrimLog()
        {
            while (_log.Count > MaxLogRows)
                _log.RemoveAt(0);
        }

        void BuildTrayIcon()
        {
            var hwnd = new WindowInteropHelper(this).EnsureHandle();
            string? iconPath = null;
            try
            {
                var candidate = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "logo.ico");
                if (System.IO.File.Exists(candidate))
                    iconPath = candidate;
            }
            catch { }
            _trayIcon = new NativeTrayIcon(hwnd, "Tor Traffic Router", iconPath);
            _trayIcon.ShowRequested += () => SafeBeginInvoke(RestoreFromTray);
            _trayIcon.ConfigRequested += () => SafeBeginInvoke(OpenConfigSafe);
            _trayIcon.ToggleRoutingRequested += () => SafeBeginInvoke(() => _ = ToggleRoutingFromTrayAsync());
            _trayIcon.ExitRequested += () => SafeBeginInvoke(() => ExitApplication());
            // Always-on tray: visible from startup regardless of window
            // state, so a stuck boot (busy overlay covering the window) can
            // still be escaped via tray → Config. Hidden only on real exit.
            try { _trayIcon.Show(); } catch { }
        }

        void SafeBeginInvoke(Action action)
        {
            try
            {
                if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished) return;
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    try { action(); }
                    catch { }
                }));
            }
            catch { }
        }

        void SafeBeginInvoke(Func<System.Threading.Tasks.Task> action)
        {
            SafeBeginInvoke(() => _ = SafeFireAndForget(action));
        }

        static async System.Threading.Tasks.Task SafeFireAndForget(Func<System.Threading.Tasks.Task> action)
        {
            try { await action(); } catch { }
        }

        async System.Threading.Tasks.Task ToggleRoutingFromTrayAsync()
        {
            if (_shuttingDown) return;
            // Tray stays reachable behind the update overlay: refuse while the installer owns the engine.
            if (_updating)
            {
                AppendStatusLine("Routing change refused — a Tor bundle update is installing. Wait for it to finish.");
                return;
            }
            if (_startingTor || _forceRetrying || _pinRescuing) return;
            if (_engine.RoutingActive)
            {
                await StopTor();
            }
            else
            {
                _useTor = true;
                _routingHandler.UseTor = true;
                _torToggle.IsOn = true;
                await StartTor();
            }
        }

        void RestoreFromTray()
        {
            if (_shuttingDown) return;
            Show();
            WindowState = WindowState.Normal;
            try { ShowInTaskbar = true; } catch { }
            Activate();
            // Tray stays visible (always-on): no Hide() here — Hide runs
            // only on real exit/dispose, so there is never a state with no
            // tray and no window.
            RepopulateAppRows();
        }

        void MainWindow_StateChanged(object sender, EventArgs e)
        {
            if (_shuttingDown) return;
            if (WindowState == WindowState.Minimized)
            {
                ClearAppRows();
                Hide();
                try { _trayIcon.Show(); } catch { }
            }
        }

        void MainWindow_Closing(object sender, CancelEventArgs e)
        {
            // Minimize-to-tray, never actual close (exits die via DieNow
            // instead): during shutdown let it proceed.
            if (_shuttingDown) return;
            e.Cancel = true;
            Hide();
            try { _trayIcon.Show(); } catch { }
            // Discoverability: X hiding to the tray while tor keeps routing
            // is exactly the perennial "exit doesn't work, tor still runs"
            // report. Say it out loud wherever the user will look next.
            try { AppendStatusLine("Minimized to tray — Tor still routing. Tray → Exit quits for real."); } catch { }
            try { _trayIcon.SetTooltip("PTor: running in tray — right-click → Exit quits"); } catch { }
        }

        // Windows itself is going down (shutdown/reboot/logoff): our Closing
        // handler hides-to-tray by default, which would stall the OS session.
        // Restore networking fast, then get out of the way (no self-kill
        // needed — the OS is already terminating us). Fully synchronous:
        // tor killed first, windivert closed, internet recovered, no waits —
        // the OS gives only seconds and Task+Wait parking is gone.
        void OnSystemSessionEnding()
        {
            try { ExitTrace.Log("os session ending: fast restore, not blocking"); } catch { }
            _shuttingDown = true;
            try { _engine.BarbaricQuitTeardown(); } catch { }
        }

        // Display-only data must not outlive visibility: drop rows + streaks
        // the moment we hide, so nothing dead accumulates unseen. UI thread
        // only, like every other _appRows touch.
        void ClearAppRows()
        {
            try { _appRows.Clear(); } catch { }
            try { _streakTracker.Clear(); } catch { }
        }

        // Barbaric quit: FULLY SYNCHRONOUS — zero await anywhere below.
        // The old path awaited a process-table snapshot (up to 2s) plus a
        // bounded async teardown (up to ~7s of WhenAny parking), which is
        // exactly the quit stall. Now: sync confirm (no snapshot walk),
        // sync BarbaricQuitTeardown (tor FIRST, then windivert, then
        // internet — all millisecond-scale, no waits), then DieNow.
        // Returns void so no caller can await it back into existence.
        void ExitApplication()
        {
            if (_shuttingDown) return;
            if (_updating)
            {
                var updateText =
                    "A Tor bundle update is installing right now — quitting mid-install can leave it half-written. " +
                    "Wait for it to finish (interrupting is safe: leftovers self-heal on next start).";
                // Same hidden-owner rule as the quit confirm: never stack an
                // invisible modal (each tray Exit click would pile another).
                var updateVisible = false;
                try { updateVisible = IsVisible; } catch { }
                if (updateVisible)
                    MessageBox.Show(this, updateText, "Update in progress", MessageBoxButton.OK, MessageBoxImage.Information);
                else
                    MessageBox.Show(updateText, "Update in progress", MessageBoxButton.OK, MessageBoxImage.Information);
                ExitTrace.Log("exit refused: update in progress");
                return;
            }
            _shuttingDown = true;
            // Watchdog arms AFTER the quit confirm below (not here): arming
            // before the modal would kill the process — with network still
            // managed — if the user takes >10s to answer, and the cancel path
            // could never disarm it in time.
            ExitTrace.Log("exit begin (tray)");
            try
            {
                // The window is usually still hidden in the tray when Exit comes
                // from the tray menu: bring it forward FIRST so the confirm
                // dialog below is actually visible. (A modal dialog owned by
                // a hidden window looks exactly like a freeze: the app waits
                // for an answer the user cannot see.)
                var wasHidden = false;
                try
                {
                    wasHidden = !IsVisible;
                    Show();
                    WindowState = WindowState.Normal;
                    ShowInTaskbar = true;
                    Activate();
                    ExitTrace.Log("exit window restored wasHidden=" + wasHidden);
                }
                catch (Exception ex) { ExitTrace.Log("exit restore failed: " + ex.GetType().Name); }

                if (_engine.RoutingActive)
                {
                    // Sync confirm on purpose: the async version walks the
                    // process table (up to 2s) before asking — that wait is
                    // gone; the generic warning below names the consequence.
                    var text = "Apps launched while routing was on keep Tor proxy env until restarted.\n\n" +
                        "They will go OFFLINE until you restart them. Quit PTor anyway?";
                    var visible = false;
                    try { visible = IsVisible; } catch { }
                    var answer = visible
                        ? MessageBox.Show(this, text, "Apps will go offline", MessageBoxButton.YesNo, MessageBoxImage.Warning)
                        : MessageBox.Show(text, "Apps will go offline", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                    ExitTrace.Log("exit confirm proceed=" + (answer == MessageBoxResult.Yes));
                    if (answer != MessageBoxResult.Yes)
                    {
                        _shuttingDown = false;
                        try { DisarmSelfDestruct(); } catch { }
                        AppendStatusLine("Quit cancelled — routing still on.");
                        try
                        {
                            if (wasHidden)
                            {
                                Hide();
                                _trayIcon.Show();
                            }
                        }
                        catch { }
                        ExitTrace.Log("exit cancelled by user");
                        return;
                    }
                }

                AppendStatusLine("Restoring network and exiting...");
                // From here on the process WILL die: even if a step below
                // wedges, the watchdog TerminateProcess-kills us. Tor is
                // killed in the first milliseconds of the teardown, so the
                // watchdog can never orphan it — it only finishes our death.
                ArmSelfDestruct(10000);
                try { _appMonitorTimer?.Stop(); } catch { }
                // BARBARIC: tor killed first, windivert closed, internet
                // recovered — synchronously, nothing awaited. Returns in ms.
                string report;
                try { report = _engine.BarbaricQuitTeardown(); }
                catch (Exception ex) { report = "barbaric teardown issue: " + ex.Message; }
                ExitTrace.Log("exit restored: " + report);
                // Tray icon off first (no ghost), then deterministic death:
                // shared state is restored above, tor is killed, and the
                // death-pact job reaps anything left. No dispatcher dance.
                try { _trayIcon.Hide(); } catch (Exception ex) { ExitTrace.Log("exit tray hide: " + ex.GetType().Name); }
                ExitTrace.Log("exit bye");
            }
            catch (Exception ex)
            {
                ExitTrace.Log("exit UNEXPECTED, dying anyway: " + ex.GetType().Name + " " + ex.Message);
            }
            DieNow();
        }
    }

    public class ToggleSwitch : Border
    {
        static readonly SolidColorBrush OffBrush = new SolidColorBrush(Color.FromRgb(0x4A, 0x51, 0x60));
        static readonly SolidColorBrush TrackBorderBrush = new SolidColorBrush(Color.FromRgb(0x34, 0x3A, 0x46));
        static readonly SolidColorBrush OnBorderBrush = new SolidColorBrush(Color.FromRgb(0x3F, 0xA8, 0xD6));
        static ToggleSwitch()
        {
            try { OffBrush.Freeze(); TrackBorderBrush.Freeze(); OnBorderBrush.Freeze(); } catch { }
        }
        readonly Border _knob;
        readonly Brush _onBrush;
        readonly Brush _offBrush = OffBrush;
        bool _isOn;

        public event Action<object, bool> Toggled;

        public bool IsOn
        {
            get => _isOn;
            set { _isOn = value; Render(); }
        }

        public ToggleSwitch(Brush onBrush)
        {
            _onBrush = onBrush;
            Width = 46;
            Height = 25;
            CornerRadius = new CornerRadius(12);
            Cursor = System.Windows.Input.Cursors.Hand;
            Background = _offBrush;
            BorderBrush = TrackBorderBrush;
            BorderThickness = new Thickness(1);
            Padding = new Thickness(2);

            _knob = new Border
            {
                Width = 19,
                Height = 19,
                CornerRadius = new CornerRadius(10),
                Background = Brushes.White,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Center
            };
            Child = _knob;

            // Dim while disabled (the main window flips IsEnabled during
            // starts): a Border has no built-in disabled look.
            IsEnabledChanged += (_, __) =>
            {
                try { Opacity = IsEnabled ? 1.0 : 0.45; } catch { }
            };

            MouseLeftButtonUp += (_, __) =>
            {
                _isOn = !_isOn;
                Render();
                Toggled?.Invoke(this, _isOn);
            };
        }

        void Render()
        {
            Background = _isOn ? _onBrush : _offBrush;
            BorderBrush = _isOn ? OnBorderBrush : TrackBorderBrush;
            _knob.HorizontalAlignment = _isOn ? HorizontalAlignment.Right : HorizontalAlignment.Left;
        }
    }

    public class NativeTrayIcon : IDisposable
    {
        const int WM_TRAYICON = 0x8000 + 1;
        const int NIF_MESSAGE = 0x1;
        const int NIF_ICON = 0x2;
        const int NIF_TIP = 0x4;
        const int NIM_ADD = 0x0;
        const int NIM_MODIFY = 0x1;
        const int NIM_DELETE = 0x2;
        const int WM_LBUTTONDBLCLK = 0x203;
        const int WM_RBUTTONUP = 0x205;
        const uint MF_STRING = 0x0;
        const uint MF_SEPARATOR = 0x800;
        const uint TPM_RIGHTBUTTON = 0x0002;
        const uint TPM_RETURNCMD = 0x0100;
        const int ID_SHOW = 1001;
        const int ID_EXIT = 1002;
        const int ID_TOGGLE_ROUTING = 1003;
        const int ID_CONFIG = 1004;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct NOTIFYICONDATA
        {
            public int cbSize;
            public IntPtr hWnd;
            public int uID;
            public int uFlags;
            public int uCallbackMessage;
            public IntPtr hIcon;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szTip;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct POINT { public int X; public int Y; }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        static extern bool Shell_NotifyIcon(int dwMessage, ref NOTIFYICONDATA lpData);

        [DllImport("user32.dll")]
        static extern IntPtr LoadIcon(IntPtr hInstance, IntPtr lpIconName);

        const uint IMAGE_ICON = 1;
        const uint LR_LOADFROMFILE = 0x10;
        const uint LR_DEFAULTSIZE = 0x40;

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr LoadImage(IntPtr hinst, string lpszName, uint uType, int cxDesired, int cyDesired, uint fuLoad);

        [DllImport("user32.dll")]
        static extern bool DestroyIcon(IntPtr hIcon);

        [DllImport("user32.dll")]
        static extern IntPtr CreatePopupMenu();

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern bool AppendMenu(IntPtr hMenu, uint uFlags, uint uIDNewItem, string lpNewItem);

        [DllImport("user32.dll")]
        static extern bool DestroyMenu(IntPtr hMenu);

        [DllImport("user32.dll")]
        static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        static extern int TrackPopupMenuEx(IntPtr hMenu, uint uFlags, int x, int y, IntPtr hWnd, IntPtr lptpm);

        [DllImport("user32.dll")]
        static extern bool GetCursorPos(out POINT lpPoint);

        [DllImport("user32.dll")]
        static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        const uint WM_NULL = 0x0000;

        readonly IntPtr _hwnd;
        readonly HwndSource _source;
        NOTIFYICONDATA _data;
        bool _visible;

        public event Action ShowRequested;
        public event Action ConfigRequested;
        public event Action ToggleRoutingRequested;
        public event Action ExitRequested;

        bool _routingOn = true;

        public void SetRoutingOn(bool on) { _routingOn = on; }

        bool _ownsIcon;

        public NativeTrayIcon(IntPtr hwnd, string tooltip, string? iconPath = null)
        {
            _hwnd = hwnd;
            _source = HwndSource.FromHwnd(hwnd);
            _source.AddHook(WndProc);

            _data = new NOTIFYICONDATA
            {
                cbSize = Marshal.SizeOf(typeof(NOTIFYICONDATA)),
                hWnd = hwnd,
                uID = 1,
                uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
                uCallbackMessage = WM_TRAYICON,
                hIcon = LoadAppIcon(iconPath),
                szTip = tooltip
            };
        }

        IntPtr LoadAppIcon(string? iconPath)
        {
            var fallback = LoadIcon(IntPtr.Zero, new IntPtr(32512));
            if (string.IsNullOrEmpty(iconPath)) return fallback;
            try
            {
                if (!System.IO.File.Exists(iconPath)) return fallback;
                var h = LoadImage(IntPtr.Zero, iconPath, IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE);
                if (h == IntPtr.Zero) return fallback;
                _ownsIcon = true;
                return h;
            }
            catch { return fallback; }
        }

        public void Show()
        {
            if (_visible) return;
            Shell_NotifyIcon(NIM_ADD, ref _data);
            _visible = true;
        }

        public void Hide()
        {
            if (!_visible) return;
            Shell_NotifyIcon(NIM_DELETE, ref _data);
            _visible = false;
        }

        public void SetTooltip(string tip)
        {
            try
            {
                if (!_visible) return;
                _data.szTip = string.IsNullOrEmpty(tip) ? "Tor Traffic Router"
                    : tip.Length <= 120 ? tip : tip.Substring(0, 120);
                Shell_NotifyIcon(NIM_MODIFY, ref _data);
            }
            catch { }
        }

        IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (msg == WM_TRAYICON)
            {
                int mouseMsg = lParam.ToInt32();
                if (mouseMsg == WM_LBUTTONDBLCLK)
                {
                    ShowRequested?.Invoke();
                    handled = true;
                }
                else if (mouseMsg == WM_RBUTTONUP)
                {
                    ShowContextMenu();
                    handled = true;
                }
            }
            return IntPtr.Zero;
        }

        void ShowContextMenu()
        {
            GetCursorPos(out var pt);
            IntPtr menu = CreatePopupMenu();
            try
            {
                AppendMenu(menu, MF_STRING, ID_SHOW, "Show");
                AppendMenu(menu, MF_STRING, ID_CONFIG, "Config...");
                AppendMenu(menu, MF_STRING, ID_TOGGLE_ROUTING, _routingOn ? "Disable routing" : "Enable routing");
                AppendMenu(menu, MF_SEPARATOR, 0, string.Empty);
                AppendMenu(menu, MF_STRING, ID_EXIT, "Exit");

                SetForegroundWindow(_hwnd);
                int cmd = TrackPopupMenuEx(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.X, pt.Y, _hwnd, IntPtr.Zero);
                // Required after TrackPopupMenuEx: tells the menu's nested
                // message loop the gesture is over. Without it the next modal
                // window (quit confirm, ...) can deadlock — the tray-exit freeze.
                try { PostMessage(_hwnd, WM_NULL, IntPtr.Zero, IntPtr.Zero); } catch { }

                if (cmd == ID_SHOW) ShowRequested?.Invoke();
                else if (cmd == ID_CONFIG) ConfigRequested?.Invoke();
                else if (cmd == ID_TOGGLE_ROUTING) ToggleRoutingRequested?.Invoke();
                else if (cmd == ID_EXIT) ExitRequested?.Invoke();
            }
            finally
            {
                try { DestroyMenu(menu); } catch { }
            }
        }

        bool _disposedIcon;

        public void Dispose()
        {
            if (_disposedIcon) return;
            _disposedIcon = true;
            Hide();
            try { _source?.RemoveHook(WndProc); } catch { }
            if (_ownsIcon && _data.hIcon != IntPtr.Zero)
            {
                try { DestroyIcon(_data.hIcon); } catch { }
                _data.hIcon = IntPtr.Zero;
                _ownsIcon = false;
            }
        }
    }

    public class DomainRoutingHandler : DelegatingHandler
    {
        readonly ObservableCollection<string> _blockedDomains;
        readonly Action<RequestLogEntry> _onLogged;

        public bool UseTor { get; set; } = true;
        public string TorSocksHost { get; set; } = "127.0.0.1";
        public int TorSocksPort { get; set; } = 9050;

        HttpMessageHandler _currentInner;
        bool _lastMode;
        readonly object _innerGate = new();

        public void DropPooledConnections()
        {
            lock (_innerGate)
            {
                try { _currentInner?.Dispose(); } catch { }
                _currentInner = null;
            }
        }

        public DomainRoutingHandler(ObservableCollection<string> blockedDomains, Action<RequestLogEntry> onLogged)
        {
            _blockedDomains = blockedDomains;
            _onLogged = onLogged;
        }

        HttpMessageHandler BuildInner(bool useTor)
        {
            var handler = new SocketsHttpHandler
            {
                AutomaticDecompression = DecompressionMethods.All,
                PooledConnectionLifetime = TimeSpan.FromMinutes(2)
            };

            if (useTor)
            {

                handler.Proxy = new WebProxy(new Uri($"socks5://{TorSocksHost}:{TorSocksPort}"));
                handler.UseProxy = true;
            }
            else
            {
                handler.UseProxy = false;
            }

            return handler;
        }

        protected override async System.Threading.Tasks.Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            var host = request.RequestUri?.Host?.ToLowerInvariant() ?? "(unknown)";
            var entry = new RequestLogEntry
            {
                Time = DateTime.Now.ToString("HH:mm:ss"),
                Method = request.Method.Method,
                Host = host,
                Route = UseTor ? "Tor" : "Direct"
            };

            if (IsBlocked(host))
            {
                entry.Status = "Blocked";
                _onLogged(entry);
                throw new HttpRequestException($"Domain '{host}' is blocked by the domain blocklist.");
            }

            EnsureInnerMatchesMode();

            try
            {
                var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
                entry.Status = ((int)response.StatusCode).ToString();
                _onLogged(entry);
                return response;
            }
            catch (ObjectDisposedException)
            {
                // Handler swapped mid-flight (rotation/toggle): re-sync once and retry.
                EnsureInnerMatchesMode();
                try
                {
                    var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
                    entry.Status = ((int)response.StatusCode).ToString();
                    _onLogged(entry);
                    return response;
                }
                catch (Exception ex2)
                {
                    entry.Status = "Error: " + ex2.GetType().Name;
                    _onLogged(entry);
                    throw;
                }
            }
            catch (Exception ex)
            {
                entry.Status = "Error: " + ex.GetType().Name;
                _onLogged(entry);
                throw;
            }
        }

        void EnsureInnerMatchesMode()
        {
            lock (_innerGate)
            {
                if (_currentInner == null || _lastMode != UseTor)
                {
                    try { _currentInner?.Dispose(); } catch { }
                    _currentInner = BuildInner(UseTor);
                    InnerHandler = _currentInner;
                    _lastMode = UseTor;
                }
            }
        }

        bool IsBlocked(string host)
        {
            // Manual user blocklist: the UI thread mutates this collection
            // while pool threads read, so snapshot. One slip max per edit.
            string[] snapshot;
            try { snapshot = new System.Collections.Generic.List<string>(_blockedDomains).ToArray(); }
            catch (InvalidOperationException) { return false; }
            catch { return false; }
            foreach (var d in snapshot)
            {
                if (host.Equals(d, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
    }

    public class RequestLogEntry
    {
        public string Time { get; set; }
        public string Method { get; set; }
        public string Host { get; set; }
        public string Route { get; set; }
        public string Status { get; set; }
    }
}
