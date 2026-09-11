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
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace PTor
{
    public partial class MainWindow : Window
    {

        static readonly SolidColorBrush BgBrush = new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20));
        static readonly SolidColorBrush PanelBrush = new SolidColorBrush(Color.FromRgb(0x2B, 0x2B, 0x2B));
        static readonly SolidColorBrush AccentBrush = new SolidColorBrush(Color.FromRgb(0x60, 0xCD, 0xFF));
        static readonly SolidColorBrush TextBrush = Brushes.WhiteSmoke;
        static readonly SolidColorBrush DimBrush = new SolidColorBrush(Color.FromRgb(0xA0, 0xA0, 0xA0));
        static readonly SolidColorBrush DangerBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0x6B, 0x6B));
        static readonly SolidColorBrush GoodBrush = new SolidColorBrush(Color.FromRgb(0x4C, 0xD9, 0x64));
        static readonly SolidColorBrush WarnBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0xC1, 0x4C));
        static readonly SolidColorBrush DarkGreenBrush = new SolidColorBrush(Color.FromRgb(0x1B, 0x5E, 0x20));
        static readonly SolidColorBrush DarkGreenHoverBrush = new SolidColorBrush(Color.FromRgb(0x26, 0x7A, 0x2E));
        static readonly SolidColorBrush DarkGreenPressedBrush = new SolidColorBrush(Color.FromRgb(0x12, 0x40, 0x16));
        static readonly SolidColorBrush DisabledBrush = new SolidColorBrush(Color.FromRgb(0x3A, 0x3A, 0x3A));

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
        readonly DirectStreakTracker _streakTracker = new DirectStreakTracker();
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
        Ellipse _statusDot;
        Border _busyOverlay;
        TextBlock _busyText;
        ProgressBar _busyBar;
        readonly List<Control> _busyLockControls = new List<Control>();

        bool _useTor = true;
        bool _reallyClose;
        bool _shuttingDown;
        bool _updating;
        bool _startingTor;
        bool _watchdogRun;
        string _lastStartError = "";
        int _watchTick;

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

            BuildUi();
            BuildTrayIcon();

            _settings = AppSettings.Load();
            foreach (var d in _settings.BlockedDomains ?? new List<string>())
                if (!string.IsNullOrWhiteSpace(d) && !_blockedDomains.Contains(d.Trim().ToLowerInvariant()))
                    _blockedDomains.Add(d.Trim().ToLowerInvariant());
            try { _engine.HeaderSpoof = _settings.HeaderSpoof ?? ""; } catch { }
            var uaErr = ApplyUserAgent(_settings.UserAgent ?? "");
            if (uaErr != null) AppendStatusLine(uaErr);

            BuildMainAppRows();
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
            StateChanged += MainWindow_StateChanged;

            _routingHandler.TorSocksHost = "127.0.0.1";
            _routingHandler.TorSocksPort = _engine.SocksPort;

            Loaded += async (_, __) =>
            {
                RemoveLegacyBlocklistCache();
                _ = BootDivertAuditAsync();
                if (_torToggle.IsOn) await StartTor();
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
                    Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri(logo));
            }
            catch { }
            Width = 780;
            Height = 620;
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
                Padding = new Thickness(20, 16, 20, 16)
            };
            Grid.SetRow(header, 0);
            root.Children.Add(header);

            var headerGrid = new Grid();
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            header.Child = headerGrid;

            var titleStack = new StackPanel { Orientation = Orientation.Horizontal };
            _statusDot = new Ellipse { Width = 10, Height = 10, Fill = AccentBrush, Margin = new Thickness(0, 0, 10, 0), VerticalAlignment = VerticalAlignment.Center };
            titleStack.Children.Add(_statusDot);
            titleStack.Children.Add(new TextBlock
            {
                Text = "Tor Traffic Router",
                Foreground = TextBrush,
                FontSize = 18,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });

            _proxyBadge = new TextBlock
            {
                Text = "",
                Foreground = DimBrush,
                FontSize = 11,
                Margin = new Thickness(12, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            titleStack.Children.Add(_proxyBadge);
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

            var controlStrip = new Border { Background = PanelBrush, Padding = new Thickness(20, 10, 20, 10) };
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

            _updateBundleBtn = MakeFlatButton("Update Tor Bundle", DarkGreenBrush, TextBrush);
            _updateBundleBtn.Margin = new Thickness(12, 0, 0, 0);
            _updateBundleBtn.Click += async (_, __) => await UpdateTorBundle();
            controlRow.Children.Add(_updateBundleBtn);
            _busyLockControls.Add(_updateBundleBtn);

            var restartAppBtn = MakeFlatButton("Restart App", DarkGreenBrush, TextBrush);
            restartAppBtn.Margin = new Thickness(12, 0, 0, 0);
            restartAppBtn.Click += async (_, __) => await RestartAppAsync();
            controlRow.Children.Add(restartAppBtn);
            _busyLockControls.Add(restartAppBtn);

            var body = new Grid { Margin = new Thickness(20) };
            Grid.SetRow(body, 2);
            root.Children.Add(body);

            var logPanel = new Border { Background = PanelBrush, CornerRadius = new CornerRadius(8), Padding = new Thickness(14) };
            body.Children.Add(logPanel);

            var logStack = new DockPanel();
            logPanel.Child = logStack;

            var logTitle = new TextBlock { Text = "Request Log", Foreground = TextBrush, FontWeight = FontWeights.SemiBold, FontSize = 14, Margin = new Thickness(0, 0, 0, 10) };
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
                ItemsSource = _log
            };
            var gridView = new GridView();
            gridView.Columns.Add(new GridViewColumn { Header = "Time", DisplayMemberBinding = new System.Windows.Data.Binding("Time"), Width = 70 });
            gridView.Columns.Add(new GridViewColumn { Header = "Method", DisplayMemberBinding = new System.Windows.Data.Binding("Method"), Width = 75 });
            gridView.Columns.Add(new GridViewColumn { Header = "Host", DisplayMemberBinding = new System.Windows.Data.Binding("Host"), Width = 175 });
            gridView.Columns.Add(new GridViewColumn { Header = "Route", DisplayMemberBinding = new System.Windows.Data.Binding("Route"), Width = 60 });
            gridView.Columns.Add(new GridViewColumn { Header = "Status", DisplayMemberBinding = new System.Windows.Data.Binding("Status"), Width = 140 });
            _logView.View = gridView;
            logStack.Children.Add(_logView);
            FillLastColumn(_logView);

            _appsView = new ListView
            {
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Foreground = TextBrush,
                ItemsSource = _appRows,
                Visibility = Visibility.Collapsed
            };
            var appsGrid = new GridView();
            appsGrid.Columns.Add(new GridViewColumn { Header = "PID", DisplayMemberBinding = new System.Windows.Data.Binding("Pid"), Width = 50 });
            appsGrid.Columns.Add(new GridViewColumn { Header = "Name", DisplayMemberBinding = new System.Windows.Data.Binding("Name"), Width = 120 });
            appsGrid.Columns.Add(MonitoredApp.CreateHealthColumn(70));
            appsGrid.Columns.Add(new GridViewColumn { Header = "Detail", DisplayMemberBinding = new System.Windows.Data.Binding("Detail"), Width = 150 });
            _appsView.View = appsGrid;
            logStack.Children.Add(_appsView);
            FillLastColumn(_appsView);

            var footer = new Border { Background = PanelBrush, Padding = new Thickness(20, 10, 20, 10) };
            Grid.SetRow(footer, 3);
            root.Children.Add(footer);

            _statusText = new TextBlock { Foreground = DimBrush, FontSize = 12 };
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
                Height = 14,
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
            _busyOverlay = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(0xE6, 0x20, 0x20, 0x20)),
                Visibility = Visibility.Collapsed,
                Child = busyStack
            };
            Grid.SetRowSpan(_busyOverlay, 4);
            Panel.SetZIndex(_busyOverlay, 100);
            root.Children.Add(_busyOverlay);
        }

        Button MakeTabButton(string text, bool selected)
        {
            return new Button
            {
                Content = text,
                Background = selected ? AccentBrush : PanelBrush,
                Foreground = selected ? Brushes.Black : TextBrush,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(14, 4, 14, 4),
                Cursor = System.Windows.Input.Cursors.Hand
            };
        }

        static void FillLastColumn(ListView lv)
        {
            if (lv.View is not GridView gv || gv.Columns.Count == 0) return;
            void Update()
            {
                try
                {
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
            return new Button
            {
                Content = text,
                Background = bg,
                Foreground = fg,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(14, 6, 14, 6),
                Cursor = System.Windows.Input.Cursors.Hand
            };
        }

        // Square template: default Button chrome is rounded.
        Button MakeFlatButton(string text, Brush bg, Brush fg)
        {
            var btn = new Button
            {
                Content = text,
                Background = bg,
                Foreground = fg,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(14, 6, 14, 6),
                Cursor = System.Windows.Input.Cursors.Hand
            };
            var template = new ControlTemplate(typeof(Button));
            var border = new FrameworkElementFactory(typeof(Border));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(0));
            border.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Button.BackgroundProperty));
            var content = new FrameworkElementFactory(typeof(ContentPresenter));
            content.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            content.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            border.AppendChild(content);
            template.VisualTree = border;

            var hover = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hover.Setters.Add(new Setter(Button.BackgroundProperty, DarkGreenHoverBrush));
            template.Triggers.Add(hover);
            var pressed = new Trigger { Property = Button.IsPressedProperty, Value = true };
            pressed.Setters.Add(new Setter(Button.BackgroundProperty, DarkGreenPressedBrush));
            template.Triggers.Add(pressed);
            var disabled = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
            disabled.Setters.Add(new Setter(Button.BackgroundProperty, DisabledBrush));
            disabled.Setters.Add(new Setter(Button.ForegroundProperty, DimBrush));
            template.Triggers.Add(disabled);

            btn.Template = template;
            return btn;
        }

        TextBox MakeTextBox(string initialText)
        {
            return new TextBox
            {
                Text = initialText,
                Background = BgBrush,
                Foreground = TextBrush,
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x45, 0x45, 0x45)),
                Padding = new Thickness(8, 5, 8, 5),
                VerticalContentAlignment = VerticalAlignment.Center
            };
        }

        // Single-flight: overlapping starts (tray double-fire, watcher vs
        // user) previously raced the busy overlay off while a bootstrap was
        // still running. Returns whether a start actually ran.
        async System.Threading.Tasks.Task<bool> StartTor()
        {
            if (_startingTor) return false;
            _startingTor = true;
            _torToggle.IsEnabled = false;
            SetBusy(true, "Starting Tor…");
            try
            {
                var rotateSecs = ParseRotateSeconds();
                var bridges = new BridgeConfig(_settings.BridgeMode,
                    new System.Collections.Generic.List<string>(_settings.CustomBridgeLines ?? new System.Collections.Generic.List<string>()));
                var exitCountries = _settings.ExitGeoEnabled
                    ? TorPathOptions.ResolveExitCountries(_settings.ExitRegion, _settings.ExitCustomCountries)
                    : new System.Collections.Generic.List<string>();
                await _engine.StartAsync(rotateEverySec: rotateSecs, bridges: bridges,
                    stableConnection: _settings.StableExitEnabled, exitCountries: exitCountries);
                RefreshRoutingBadge();
                if (_settings.EnforceTorOnly && !_engine.EnforcementActive)
                {
                    if (_engine.EnforcementAvailable && AdminHelper.IsAdministrator())
                    {
                        try { AppendStatusLine(await System.Threading.Tasks.Task.Run(() => _engine.EnableEnforcement())); }
                        catch (Exception ex) { AppendStatusLine("Tor-only lockdown preferred ON but failed to engage: " + ex.Message); }
                        RefreshRoutingBadge();
                    }
                    else if (!AdminHelper.IsAdministrator())
                    {
                        AppendStatusLine("Tor-only lockdown preferred ON — skipped (needs administrator rights). Flip it in Config when elevated.");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Intentional stop landed mid-start: not a failure, just release the UI.
                AppendStatusLine("Start cancelled (stop requested).");
                _torToggle.IsOn = false;
                _useTor = false;
                _routingHandler.UseTor = false;
            }
            catch (Exception ex)
            {
                // Watchdog retries every 15s: don't spam the same failure line.
                if (!_watchdogRun || ex.Message != _lastStartError)
                    AppendStatusLine("Failed to start Tor: " + ex.Message);
                _lastStartError = ex.Message;
                _statusDot.Fill = DangerBrush;
                _torToggle.IsOn = false;
                _useTor = false;
                _routingHandler.UseTor = false;
            }
            finally
            {
                SetBusy(false);
                _torToggle.IsEnabled = true;
                _startingTor = false;
            }
            return _engine.RoutingActive;
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
        // seconds on loaded machines: never on the UI thread. The MessageBox
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
                var (shown, total) = await System.Threading.Tasks.Task.Run(
                    () => RunningAppEnumerator.GetLaunchedSince(routingSince.Value));
                if (total == 0)
                    return (true, 0);
                var names = string.Join("\n", shown.Select(s => "  • " + s))
                    + (total > shown.Count ? $"\n  • …and {total - shown.Count} more" : "");
                var text = $"{total} app(s) were launched while routing was on and keep Tor proxy env until restarted:\n{names}\n\n" +
                    $"They will go OFFLINE until you restart them. {actionNoun} anyway?";
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

            new RoutingInfoDialog(_engine, _blockedDomains, _settings, CurrentUserAgent, ApplyUserAgent, AppendStatusLine, RestartAsAdminAsync) { Owner = this }.ShowDialog();
            RefreshRoutingBadge();
        }

        void RefreshRoutingBadge()
        {
            _proxyBadge.Text = _engine.RoutingActive
                ? $"● User apps → Tor · {_engine.ExitLabel}" + (_engine.EnforcementActive ? " · LOCKDOWN" : "")
                : "";
            try { _trayIcon?.SetRoutingOn(_engine.RoutingActive); } catch { }
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
            try { await _engine.StopAsync(); } catch { }
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
            ExitTrace.Log("restart teardown (relaunch)");
            _reallyClose = true;
            ArmExitFailsafe("restart");
            try { _trayIcon.Dispose(); } catch { }
            try { _client.Dispose(); } catch { }
            Close();
            Application.Current.Shutdown();
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
            try { await _engine.StopAsync(); } catch { }
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
            ExitTrace.Log("restart teardown (elevated relaunch)");
            _reallyClose = true;
            ArmExitFailsafe("elevated restart");
            try { _trayIcon.Dispose(); } catch { }
            try { _client.Dispose(); } catch { }
            Close();
            Application.Current.Shutdown();
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
                    var pct = p.PercentOfStage.HasValue ? $" ({p.PercentOfStage:0}%)" : "";
                    AppendStatusLine(p.Stage + pct);
                    _busyText.Text = updateWarning + "\n\n" + p.Stage + pct;
                    if (p.PercentOfStage.HasValue)
                    {
                        _busyBar.IsIndeterminate = false;
                        _busyBar.Value = Math.Max(0, Math.Min(100, p.PercentOfStage.Value));
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
                if (_shuttingDown || _updating || _startingTor) return;
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
                // Table walk off-UI (grows with socket counts); rows update back on UI context.
                var traffic = await System.Threading.Tasks.Task.Run(
                    () => AppTrafficMonitor.Snapshot(_engine.SocksPort, _engine.BridgePort));
                foreach (var row in _appRows)
                {
                    traffic.TryGetValue(row.Pid, out var stats);
                    var (label, kind, detail) = AppTrafficMonitor.Verdict(stats);
                    row.SetHealth(label, kind, detail);
                }
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

        void BuildMainAppRows()
        {
            // One-time population, same off-UI rule (first paint wins over rows).
            _ = System.Threading.Tasks.Task.Run(() =>
            {
                List<RunningAppInfo> list;
                try { list = RunningAppEnumerator.GetNonSystemUserApps(); }
                catch { return; }
                SafeBeginInvoke(() =>
                {
                    try
                    {
                        _appRows.Clear();
                        foreach (var a in list)
                            _appRows.Add(new MonitoredApp(a.Pid, a.Name, a.ExePath));
                    }
                    catch { }
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

        void WarnNewlyDirect()
        {
            try
            {
                if (!_engine.RoutingActive) return;
                var offenders = _streakTracker.Update(CollectDirectFlags(), threshold: 3);
                if (offenders.Count == 0) return;
                var byPid = new Dictionary<int, string>();
                foreach (var row in _appRows) byPid[row.Pid] = row.Name;
                var names = new List<string>();
                foreach (var pid in offenders)
                    names.Add(byPid.TryGetValue(pid, out var n) ? $"{n} (PID {pid})" : $"PID {pid}");
                AppendStatusLine("WARNING: " + string.Join(", ", names) +
                    " talking DIRECT (bypassing Tor) for 3s+ — check its own proxy settings / QUIC (see Config). Tor-only lockdown prevents this class entirely.");
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
            _trayIcon.ToggleRoutingRequested += () => SafeBeginInvoke(() => _ = ToggleRoutingFromTrayAsync());
            _trayIcon.ExitRequested += () => SafeBeginInvoke(() => ExitApplication());
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
            if (_startingTor) return;
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
            Activate();
            _trayIcon.Hide();
        }

        void MainWindow_StateChanged(object sender, EventArgs e)
        {
            if (_shuttingDown) return;
            if (WindowState == WindowState.Minimized)
            {
                Hide();
                _trayIcon.Show();
            }
        }

        void MainWindow_Closing(object sender, CancelEventArgs e)
        {
            // During shutdown teardown must proceed: never cancel/hide here.
            if (_reallyClose || _shuttingDown) return;
            e.Cancel = true;
            Hide();
            _trayIcon.Show();
        }

        async System.Threading.Tasks.Task ExitApplication()
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
            ExitTrace.Log("exit begin (tray)");
            try
            {
                // The window is usually still hidden in the tray when Exit comes
                // from the tray menu: bring it forward FIRST so the confirm
                // dialog below and the shutdown progress are actually visible.
                // (A modal dialog owned by a hidden window looks exactly like a
                // freeze: the app waits for an answer the user cannot see.)
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
                    var (proceed, affected) = await ConfirmStopRoutingAsync("Quit PTor");
                    ExitTrace.Log("exit confirm proceed=" + proceed + " affected=" + affected);
                    if (!proceed)
                    {
                        _shuttingDown = false;
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
                    if (affected > 0)
                        AppendStatusLine($"Quitting — remember to restart the {affected} listed app(s).");
                }

                AppendStatusLine("Shutting down Tor...");
                SetBusy(true, "Shutting down…");
                try { _appMonitorTimer?.Stop(); } catch { }
                var sw = Stopwatch.StartNew();
                try
                {
                    // Never let a wedged stop hang the exit: bound the wait, then
                    // continue to teardown regardless (StopAsync's verification
                    // pass already best-effort repaired proxy/env/DNS).
                    await System.Threading.Tasks.Task.Run(() => _engine.StopAsync())
                        .WaitAsync(TimeSpan.FromSeconds(25));
                    ExitTrace.Log("exit engine stop done in " + sw.ElapsedMilliseconds + "ms");
                }
                catch (Exception ex)
                {
                    ExitTrace.Log("exit engine stop issue after " + sw.ElapsedMilliseconds + "ms: " + ex.GetType().Name);
                    AppendStatusLine("Shutdown stop issue (continuing to exit): " + ex.GetType().Name);
                }
            }
            catch (Exception ex)
            {
                // Any unexpected failure above must STILL tear down below: a
                // latched _shuttingDown on a live app was the un-exitable state.
                ExitTrace.Log("exit UNEXPECTED, forcing teardown: " + ex.GetType().Name + " " + ex.Message);
            }
            finally
            {
                ExitTrace.Log("exit teardown begin");
                _reallyClose = true;
                ArmExitFailsafe("tray exit");
                try { _trayIcon.Dispose(); ExitTrace.Log("exit tray disposed"); }
                catch (Exception ex) { ExitTrace.Log("exit tray dispose: " + ex.GetType().Name); }
                try { _client.Dispose(); }
                catch (Exception ex) { ExitTrace.Log("exit client dispose: " + ex.GetType().Name); }
                try { Close(); ExitTrace.Log("exit Close returned"); }
                catch (Exception ex) { ExitTrace.Log("exit Close threw: " + ex.GetType().Name); }
                try { Application.Current.Shutdown(); ExitTrace.Log("exit Shutdown returned"); }
                catch (Exception ex) { ExitTrace.Log("exit Shutdown threw: " + ex.GetType().Name); }
            }
        }

        // Last resort, armed once teardown starts: if anything below hangs
        // (Close/Shutdown included), the process force-exits at 90s instead
        // of sticking forever. Normal exits finish in seconds, so this can
        // only fire when truly stuck. Background pool thread: evaporates with
        // a clean exit, never delays one.
        static void ArmExitFailsafe(string why)
        {
            try
            {
                _ = System.Threading.Tasks.Task.Run(async () =>
                {
                    try
                    {
                        await System.Threading.Tasks.Task.Delay(TimeSpan.FromSeconds(90));
                        try { ExitTrace.Log("FAILSAFE fired 90s after " + why + " — forcing process exit."); } catch { }
                        try { Environment.Exit(42); } catch { }
                    }
                    catch { }
                });
            }
            catch { }
        }
    }

    public class ToggleSwitch : Border
    {
        readonly Border _knob;
        readonly Brush _onBrush;
        readonly Brush _offBrush = new SolidColorBrush(Color.FromRgb(0x55, 0x55, 0x55));
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
            Width = 42;
            Height = 22;
            CornerRadius = new CornerRadius(11);
            Cursor = System.Windows.Input.Cursors.Hand;
            Background = _offBrush;

            _knob = new Border
            {
                Width = 18,
                Height = 18,
                CornerRadius = new CornerRadius(9),
                Background = Brushes.White,
                HorizontalAlignment = HorizontalAlignment.Left,
                Margin = new Thickness(2, 0, 0, 0)
            };
            Child = _knob;

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
            _knob.HorizontalAlignment = _isOn ? HorizontalAlignment.Right : HorizontalAlignment.Left;
            _knob.Margin = _isOn ? new Thickness(0, 0, 2, 0) : new Thickness(2, 0, 0, 0);
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
