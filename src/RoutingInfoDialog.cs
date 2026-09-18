using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;

namespace PTor
{

    public class RoutingInfoDialog : Window
    {
        readonly TorEngine _engine;
        readonly ObservableCollection<string> _blockedDomains;
        readonly AppSettings _settings;
        readonly Func<string, string?> _applyUserAgent;
        readonly Action<string> _status;
        TextBlock _proxyStatus;
        TextBlock _linkStatus;
        TextBlock _verifyResult;
        ListBox _domainListBox;
        TextBox _domainInput;
        TextBox _userAgentInput;
        TextBlock _enforceStatus;
        TextBlock _dnsStatus;
        TextBlock _browserStatus;
        TextBox _torLogBox;
        bool _browserBusy;
        ComboBox _bridgeModeBox = null!;
        TextBox _bridgeLinesView = null!;
        TextBlock _bridgeStatus = null!;
        Button _bridgeFetchBtn = null!;
        bool _bridgeFetching;
        bool _bridgeUiReady;
        CheckBox _stableToggle = null!;
        CheckBox _geoToggle = null!;
        ComboBox _geoRegionBox = null!;
         TextBox _geoCustomInput = null!;
         TextBlock _pathStatus = null!;
         TextBox _circuitDirtinessInput = null!;
         TextBox _streamTimeoutInput = null!;
         CheckBox _restrictiveFirewallToggle = null!;
        CheckBox _pinToggle = null!;
        TextBox _pinEntryInput = null!;
        TextBox _pinMiddleInput = null!;
        TextBox _pinExitInput = null!;
        TextBlock _pinStatus = null!;
        Button _pinCurrentBtn = null!;
        bool _pinFilling;
        CheckBox _enforceToggle = null!;
        bool _enforceBusy;
        CheckBox _startupToggle = null!;
        TextBlock _startupStatus = null!;
        bool _startupBusy;
        CheckBox _blockJsToggle = null!;
        CheckBox _blockWebRtcToggle = null!;
        CheckBox _blockCookiesToggle = null!;
        CheckBox _mitmToggle = null!;
        TextBlock _contentPolicyStatus = null!;
        TextBlock _mitmStatus = null!;
        bool _contentPolicyBusy;
        readonly Func<Task>? _requestRestartAsAdmin;

        // Shared frozen brushes: assigned, never mutated — frozen once for
        // cheaper rendering and safe cross-thread reads. textBrush aliases
        // the framework-frozen Brushes.WhiteSmoke.
        static readonly SolidColorBrush BgBrush = new(Color.FromRgb(0x20, 0x20, 0x20));
        static readonly SolidColorBrush PanelBrushStatic = new(Color.FromRgb(0x2B, 0x2B, 0x2B));
        static readonly SolidColorBrush DimBrushStatic = new(Color.FromRgb(0xA0, 0xA0, 0xA0));
        static readonly SolidColorBrush AccentBrushStatic = new(Color.FromRgb(0x60, 0xCD, 0xFF));
        static readonly SolidColorBrush GoodBrushStatic = new(Color.FromRgb(0x4C, 0xD9, 0x64));
        static readonly SolidColorBrush BorderBrushStatic = new(Color.FromRgb(0x45, 0x45, 0x45));
        static readonly Geometry ComboArrowGeometry = Geometry.Parse("M 0 0 L 4 4 L 8 0 Z");

        static RoutingInfoDialog()
        {
            try
            {
                BgBrush.Freeze(); PanelBrushStatic.Freeze(); DimBrushStatic.Freeze();
                AccentBrushStatic.Freeze(); GoodBrushStatic.Freeze(); BorderBrushStatic.Freeze();
                if (ComboArrowGeometry.CanFreeze) ComboArrowGeometry.Freeze();
            }
            catch { }
        }

        public RoutingInfoDialog(TorEngine engine, ObservableCollection<string> blockedDomains,
            AppSettings settings, string initialUserAgent, Func<string, string?> applyUserAgent,
            Action<string> statusCallback, Func<Task>? requestRestartAsAdmin = null)
        {
            _engine = engine;
            _blockedDomains = blockedDomains;
            _settings = settings;
            _applyUserAgent = applyUserAgent;
            _status = statusCallback;
            _requestRestartAsAdmin = requestRestartAsAdmin;

            Title = "Config — routing, blocking & identity";
            Width = 920;
            Height = 620;
            MinWidth = 720;
            MinHeight = 480;
            Background = BgBrush;
            FontFamily = new FontFamily("Segoe UI Variable, Segoe UI");
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            var panelBrush = PanelBrushStatic;
            var textBrush = Brushes.WhiteSmoke;
            var dimBrush = DimBrushStatic;
            var accentBrush = AccentBrushStatic;
            var goodBrush = GoodBrushStatic;

            var root = new DockPanel { Margin = new Thickness(16) };

            var scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            scroll.Content = root;
            Content = scroll;

            var stateLine = new TextBlock
            {
                Foreground = _engine.RoutingActive ? goodBrush : dimBrush,
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8),
                Text = _engine.RoutingActive
                    ? "● Routing ACTIVE — proxy-aware apps of this Windows user go through Tor automatically."
                    : "○ Routing OFF — turn on \"Route via Tor\" to reroute this user's apps."
            };
            DockPanel.SetDock(stateLine, Dock.Top);
            root.Children.Add(stateLine);

            _linkStatus = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            };
            DockPanel.SetDock(_linkStatus, Dock.Top);
            root.Children.Add(_linkStatus);

            var hint = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 10),
                Text = "No firewall, no drivers, no per-app setup. PTor routes this user through TWO channels: " +
                       "the system proxy (browsers, .NET…) and inherited env vars (Go, Python, curl, Java, and " +
                       "Node CLIs that read HTTP_PROXY/HTTPS_PROXY themselves). Electron apps are NOT covered by " +
                       "env vars — Chromium only reads env-var proxies on Linux, never on Windows. An Electron " +
                       "app's own network calls (fetch/webview) follow the system-proxy channel instead, IF it's " +
                       "relaunched after routing turns on and doesn't set its own proxy — some apps override this " +
                       "themselves and can't be forced. Services, other Windows users, UDP/raw traffic, DNS outside " +
                       "the proxy, and apps with their own proxy settings are NOT routed (proxy, not VPN). " +
                       "App already running? Fully quit it — and the terminal/launcher that spawns it — and relaunch " +
                       "AFTER routing is on. Firefox must be on Settings → Network → “Use system proxy settings”. " +
                       "And the reverse: after routing STOPS, restart apps you ran while it was on — " +
                       "a running process keeps its Tor env until restarted and otherwise stays offline. " +
                       "If some sites seem to bypass Tor while the rest works: disable QUIC/HTTP3 in the browser " +
                       "(Chrome/Edge: chrome://flags → Experimental QUIC protocol → Disabled; Firefox: about:config → " +
                       "network.http.http3.enabled = false) — QUIC runs over UDP, and neither any proxy nor Tor carries UDP."
            };
            DockPanel.SetDock(hint, Dock.Top);
            root.Children.Add(hint);

            var epPanel = new StackPanel { Margin = new Thickness(0, 0, 0, 10) };
            DockPanel.SetDock(epPanel, Dock.Top);
            root.Children.Add(epPanel);
            epPanel.Children.Add(EndpointRow("SOCKS5:", _engine.SocksEndpoint, textBrush, accentBrush));
            epPanel.Children.Add(EndpointRow("HTTP proxy:", _engine.HttpEndpoint, textBrush, accentBrush));

            var verifyRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 0) };
            epPanel.Children.Add(verifyRow);
            var verifyBtn = SafetyBtn("Verify exit IP…", panelBrush, textBrush);
            verifyBtn.Click += async (_, __) => await VerifyExitIpAsync();
            verifyRow.Children.Add(verifyBtn);
            _verifyResult = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(10, 0, 0, 0),
                Text = "Not checked yet."
            };
            verifyRow.Children.Add(_verifyResult);

            var spoofRow = new DockPanel { Margin = new Thickness(0, 8, 0, 0) };
            epPanel.Children.Add(spoofRow);
            var spoofLabel = new TextBlock
            {
                Text = "Header Spoof",
                Foreground = DimBrushStatic,
                Width = 140,
                VerticalAlignment = VerticalAlignment.Center
            };
            DockPanel.SetDock(spoofLabel, Dock.Left);
            spoofRow.Children.Add(spoofLabel);
            var spoofInput = new TextBox
            {
                Text = _engine.HeaderSpoof,
                Background = BgBrush,
                Foreground = textBrush,
                BorderBrush = BorderBrushStatic,
                Padding = new Thickness(8, 5, 8, 5),
                VerticalContentAlignment = VerticalAlignment.Center
            };
            spoofInput.LostFocus += (_, __) => ApplyHeaderSpoof(spoofInput.Text);
            spoofInput.KeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) ApplyHeaderSpoof(spoofInput.Text); };
            spoofRow.Children.Add(spoofInput);
            epPanel.Children.Add(new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 0),
                Text = "Rewrites Host: on relayed plain-HTTP requests (e.g. connect to AA, serve BB). Spoofed relays show as “→ Tor (Host: …)” in the Request Log."
            });

            var safetyBox = new Border
            {
                Background = panelBrush,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 10)
            };
            DockPanel.SetDock(safetyBox, Dock.Top);
            root.Children.Add(safetyBox);

            var safety = new StackPanel();
            safetyBox.Child = safety;
            safety.Children.Add(new TextBlock
            {
                Text = "Safety net",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 6)
            });

            _proxyStatus = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            };
            safety.Children.Add(_proxyStatus);

            // No in-app proxy-restore button by design: if PTor itself can't
            // run (or you don't trust its state), proxy recovery belongs to
            // rescue-internet.bat next to PTor.exe (run as admin) — see README.
            safety.Children.Add(new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 8, 0, 0),
                Text = "PTor never changes firewall rules. Child processes are covered automatically: proxy settings are per-user, " +
                       "so any child spawned by your apps inherits the same routing."
            });

            _enforceStatus = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 10, 0, 0)
            };
            var enforceRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 10, 0, 0) };
            _enforceToggle = new CheckBox
            {
                Content = "Tor-only lockdown (packet layer)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                VerticalContentAlignment = VerticalAlignment.Center,
                IsChecked = _engine.EnforcementActive,
                ToolTip = "Only Tor's own traffic and loopback leave this PC. Apps ignoring the proxy fail instead of leaking. Needs admin + active routing. Remembered across restarts."
            };
            _enforceToggle.Checked += async (_, __) => await EnforceToggledAsync(true);
            _enforceToggle.Unchecked += async (_, __) => await EnforceToggledAsync(false);
            enforceRow.Children.Add(_enforceToggle);
            safety.Children.Add(enforceRow);
            safety.Children.Add(new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 0),
                Text = "Only Tor's own traffic and loopback leave this PC — apps ignoring the proxy fail " +
                       "instead of leaking. Needs administrator rights and active routing. This choice is " +
                       "remembered and re-applied on start when possible."
            });
            safety.Children.Add(_enforceStatus);
            _dnsStatus = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            };
            safety.Children.Add(_dnsStatus);
            var rollbackBtn = SafetyBtn("Rollback checkpoint…", panelBrush, textBrush);
            rollbackBtn.Margin = new Thickness(0, 8, 0, 0);
            rollbackBtn.Click += async (_, __) =>
            {
                var confirm = MessageBox.Show(this,
                    "Roll back to pre-PTor networking?\n\nStops enforcement, removes the driver service PTor created " +
                    "(never anyone else's), restores your proxy + env.",
                    "Rollback checkpoint", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (confirm != MessageBoxResult.Yes) return;
                try
                {
                    _status(await _engine.RollbackCheckpointAsync());
                    // Forget the lockdown preference too: next start must not re-engage a rolled-back lockdown.
                    try { _settings.EnforceTorOnly = false; _settings.Save(); } catch { }
                    RefreshAll();
                }
                catch (Exception ex) { _status("Rollback failed: " + ex.Message); }
            };
            var rollbackRow = new StackPanel { Orientation = Orientation.Horizontal };
            rollbackRow.Children.Add(rollbackBtn);
            safety.Children.Add(rollbackRow);
            var repairBtn = SafetyBtn("Repair broken networking…", panelBrush, textBrush);
            repairBtn.Margin = new Thickness(0, 8, 0, 0);
            repairBtn.Click += async (_, __) =>
            {
                try
                {
                    foreach (var line in await _engine.RepairNetworkAsync())
                        _status(line);
                    RefreshAll();
                }
                catch (Exception ex) { _status("Repair failed: " + ex.Message); }
            };
            var repairRow = new StackPanel { Orientation = Orientation.Horizontal };
            repairRow.Children.Add(repairBtn);
            safety.Children.Add(repairRow);
            safety.Children.Add(new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 0),
                Text = "No internet after a crash, a Task Manager kill, or even a reboot? Proxy, env vars and DNS live in the registry, " +
                       "so they survive all of that until something puts them back — Repair is that something: it restores your original " +
                       "proxy, env vars and DNS resolvers, flushes the DNS cache so no stale entries dangle, and clears stale checkpoints. " +
                       "Refuses while lockdown is on (turn it off first). DNS restore needs admin. " +
                       "If PTor won't start at all, run rescue-internet.bat (next to PTor.exe, as admin) — the same repair without the app. See README."
            });

            var startupBox = new Border
            {
                Background = panelBrush,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 10)
            };
            DockPanel.SetDock(startupBox, Dock.Top);
            root.Children.Add(startupBox);

            var startup = new StackPanel();
            startupBox.Child = startup;
            startup.Children.Add(new TextBlock
            {
                Text = "Windows startup",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 6)
            });
            _startupToggle = new CheckBox
            {
                Content = "Start PTor on Windows logon (minimized to tray)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                VerticalContentAlignment = VerticalAlignment.Center,
                IsChecked = _settings.StartOnStartup,
                ToolTip = "Adds a per-user logon entry (no admin needed). Off by default."
            };
            _startupToggle.Checked += (_, __) => SaveStartupSettingsFromUi();
            _startupToggle.Unchecked += (_, __) => SaveStartupSettingsFromUi();
            startup.Children.Add(_startupToggle);
            _startupStatus = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            };
            startup.Children.Add(_startupStatus);
            startup.Children.Add(new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 0),
                Text = "Per-user logon entry (HKCU Run, no admin needed) launching this install minimized to the tray. " +
                       "Off by default. The entry is repointed automatically after updates (each release lives in its own folder). " +
                       "Uninstall.exe and clear-startup.bat remove it."
            });

            var bridgeBox = new Border
            {
                Background = panelBrush,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 10)
            };
            DockPanel.SetDock(bridgeBox, Dock.Top);
            root.Children.Add(bridgeBox);

            var bridge = new StackPanel();
            bridgeBox.Child = bridge;
            bridge.Children.Add(new TextBlock
            {
                Text = "Censorship circumvention (bridges)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 6)
            });
            _bridgeModeBox = new ComboBox
            {
                Background = BgBrush,
                Foreground = textBrush,
                BorderBrush = BorderBrushStatic,
                Padding = new Thickness(8, 5, 8, 5),
                Margin = new Thickness(0, 0, 0, 8)
            };
            // Stock ComboBox chrome ignores Background (white box, white popup:
            // the active mode renders white-on-white). Full dark template.
            StyleDarkComboBox(_bridgeModeBox,
                BgBrush, textBrush,
                BorderBrushStatic, accentBrush);
            _bridgeModeBox.Items.Add("Direct (no bridges)");
            _bridgeModeBox.Items.Add("obfs4 — automatic");
            _bridgeModeBox.Items.Add("Snowflake — automatic");
            _bridgeModeBox.Items.Add("Automatic (all tiers)");
            _bridgeModeBox.Items.Add("WebTunnel — automatic");
            _bridgeModeBox.SelectedIndex = BridgeIndexFromMode(_settings.BridgeMode);
            bridge.Children.Add(_bridgeModeBox);
            // Fully automatic: there is deliberately NO manual bridge input.
            // Fresh lines are fetched from Tor's directory at every start
            // (last-good lines cached, bundled file last), and the Fetch
            // button below refreshes the cache on demand. This box is
            // read-only proof of what will be used — never an input.
            _bridgeLinesView = new TextBox
            {
                Background = BgBrush,
                Foreground = textBrush,
                BorderBrush = BorderBrushStatic,
                Padding = new Thickness(8, 5, 8, 5),
                AcceptsReturn = true,
                TextWrapping = TextWrapping.Wrap,
                Height = 90,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                IsReadOnly = true,
                IsReadOnlyCaretVisible = true,
                ToolTip = "Read-only: the automatically fetched bridge lines that will be tried first at the next start (or why there are none yet)."
            };
            bridge.Children.Add(_bridgeLinesView);
            RefreshBridgeLinesView();
            // Fully automatic supply: Tor's public bridge directory
            // (bridges.torproject.org, no account, no captcha — rate-limited
            // per network). Fetching happens at every start by itself; this
            // button just refreshes the on-disk cache right now. Label
            // switches per mode (see RefreshBridgeFetchBtn).
            _bridgeFetchBtn = SafetyBtn("Fetch bridges from Tor", panelBrush, textBrush);
            _bridgeFetchBtn.Margin = new Thickness(0, 6, 0, 0);
            _bridgeFetchBtn.HorizontalAlignment = HorizontalAlignment.Left;
            _bridgeFetchBtn.Click += (_, __) => _ = FetchBridgesForModeAsync();
            bridge.Children.Add(_bridgeFetchBtn);
            RefreshBridgeFetchBtn();
            _bridgeModeBox.SelectionChanged += (_, __) =>
            {
                if (!_bridgeUiReady) return;
                SaveBridgeSettingsFromUi();
            };
            _bridgeUiReady = true;
            _bridgeStatus = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            };
            bridge.Children.Add(_bridgeStatus);
            bridge.Children.Add(new TextBlock
            {
                Text = "Use where Tor entry guards are blocked or fingerprinted. Every mode here is fully automatic: fresh bridges are fetched from Tor's directory at each start — last-good lines cached on disk, bundled file only as the last resort. " +
                       "Snowflake needs working system DNS plus direct UDP from its helper (no VPN kill-switch blocking it); without those it fails fast instead of stalling. " +
                       "WebTunnel bridges are scarce per network — when the directory has none for you it says so and the start falls back automatically. " +
                       "Takes effect on next Tor start; a bad config refuses to start rather than falling back to direct.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            });

            var domBox = new Border
            {
                Background = panelBrush,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 10)
            };
            DockPanel.SetDock(domBox, Dock.Top);
            root.Children.Add(domBox);

            BuildPathSection(root, panelBrush, textBrush, dimBrush);

            var dom = new StackPanel();
            domBox.Child = dom;
            dom.Children.Add(new TextBlock
            {
                Text = "Blocked Domains",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 6)
            });

            var domAddRow = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
            dom.Children.Add(domAddRow);
            var domAddBtn = SafetyBtn("Add", panelBrush, textBrush);
            DockPanel.SetDock(domAddBtn, Dock.Right);
            domAddBtn.Margin = new Thickness(8, 0, 0, 0);
            domAddBtn.Click += (_, __) => AddBlockedDomain();
            domAddRow.Children.Add(domAddBtn);
            _domainInput = DialogTextBox("example.com", textBrush);
            _domainInput.KeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) AddBlockedDomain(); };
            domAddRow.Children.Add(_domainInput);

            _domainListBox = new ListBox
            {
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Foreground = textBrush,
                Height = 110,
                SelectionMode = SelectionMode.Extended,
                ItemsSource = _blockedDomains,
                ContextMenu = DeleteMenu(RemoveSelectedDomains)
            };
            _domainListBox.KeyDown += (_, e) =>
            {
                if (e.Key == System.Windows.Input.Key.Delete) { RemoveSelectedDomains(); e.Handled = true; }
            };
            _domainListBox.MouseDoubleClick += (_, __) => RemoveSelectedDomains();
            dom.Children.Add(_domainListBox);
            dom.Children.Add(new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                Margin = new Thickness(0, 6, 0, 0),
                Text = "Enforced everywhere, instantly: HTTP proxy, SOCKS (incl. TLS SNI), inspected HTTPS, and Tor-DNS (answered NXDOMAIN locally, never leaked). " +
                       "Entries cover subdomains (example.com blocks a.example.com). Ctrl/Shift+click selects multiple. Delete key, right-click → Delete, or double-click removes."
            });

            BuildContentPolicySection(root, panelBrush, textBrush, dimBrush);

            var uaBox = new Border
            {
                Background = panelBrush,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 10)
            };
            DockPanel.SetDock(uaBox, Dock.Top);
            root.Children.Add(uaBox);

            var ua = new StackPanel();
            uaBox.Child = ua;
            ua.Children.Add(new TextBlock
            {
                Text = "Custom User-Agent",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 6)
            });
            _userAgentInput = DialogTextBox(initialUserAgent ?? "", textBrush);
            _userAgentInput.LostFocus += (_, __) => SaveUserAgentFromUi();
            _userAgentInput.KeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) SaveUserAgentFromUi(); };
            ua.Children.Add(_userAgentInput);
            var uaPresetRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
            ua.Children.Add(uaPresetRow);
            foreach (var (label, value) in UserAgentPresets)
            {
                var btn = SafetyBtn(label, panelBrush, textBrush);
                btn.Margin = new Thickness(0, 0, 8, 0);
                btn.Click += (_, __) =>
                {
                    _userAgentInput.Text = value;
                    SaveUserAgentFromUi();
                };
                uaPresetRow.Children.Add(btn);
            }
            ua.Children.Add(new TextBlock
            {
                Text = "Presets or paste your own; empty = system default (no injection). Applies to PTor's own test requests only — relayed app traffic is never modified. For mobile web in your browser, use its device emulation instead.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            });

            var browserBox = new Border
            {
                Background = panelBrush,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 10)
            };
            DockPanel.SetDock(browserBox, Dock.Top);
            root.Children.Add(browserBox);

            var browserStack = new StackPanel();
            browserBox.Child = browserStack;
            browserStack.Children.Add(new TextBlock
            {
                Text = "Browser checklist (Secure DNS)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 6)
            });
            _browserStatus = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap
            };
            browserStack.Children.Add(_browserStatus);
            browserStack.Children.Add(new TextBlock
            {
                Text = "Read-only: Secure DNS (DoH) bypasses Tor DNS, and breaks page loads under Tor-only lockdown. " +
                       "If a browser fails while others work, turn its Secure DNS off (Firefox: Settings → Privacy → DNS over HTTPS → Off; " +
                       "Edge/Chrome: Settings → Privacy → Security → Use secure DNS → Off or automatic with fallback).",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            });

            var torLogBox = new Border
            {
                Background = panelBrush,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 10)
            };
            DockPanel.SetDock(torLogBox, Dock.Top);
            root.Children.Add(torLogBox);

            var torLogStack = new StackPanel();
            torLogBox.Child = torLogStack;
            torLogStack.Children.Add(new TextBlock
            {
                Text = "Tor log (recent lines — says WHY tor won't connect)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 6)
            });
            _torLogBox = new TextBox
            {
                Background = BgBrush,
                Foreground = textBrush,
                BorderBrush = BorderBrushStatic,
                BorderThickness = new Thickness(1),
                FontFamily = new FontFamily("Consolas, Cascadia Mono"),
                FontSize = 11,
                Height = 130,
                AcceptsReturn = true,
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto
            };
            torLogStack.Children.Add(_torLogBox);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
            DockPanel.SetDock(btnRow, Dock.Top);
            root.Children.Add(btnRow);

            var refreshBtn = new Button
            {
                Content = "Refresh",
                Background = panelBrush,
                Foreground = textBrush,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(14, 6, 14, 6),
                Cursor = System.Windows.Input.Cursors.Hand
            };
            refreshBtn.Click += (_, __) => RefreshAll();
            btnRow.Children.Add(refreshBtn);
            btnRow.Children.Add(new TextBlock
            {
                Text = "Refreshes proxy/link status. Per-app traffic lives in the main window's Apps tab.",
                Foreground = dimBrush,
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(12, 0, 0, 0)
            });

            RefreshProxyStatus();
            RefreshLinkStatus();
            RefreshEnforcementStatus();
            RefreshDnsStatus();
            RefreshBridgeStatus();
            RefreshPathStatus();
            RefreshContentPolicyStatus();
            RefreshStartupStatus();
            RefreshTorLog();
            _ = RefreshBrowserStatusAsync();
        }

        static (string Label, string Value)[] UserAgentPresets => new[]
        {
            ("System default", ""),
            ("Desktop Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
            ("Android Chrome", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"),
            ("iPhone Safari", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"),
        };

        static Button SafetyBtn(string text, Brush bg, Brush fg) => new Button
        {
            Content = text,
            Background = bg,
            Foreground = fg,
            BorderThickness = new Thickness(1),
            BorderBrush = BorderBrushStatic,
            Padding = new Thickness(12, 6, 12, 6),
            Cursor = System.Windows.Input.Cursors.Hand
        };

        // Dark ComboBox chrome: dark box + dark popup, light text, accent
        // highlight. Selection behavior (SelectedIndex/SelectedItem, keyboard,
        // drop-down open/close) is untouched — only the visuals.
        static void StyleDarkComboBox(ComboBox box, Brush bg, Brush fg, Brush border, Brush accent)
        {
            var toggleTemplate = new ControlTemplate(typeof(ToggleButton));
            var toggleBorder = new FrameworkElementFactory(typeof(Border));
            toggleBorder.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(ToggleButton.BackgroundProperty));
            toggleBorder.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(ToggleButton.BorderBrushProperty));
            toggleBorder.SetValue(Border.BorderThicknessProperty, new TemplateBindingExtension(ToggleButton.BorderThicknessProperty));
            var arrow = new FrameworkElementFactory(typeof(System.Windows.Shapes.Path));
            arrow.SetValue(System.Windows.Shapes.Path.DataProperty, ComboArrowGeometry);
            arrow.SetValue(System.Windows.Shapes.Path.FillProperty, fg);
            arrow.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Right);
            arrow.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
            arrow.SetValue(FrameworkElement.MarginProperty, new Thickness(0, 0, 10, 0));
            toggleBorder.AppendChild(arrow);
            toggleTemplate.VisualTree = toggleBorder;

            var template = new ControlTemplate(typeof(ComboBox));
            var grid = new FrameworkElementFactory(typeof(Grid));
            var toggle = new FrameworkElementFactory(typeof(ToggleButton));
            toggle.SetValue(ToggleButton.TemplateProperty, toggleTemplate);
            toggle.SetValue(ToggleButton.BackgroundProperty, bg);
            toggle.SetValue(ToggleButton.BorderBrushProperty, border);
            toggle.SetValue(ToggleButton.BorderThicknessProperty, new Thickness(1));
            toggle.SetValue(ToggleButton.FocusableProperty, false);
            toggle.SetValue(ToggleButton.ClickModeProperty, ClickMode.Press);
            toggle.SetBinding(ToggleButton.IsCheckedProperty, new Binding("IsDropDownOpen")
            {
                RelativeSource = new RelativeSource(RelativeSourceMode.TemplatedParent),
                Mode = BindingMode.TwoWay
            });
            var content = new FrameworkElementFactory(typeof(ContentPresenter));
            content.SetValue(ContentPresenter.MarginProperty, new Thickness(8, 5, 26, 5));
            content.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            content.SetValue(ContentPresenter.IsHitTestVisibleProperty, false);
            content.SetValue(ContentPresenter.ContentProperty,
                new TemplateBindingExtension(ComboBox.SelectionBoxItemProperty));
            var popup = new FrameworkElementFactory(typeof(Popup));
            popup.SetValue(Popup.PlacementProperty, PlacementMode.Bottom);
            popup.SetValue(Popup.AllowsTransparencyProperty, true);
            popup.SetValue(Popup.FocusableProperty, false);
            popup.SetValue(Popup.PopupAnimationProperty, PopupAnimation.Slide);
            popup.SetValue(Popup.StaysOpenProperty, false);
            popup.SetValue(Popup.IsOpenProperty,
                new TemplateBindingExtension(ComboBox.IsDropDownOpenProperty));
            var popupBorder = new FrameworkElementFactory(typeof(Border));
            popupBorder.SetValue(Border.BackgroundProperty, bg);
            popupBorder.SetValue(Border.BorderBrushProperty, border);
            popupBorder.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            popupBorder.SetValue(Border.MinWidthProperty,
                new TemplateBindingExtension(ComboBox.ActualWidthProperty));
            popupBorder.SetValue(Border.MaxHeightProperty,
                new TemplateBindingExtension(ComboBox.MaxDropDownHeightProperty));
            var scroll = new FrameworkElementFactory(typeof(ScrollViewer));
            scroll.AppendChild(new FrameworkElementFactory(typeof(ItemsPresenter)));
            popupBorder.AppendChild(scroll);
            popup.AppendChild(popupBorder);
            grid.AppendChild(toggle);
            grid.AppendChild(content);
            grid.AppendChild(popup);
            template.VisualTree = grid;
            box.Template = template;

            var itemStyle = new Style(typeof(ComboBoxItem));
            itemStyle.Setters.Add(new Setter(Control.BackgroundProperty, bg));
            itemStyle.Setters.Add(new Setter(Control.ForegroundProperty, fg));
            itemStyle.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(8, 4, 8, 4)));
            var highlighted = new Trigger { Property = ComboBoxItem.IsHighlightedProperty, Value = true };
            highlighted.Setters.Add(new Setter(Control.BackgroundProperty, accent));
            highlighted.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.Black));
            itemStyle.Triggers.Add(highlighted);
            var selected = new Trigger { Property = ComboBoxItem.IsSelectedProperty, Value = true };
            selected.Setters.Add(new Setter(Control.BackgroundProperty, accent));
            selected.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.Black));
            itemStyle.Triggers.Add(selected);
            box.ItemContainerStyle = itemStyle;
        }

        async System.Threading.Tasks.Task VerifyExitIpAsync()
        {
            _verifyResult.Text = "Checking via system proxy…";
            try
            {

                using var http = new System.Net.Http.HttpClient
                {
                    Timeout = TimeSpan.FromSeconds(15)
                };
                var json = await http.GetStringAsync("https://check.torproject.org/api/ip");
                string ip = "?", isTor = "?";
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("IP", out var ipEl))
                        ip = ipEl.GetString() ?? "?";
                    if (doc.RootElement.TryGetProperty("IsTor", out var torEl))
                        isTor = torEl.GetBoolean() ? "TRUE" : "FALSE";
                }
                catch { ip = json.Trim(); }
                var msg = $"Exit IP {ip} — IsTor={isTor} (via system proxy).";
                _verifyResult.Text = msg;
                _status(msg + (isTor == "TRUE"
                    ? " Rewiring works."
                    : " NOT via Tor — is routing on, and was the app (re)started after?"));
            }
            catch (Exception ex)
            {
                var msg = "Check failed: " + ex.GetType().Name +
                    " — is routing on? (If on, the app may still hold pre-PTor settings: fully quit and relaunch it.)";
                _verifyResult.Text = msg;
                _status(msg);
            }
        }

        void ApplyHeaderSpoof(string text)
        {
            try
            {
                var v = (text ?? "").Trim();
                _engine.HeaderSpoof = v;
                _settings.HeaderSpoof = v;
                _settings.Save();
                _status(string.IsNullOrEmpty(v)
                    ? "Header spoof off — relayed requests keep their original Host."
                    : $"Header spoof ON — relayed plain-HTTP requests will carry Host: {v} (TCP still goes to the URL's host).");
            }
            catch (Exception ex)
            {
                _status("Header spoof failed: " + ex.Message);
            }
        }

        void SaveStartupSettingsFromUi()
        {
            if (_startupBusy) return;
            _startupBusy = true;
            try
            {
                _settings.StartOnStartup = _startupToggle.IsChecked == true;
                _settings.Save();
                string? note = null;
                try { note = StartupManager.Sync(_settings.StartOnStartup); } catch { }
                if (!string.IsNullOrEmpty(note)) _status(note);
                else _status(_settings.StartOnStartup
                    ? "Start on startup ON — takes effect on next logon."
                    : "Start on startup OFF — logon entry removed.");
            }
            catch (Exception ex) { _status("Startup settings save failed: " + ex.Message); }
            finally
            {
                try { RefreshStartupStatus(); } catch { }
                _startupBusy = false;
            }
        }

        void RefreshStartupStatus()
        {
            try
            {
                // Checkbox shows the saved preference; the line below shows
                // the live registry truth (they can diverge if something
                // external edited the Run key — re-saving repoints it).
                try { _startupToggle.IsChecked = _settings.StartOnStartup; } catch { }
                _startupStatus.Text = StartupManager.StatusLine();
            }
            catch { try { _startupStatus.Text = "Startup: unknown."; } catch { } }
        }

        void RefreshAll()
        {
            RefreshProxyStatus();
            RefreshLinkStatus();
            RefreshEnforcementStatus();
            RefreshDnsStatus();
            RefreshBridgeStatus();
            RefreshPathStatus();
            RefreshContentPolicyStatus();
            RefreshStartupStatus();
            RefreshTorLog();
            _ = RefreshBrowserStatusAsync();
            if (!_enforceBusy)
            {
                _enforceBusy = true;
                try { SyncEnforceToggle(); } catch { }
                _enforceBusy = false;
            }
        }

        void RefreshEnforcementStatus()
        {
            try
            {
                _enforceStatus.Text = _engine.EnforcementStatus;
                if (_settings.EnforceTorOnly && !_engine.EnforcementActive)
                    _enforceStatus.Text += " · preferred ON (applies once routing is active and PTor runs as admin).";
            }
            catch { _enforceStatus.Text = "Enforcement: unknown."; }
        }

        // Combo ↔ BridgeMode mapping (explicit: Custom has no UI row —
        // manual bridge input is gone, everything is automatic). Legacy
        // Custom installs map to Automatic for display; their saved lines
        // are preserved untouched and keep feeding Automatic's private tier.
        static internal BridgeMode BridgeModeFromIndex(int i) => i switch
        {
            0 => BridgeMode.Direct,
            1 => BridgeMode.Obfs4Default,
            2 => BridgeMode.SnowflakeDefault,
            3 => BridgeMode.Auto,
            4 => BridgeMode.WebTunnel,
            _ => BridgeMode.Direct,
        };

        static internal int BridgeIndexFromMode(BridgeMode m) => m switch
        {
            BridgeMode.Direct => 0,
            BridgeMode.Obfs4Default => 1,
            BridgeMode.SnowflakeDefault => 2,
            BridgeMode.Auto => 3,
            BridgeMode.WebTunnel => 4,
            _ => 3,
        };

        void SaveBridgeSettingsFromUi()
        {
            try
            {
                var mode = BridgeModeFromIndex(_bridgeModeBox.SelectedIndex);
                _settings.BridgeMode = mode;
                // NOTE: CustomBridgeLines are deliberately never touched
                // here (no input exists): legacy lines stay saved and keep
                // feeding Automatic's private tier.
                _settings.Save();
                try { RefreshBridgeFetchBtn(); } catch { }
                try { RefreshBridgeLinesView(); } catch { }
                _status(mode == BridgeMode.Direct
                    ? "Bridge mode: direct guards (change takes effect on next Tor start)."
                    : $"Bridge mode: {mode} saved — bridges fetch automatically, takes effect on next Tor start.");
            }
            catch (Exception ex) { _status("Bridge settings save failed: " + ex.Message); }
            RefreshBridgeStatus();
        }

        // Read-only proof of what the next start will try first: cached
        // auto lines for the selected mode, or why there are none yet.
        // Never throws.
        void RefreshBridgeLinesView()
        {
            try
            {
                var mode = BridgeModeFromIndex(_bridgeModeBox.SelectedIndex);
                string want = mode == BridgeMode.WebTunnel ? "webtunnel"
                    : mode == BridgeMode.Obfs4Default ? "obfs4"
                    : mode == BridgeMode.SnowflakeDefault ? "snowflake" : "";
                if (string.IsNullOrEmpty(want))
                {
                    var legacy = 0;
                    try { legacy = _settings.CustomBridgeLines?.Count ?? 0; } catch { }
                    _bridgeLinesView.Text = mode == BridgeMode.Direct
                        ? "(direct guards — no bridges.)"
                        : "(Automatic fetches per tier at start: live directory → on-disk cache → bundled file." +
                          (legacy > 0 ? $" {legacy} legacy custom line(s) still saved and feeding its private tier.)" : ")");
                    return;
                }
                AutoBridgeCache.CachedBridges? cached = null;
                try { cached = AutoBridgeCache.Load(); } catch { }
                if (cached != null && string.Equals(cached.Transport, want, StringComparison.OrdinalIgnoreCase)
                    && cached.Lines.Count > 0)
                {
                    var age = AutoBridgeCache.DescribeAge(cached, DateTime.UtcNow);
                    var fresh = AutoBridgeCache.IsFresh(cached, DateTime.UtcNow);
                    _bridgeLinesView.Text =
                        $"(read-only — {cached.Lines.Count} {want} line(s), {age}" +
                        (fresh ? ", tried first at next start)" : " — STALE, a fresh fetch runs at next start)") +
                        Environment.NewLine + string.Join(Environment.NewLine, cached.Lines);
                    return;
                }
                _bridgeLinesView.Text = $"(no {want} lines cached yet — they are fetched automatically at start " +
                    "(bundled file as fallback), or press Fetch now.)";
            }
            catch { try { _bridgeLinesView.Text = "(bridge lines unavailable.)"; } catch { } }
        }

        // Fetch-button label/visibility per bridge mode. obfs4 refreshes
        // from the directory, Snowflake from Tor's published builtin config
        // (the directory does not distribute Snowflake per network),
        // WebTunnel from the directory. Results land in the on-disk auto
        // cache — the mode never changes. Never throws.
        void RefreshBridgeFetchBtn()
        {
            try
            {
                var mode = BridgeModeFromIndex(_bridgeModeBox.SelectedIndex);
                if (mode == BridgeMode.WebTunnel)
                {
                    _bridgeFetchBtn.Content = "Fetch WebTunnel bridges now";
                    _bridgeFetchBtn.ToolTip = "Pull fresh WebTunnel lines from Tor's public bridge directory into the automatic cache (used first at the next start). Uses the system connection (via Tor when routing is on).";
                    _bridgeFetchBtn.Visibility = Visibility.Visible;
                }
                else if (mode == BridgeMode.Obfs4Default)
                {
                    _bridgeFetchBtn.Content = "Fetch fresh obfs4 bridges now";
                    _bridgeFetchBtn.ToolTip = "Pull fresh obfs4 lines from Tor's public bridge directory into the automatic cache (used first at the next start, ahead of the bundled file).";
                    _bridgeFetchBtn.Visibility = Visibility.Visible;
                }
                else if (mode == BridgeMode.SnowflakeDefault)
                {
                    _bridgeFetchBtn.Content = "Refresh Snowflake config now";
                    _bridgeFetchBtn.ToolTip = "Snowflake needs no per-user bridges (one static rendezvous config for everyone). This pulls Tor's published canonical config into the automatic cache.";
                    _bridgeFetchBtn.Visibility = Visibility.Visible;
                }
                else
                {
                    _bridgeFetchBtn.Visibility = Visibility.Collapsed;
                }
            }
            catch { }
        }

        // Fetches into the automatic on-disk cache (never a textbox — none
        // exists). Only a success changes anything; failures keep the
        // previous cache. Network stays off the UI thread. Never throws.
        async System.Threading.Tasks.Task FetchBridgesForModeAsync()
        {
            if (_bridgeFetching) return;
            _bridgeFetching = true;
            try { _bridgeFetchBtn.IsEnabled = false; } catch { }
            try
            {
                var mode = BridgeModeFromIndex(_bridgeModeBox.SelectedIndex);
                string transport;
                string noun;
                if (mode == BridgeMode.Obfs4Default) { transport = "obfs4"; noun = "obfs4 bridges"; }
                else if (mode == BridgeMode.SnowflakeDefault) { transport = "snowflake"; noun = "Snowflake config"; }
                else if (mode == BridgeMode.WebTunnel) { transport = "webtunnel"; noun = "WebTunnel bridges"; }
                else { _status("Fetch is available in the WebTunnel / obfs4 / Snowflake modes."); return; }
                _status($"Fetching fresh {noun} from Tor's directory (bridges.torproject.org)…");
                BridgeFetchResult result;
                try
                {
                    using var client = BridgeFetcher.CreateClient();
                    result = transport == "snowflake"
                        ? await BridgeFetcher.FetchBuiltinSnowflakeAsync(client)
                        : await BridgeFetcher.FetchTransportAsync(client, transport);
                }
                catch (Exception ex)
                {
                    _status($"Fetch failed ({ex.GetType().Name}) — retry later or switch mode.");
                    return;
                }
                if (result.Lines.Count == 0)
                {
                    _status("Fetch: " + (result.Error ?? "no bridges returned."));
                    return;
                }
                try { AutoBridgeCache.Save(transport, result.Lines); } catch { }
                try { RefreshBridgeLinesView(); } catch { }
                _status($"Fetched {result.Lines.Count} live {noun} from Tor's directory — cached, tried first at next Tor start.");
            }
            catch (Exception ex) { _status("Fetch failed: " + ex.Message); }
            finally
            {
                _bridgeFetching = false;
                try { _bridgeFetchBtn.IsEnabled = true; } catch { }
                try { RefreshBridgeStatus(); } catch { }
            }
        }

        void BuildPathSection(DockPanel root, Brush panelBrush, Brush textBrush, Brush dimBrush)
        {
            var box = new Border
            {
                Background = panelBrush,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 10)
            };
            DockPanel.SetDock(box, Dock.Top);
            root.Children.Add(box);

            var p = new StackPanel();
            box.Child = p;
            p.Children.Add(new TextBlock
            {
                Text = "Entry/exit path (stable IP + geography)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 6)
            });

            _stableToggle = new CheckBox
            {
                Content = "Stable connection (keep one exit IP)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                VerticalContentAlignment = VerticalAlignment.Center,
                IsChecked = _settings.StableExitEnabled,
            };
            _stableToggle.Checked += (_, __) => SavePathSettingsFromUi();
            _stableToggle.Unchecked += (_, __) => SavePathSettingsFromUi();
            p.Children.Add(_stableToggle);
            p.Children.Add(new TextBlock
            {
                Text = "Circuits stay alive up to 24h and scheduled rotation pauses, so logins and captchas stop breaking on IP hops. " +
                       "Manual rotation still works. Tradeoff: longer linkability window, and a dead link takes longer to recover (restarts still happen, just later). " +
                        "Takes effect on next Tor start. No exit is ever guaranteed single — Tor may still open a second circuit under load.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 10)
            });

            var dirtRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 0) };
            p.Children.Add(dirtRow);
            dirtRow.Children.Add(new TextBlock
            {
                Text = "Circuit lifetime (seconds):",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0)
            });
            _circuitDirtinessInput = DialogTextBox(_settings.CircuitDirtinessSec.ToString(), textBrush);
            _circuitDirtinessInput.Width = 80;
            _circuitDirtinessInput.LostFocus += (_, __) => SavePathSettingsFromUi();
            _circuitDirtinessInput.KeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) SavePathSettingsFromUi(); };
            dirtRow.Children.Add(_circuitDirtinessInput);
            p.Children.Add(new TextBlock
            {
                Text = "How long Tor reuses a circuit before building a fresh one (torrc MaxCircuitDirtiness). " +
                        "600 = Tor default (10 min). Lower = fresher exits but more building (slower, chattier); " +
                        "higher = longer linkability window. Allowed 60–86400; anything else resets to 600. " +
                        "Stable-connection mode above pins this to 24h while it is on. Takes effect on next Tor start.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 10)
            });

            var streamRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 0) };
            p.Children.Add(streamRow);
            streamRow.Children.Add(new TextBlock
            {
                Text = "Stream retry timeout (seconds):",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0)
            });
            _streamTimeoutInput = DialogTextBox(_settings.CircuitStreamTimeoutSec.ToString(), textBrush);
            _streamTimeoutInput.Width = 80;
            _streamTimeoutInput.LostFocus += (_, __) => SavePathSettingsFromUi();
            _streamTimeoutInput.KeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) SavePathSettingsFromUi(); };
            streamRow.Children.Add(_streamTimeoutInput);
            p.Children.Add(new TextBlock
            {
                Text = "How long until Tor detaches a stream from a sluggish circuit and tries a new one " +
                        "(torrc CircuitStreamTimeout). 0 = Tor's internal schedule (default). On slow networks a " +
                        "higher value (e.g. 60) rides out stalls instead of re-trying; lower fails fast. " +
                        "Allowed 0–600; anything else resets to 0. Takes effect on next Tor start.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 10)
            });

            _restrictiveFirewallToggle = new CheckBox
            {
                Content = "Restrictive firewall (guard links only on ports 80/443)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                IsChecked = _settings.RestrictiveFirewallOnly,
            };
            _restrictiveFirewallToggle.Checked += (_, __) => SavePathSettingsFromUi();
            _restrictiveFirewallToggle.Unchecked += (_, __) => SavePathSettingsFromUi();
            p.Children.Add(_restrictiveFirewallToggle);
            p.Children.Add(new TextBlock
            {
                Text = "For networks that filter outbound ports: Tor then only connects to guards on 80/443 " +
                        "(torrc FascistFirewall). Turn this on if bootstraps die in TLS handshakes on a network " +
                        "you don't control (hotel, office, campus). Off = all guard ports allowed. " +
                        "Takes effect on next Tor start.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 10)
            });

            _geoToggle = new CheckBox
            {
                Content = "Prefer exits in a region (faster path)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                VerticalContentAlignment = VerticalAlignment.Center,
                IsChecked = _settings.ExitGeoEnabled,
            };
            _geoToggle.Checked += (_, __) => SavePathSettingsFromUi();
            _geoToggle.Unchecked += (_, __) => SavePathSettingsFromUi();
            p.Children.Add(_geoToggle);
            _geoRegionBox = new ComboBox
            {
                Background = BgBrush,
                Foreground = textBrush,
                BorderBrush = BorderBrushStatic,
                Padding = new Thickness(8, 5, 8, 5),
                Margin = new Thickness(0, 6, 0, 0)
            };
            StyleDarkComboBox(_geoRegionBox,
                BgBrush, textBrush,
                BorderBrushStatic,
                AccentBrushStatic);
            var regions = new System.Collections.Generic.List<string>(TorPathOptions.ExitRegions.Keys);
            regions.Sort(StringComparer.Ordinal);
            foreach (var r in regions) _geoRegionBox.Items.Add(r);
            _geoRegionBox.SelectedItem = regions.Contains(_settings.ExitRegion ?? "")
                ? _settings.ExitRegion
                : regions[0];
            _geoRegionBox.SelectionChanged += (_, __) => SavePathSettingsFromUi();
            p.Children.Add(_geoRegionBox);
            _geoCustomInput = DialogTextBox(_settings.ExitCustomCountries ?? "", textBrush);
            _geoCustomInput.LostFocus += (_, __) => SavePathSettingsFromUi();
            _geoCustomInput.KeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) SavePathSettingsFromUi(); };
            p.Children.Add(_geoCustomInput);
            p.Children.Add(new TextBlock
            {
                Text = "Optional custom country codes (us, de, jp — comma separated, overrides the region). OFF by default; when no preferred exit is available Tor falls back to any country. Smaller exit pool = weaker anonymity — use for speed/locale, not for hiding. Entry guards are deliberately untouched (churning them harms anonymity). Takes effect on next Tor start.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 10)
            });

            _pinToggle = new CheckBox
            {
                Content = "Pin circuit to specific relays (stop IP hops)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                VerticalContentAlignment = VerticalAlignment.Center,
                IsChecked = _settings.PinnedCircuitEnabled,
                ToolTip = "Pins Entry/Middle/Exit to your relays (StrictNodes 1, huge circuit lifetime). Overrides stable, lifetime, geography, and rotation."
            };
            _pinToggle.Checked += (_, __) => SavePathSettingsFromUi();
            _pinToggle.Unchecked += (_, __) => SavePathSettingsFromUi();
            p.Children.Add(_pinToggle);
            p.Children.Add(new TextBlock
            {
                Text = "OFF by default. When ON, Tor only ever uses YOUR listed relays (torrc EntryNodes / MiddleNodes / ExitNodes + " +
                       "StrictNodes 1 + MaxCircuitDirtiness 999999999 + EnforceDistinctSubnets 0). " +
                       "A FIXED exit IP needs an EXIT pin of exactly ONE relay fingerprint: with no exit pinned Tor still picks " +
                       "fresh exits whenever a circuit is rebuilt (IP keeps hopping — entry/middle pins alone never stop exit hops), " +
                       "and with several exits Tor spreads circuits across all of them (IP hops inside your set). " +
                       "OVERRIDES while on: stable-connection mode, circuit lifetime, exit geography, and scheduled + manual rotation " +
                       "(all saved but ignored until pin is off). Takes effect on next Tor start. " +
                       "Warning: a tiny relay set is more linkable, and if a pinned relay dies the IP must change — " +
                       "auto-recovery below then re-pins to a live relay and says so. " +
                       "While bridges are in use the entry pin is dropped (tor refuses it next to bridges — the bridge is your entry); " +
                       "middle/exit pins still apply.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 6)
            });
            var pinBtnRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 2) };
            _pinCurrentBtn = SafetyBtn("Use current circuit", panelBrush, textBrush);
            _pinCurrentBtn.ToolTip = "Fill the boxes from your live Tor circuit (needs routing ON). Most reliable: relays you are already connected to.";
            _pinCurrentBtn.Click += (_, __) => _ = FillPinFromCurrentCircuitAsync();
            pinBtnRow.Children.Add(_pinCurrentBtn);
            p.Children.Add(pinBtnRow);
            var pinMetricsLink = new TextBlock
            {
                Foreground = AccentBrushStatic,
                FontSize = 11,
                Text = "Or pick relays by hand at metrics.torproject.org/rs.html → relay details → fingerprint (click to open)",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 2),
                Cursor = System.Windows.Input.Cursors.Hand
            };
            pinMetricsLink.MouseLeftButtonUp += (_, __) =>
            {
                try { using var proc = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://metrics.torproject.org/rs.html") { UseShellExecute = true }); }
                catch (Exception ex) { _status("Could not open browser: " + ex.Message); }
            };
            p.Children.Add(pinMetricsLink);
            p.Children.Add(new TextBlock
            {
                Text = "Entry nodes (fingerprints or nicknames, comma separated):",
                Foreground = textBrush,
                FontSize = 11,
                Margin = new Thickness(0, 4, 0, 2)
            });
            _pinEntryInput = DialogTextBox(_settings.PinnedEntryNodes ?? "", textBrush);
            _pinEntryInput.ToolTip = "e.g. $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, MyGuard1";
            _pinEntryInput.LostFocus += (_, __) => SavePathSettingsFromUi();
            _pinEntryInput.KeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) SavePathSettingsFromUi(); };
            p.Children.Add(_pinEntryInput);
            p.Children.Add(new TextBlock
            {
                Text = "Middle nodes (fingerprints or nicknames, comma separated — empty = any middle):",
                Foreground = textBrush,
                FontSize = 11,
                Margin = new Thickness(0, 6, 0, 2)
            });
            _pinMiddleInput = DialogTextBox(_settings.PinnedMiddleNodes ?? "", textBrush);
            _pinMiddleInput.ToolTip = "Empty means any middle relay (entry + exit still pinned).";
            _pinMiddleInput.LostFocus += (_, __) => SavePathSettingsFromUi();
            _pinMiddleInput.KeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) SavePathSettingsFromUi(); };
            p.Children.Add(_pinMiddleInput);
            p.Children.Add(new TextBlock
            {
                Text = "Exit nodes (fingerprints or nicknames, comma separated):",
                Foreground = textBrush,
                FontSize = 11,
                Margin = new Thickness(0, 6, 0, 2)
            });
            _pinExitInput = DialogTextBox(_settings.PinnedExitNodes ?? "", textBrush);
            _pinExitInput.ToolTip = "e.g. $BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB, MyExit1";
            _pinExitInput.LostFocus += (_, __) => SavePathSettingsFromUi();
            _pinExitInput.KeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) SavePathSettingsFromUi(); };
            p.Children.Add(_pinExitInput);
            // No auto-recover toggle: recovery is part of pinning itself. If
            // a pinned relay dies, PTor probes once without the pin; if that
            // connects it re-pins to the live circuit automatically, and if
            // the whole network is down the pin is kept untouched.
            p.Children.Add(new TextBlock
            {
                Text = "Built-in safety: if a pinned relay dies, PTor restarts once without the pin; if that connects it re-pins to the live circuit automatically. " +
                       "If the unpinned try also fails (whole network down) your pin is kept.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 0)
            });
            _pinStatus = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 10)
            };
            p.Children.Add(_pinStatus);
            _pathStatus = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            };
            p.Children.Add(_pathStatus);
            RefreshPathStatus();
        }

        async System.Threading.Tasks.Task FillPinFromCurrentCircuitAsync()
        {
            if (_pinFilling) return;
            _pinFilling = true;
            try { _pinCurrentBtn.IsEnabled = false; } catch { }
            try
            {
                try { _pinStatus.Text = "Reading live circuit…"; } catch { }
                // A GENERAL circuit builds lazily right after bootstrap: a
                // single immediate read often catches only a 1-hop directory
                // circuit (or nothing yet) and would fill just the entry box.
                // Retry for the full 3-hop data path, keeping the best read.
                string? entry = null, middle = null, exit = null;
                for (var i = 0; i < 4; i++)
                {
                    try { (entry, middle, exit) = await _engine.GetLiveCircuitNodesAsync(); } catch { }
                    if (!string.IsNullOrWhiteSpace(entry) && !string.IsNullOrWhiteSpace(middle) && !string.IsNullOrWhiteSpace(exit))
                        break;
                    if (i < 3)
                    {
                        try { _pinStatus.Text = $"Reading live circuit… (attempt {i + 1}/4 — waiting for the full path)"; } catch { }
                        try { await System.Threading.Tasks.Task.Delay(TimeSpan.FromSeconds(3)); } catch { break; }
                    }
                }
                if (entry == null && middle == null && exit == null)
                {
                    var msg = "No live circuit yet — start routing and wait for bootstrap 100%, then retry.";
                    _status(msg);
                    try { _pinStatus.Text = msg; } catch { }
                    return;
                }
                // While bridged the live "entry" hop is the bridge itself and
                // Tor ignores EntryNodes anyway: keep the user's saved entry
                // pick instead of persisting a bridge fingerprint that would
                // fail when bridges go off (same rule as pin auto-recovery).
                // Middle/exit pins still apply, so they are always filled.
                bool bridgesInUse = false;
                try { bridgesInUse = _engine.ActiveBridgeLines.Count > 0; } catch { }
                if (bridgesInUse) entry = null;
                ApplyPinFill(entry, middle, exit, "live circuit");
                if (bridgesInUse)
                {
                    _status("Circuit pin filled from live circuit (middle + exit — entry kept as saved: Tor ignores it while bridged) — takes effect on next Tor start.");
                    try { _pinStatus.Text = "Filled middle + exit from the live circuit (entry kept as saved — Tor ignores it while bridged). Takes effect on next Tor start."; } catch { }
                }
            }
            catch (Exception ex) { _status("Could not read live circuit: " + ex.Message); }
            finally
            {
                try { _pinCurrentBtn.IsEnabled = true; } catch { }
                _pinFilling = false;
            }
        }

        void ApplyPinFill(string? entry, string? middle, string? exits, string source)
        {
            try
            {
                // Only overwrite positions we actually got: a 2-hop live
                // circuit has no middle (empty = any middle stays valid).
                if (!string.IsNullOrWhiteSpace(entry)) _pinEntryInput.Text = entry.Trim();
                if (!string.IsNullOrWhiteSpace(middle)) _pinMiddleInput.Text = middle.Trim();
                if (!string.IsNullOrWhiteSpace(exits)) _pinExitInput.Text = exits.Trim();
                SavePathSettingsFromUi();
                _status($"Circuit pin filled from {source} — takes effect on next Tor start.");
            }
            catch (Exception ex) { _status("Pin fill failed: " + ex.Message); }
        }

        void SavePathSettingsFromUi()
        {
            try
            {
                _settings.StableExitEnabled = _stableToggle.IsChecked == true;
                _settings.RestrictiveFirewallOnly = _restrictiveFirewallToggle.IsChecked == true;
                _settings.ExitGeoEnabled = _geoToggle.IsChecked == true;                _settings.ExitRegion = _geoRegionBox.SelectedItem as string ?? "";
                _settings.ExitCustomCountries = _geoCustomInput.Text ?? "";
                _settings.PinnedCircuitEnabled = _pinToggle.IsChecked == true;
                _settings.PinnedEntryNodes = _pinEntryInput.Text ?? "";
                _settings.PinnedMiddleNodes = _pinMiddleInput.Text ?? "";
                _settings.PinnedExitNodes = _pinExitInput.Text ?? "";
                try
                {
                    var raw = (_circuitDirtinessInput.Text ?? "").Trim();
                    if (int.TryParse(raw, out var secs) && secs >= 60 && secs <= 86400)
                        _settings.CircuitDirtinessSec = secs;
                    else
                        _circuitDirtinessInput.Text = _settings.CircuitDirtinessSec.ToString();
                }
                catch { try { _circuitDirtinessInput.Text = _settings.CircuitDirtinessSec.ToString(); } catch { } }
                try
                {
                    var raw = (_streamTimeoutInput.Text ?? "").Trim();
                    if (int.TryParse(raw, out var secs) && secs >= 0 && secs <= 600)
                        _settings.CircuitStreamTimeoutSec = secs;
                    else
                        _streamTimeoutInput.Text = _settings.CircuitStreamTimeoutSec.ToString();
                }
                catch { try { _streamTimeoutInput.Text = _settings.CircuitStreamTimeoutSec.ToString(); } catch { } }
                _settings.Save();
                var pinOn = TorProcessManager.IsPinActiveRaw(
                    _settings.PinnedCircuitEnabled,
                    _settings.PinnedEntryNodes, _settings.PinnedMiddleNodes, _settings.PinnedExitNodes);
                _status(pinOn
                    ? "Circuit pin saved and will OVERRIDE stable / lifetime / geography / rotation on next Tor start."
                    : "Entry/exit path saved — takes effect on next Tor start.");
            }
            catch (Exception ex) { _status("Path settings save failed: " + ex.Message); }
            RefreshPathStatus();
        }

        void BuildContentPolicySection(DockPanel root, Brush panelBrush, Brush textBrush, Brush dimBrush)
        {
            var box = new Border
            {
                Background = panelBrush,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 10)
            };
            DockPanel.SetDock(box, Dock.Top);
            root.Children.Add(box);

            var s = new StackPanel();
            box.Child = s;
            s.Children.Add(new TextBlock
            {
                Text = "Content blocking — HTTPS inspection + BlockJS / WebRTC / cookies",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 6)
            });
            _mitmToggle = new CheckBox
            {
                Content = "Inspect HTTPS (decrypt → filter → re-encrypt via Tor)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                VerticalContentAlignment = VerticalAlignment.Center,
                IsChecked = _settings.MitmEnabled,
                ToolTip = "Terminates CONNECT TLS with per-host certs from PTor's local CA, applies the filters below to decrypted HTTPS, then re-encrypts to the real origin through Tor (origin certificates still validated fail-closed)."
            };
            _mitmToggle.Checked += async (_, __) => await MitmToggledAsync(true);
            _mitmToggle.Unchecked += async (_, __) => await MitmToggledAsync(false);
            s.Children.Add(_mitmToggle);
            s.Children.Add(new TextBlock
            {
                Text = "Without this, HTTPS is opaque: only the host/port gate applies and scripts/cookies inside " +
                       "TLS keep working. With this ON, the same BlockJS / WebRTC / cookie filters run on decrypted " +
                       "HTTPS in both HTTP/2 and HTTP/1.1 natively (each leg keeps its own best protocol). " +
                       "Needs the local CA trusted below (one Windows prompt). Applies instantly, no Tor restart.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 10)
            });
            _mitmStatus = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 6)
            };
            s.Children.Add(_mitmStatus);
            var caRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
            s.Children.Add(caRow);
            var installBtn = SafetyBtn("Install CA…", panelBrush, textBrush);
            installBtn.Margin = new Thickness(0, 0, 8, 0);
            installBtn.Click += async (_, __) => await CaButtonAsync("install", installBtn);
            caRow.Children.Add(installBtn);
            var removeBtn = SafetyBtn("Remove CA", panelBrush, textBrush);
            removeBtn.Margin = new Thickness(0, 0, 8, 0);
            removeBtn.Click += async (_, __) => await CaButtonAsync("remove", removeBtn);
            caRow.Children.Add(removeBtn);
            var regenBtn = SafetyBtn("Regenerate CA…", panelBrush, textBrush);
            regenBtn.Click += async (_, __) => await CaButtonAsync("regen", regenBtn);
            caRow.Children.Add(regenBtn);
            s.Children.Add(new TextBlock
            {
                Text = "The CA is free and per-install (self-signed on this PC — no purchases, no Let's Encrypt). " +
                       "Private key stays in %AppData%\\PTor\\mitm and is never installed anywhere. " +
                       "Install auto-trusts Chrome/Edge/system apps (plus LocalMachine when elevated, so all Windows users are covered) " +
                       "and auto-configures Firefox/Thunderbird profiles (security.enterprise_roots via user.js — restart the browser). " +
                       "Your Blocked Domains list is enforced on every channel, including SOCKS and inspected HTTPS.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 10)
            });
            _blockJsToggle = new CheckBox
            {
                Content = "BlockJS — block JavaScript",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                VerticalContentAlignment = VerticalAlignment.Center,
                IsChecked = _settings.BlockJs,
                ToolTip = "Blocks .js/.mjs/.cjs requests + JS MIME responses and injects CSP script-src 'none' on HTML. Covers HTTPS too while inspection is on."
            };
            _blockJsToggle.Checked += (_, __) => SaveContentPolicyFromUi();
            _blockJsToggle.Unchecked += (_, __) => SaveContentPolicyFromUi();
            s.Children.Add(_blockJsToggle);
            s.Children.Add(new TextBlock
            {
                Text = ".js file requests get 403, JS MIME responses get 403, HTML gains " +
                       "Content-Security-Policy: script-src 'none'. Plain-HTTP always; HTTPS too while inspection is ON.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 10)
            });
            _blockWebRtcToggle = new CheckBox
            {
                Content = "WebRTC — block STUN/TURN + signaling",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                VerticalContentAlignment = VerticalAlignment.Center,
                IsChecked = _settings.BlockWebRtc,
                ToolTip = "Refuses STUN/TURN TCP relay and blocks SDP signaling responses. Turning this on also engages Tor-only lockdown when possible, so WebRTC UDP is dropped at the packet layer."
            };
            _blockWebRtcToggle.Checked += (_, __) => SaveContentPolicyFromUi();
            _blockWebRtcToggle.Unchecked += (_, __) => SaveContentPolicyFromUi();
            s.Children.Add(_blockWebRtcToggle);
            s.Children.Add(new TextBlock
            {
                Text = "Refuses TURN/STUN-over-TCP at both proxies (CONNECT + SOCKS to stun.*/turn.* hosts and ports " +
                       "3478/5349/19302-19309/8801-8802) and blocks SDP signaling responses (plain-HTTP always, HTTPS " +
                       "while inspecting). WebRTC UDP bypasses any proxy — Tor carries no UDP — so switching this on " +
                       "auto-engages Tor-only lockdown when possible (admin + routing live); the status line confirms " +
                       "whether UDP is actually covered.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 10)
            });
            _blockCookiesToggle = new CheckBox
            {
                Content = "Block cookies (breaks logins)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                VerticalContentAlignment = VerticalAlignment.Center,
                IsChecked = _settings.BlockCookies,
                ToolTip = "Strips Cookie request headers and Set-Cookie response headers. Expect to be logged out everywhere while on."
            };
            _blockCookiesToggle.Checked += (_, __) => SaveContentPolicyFromUi();
            _blockCookiesToggle.Unchecked += (_, __) => SaveContentPolicyFromUi();
            s.Children.Add(_blockCookiesToggle);
            s.Children.Add(new TextBlock
            {
                Text = "Strips Cookie: on requests and Set-Cookie on responses (plain-HTTP always, HTTPS while inspecting). " +
                       "This logs you out everywhere and breaks sessions that require cookies — that breakage IS the protection.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 6)
            });
            _contentPolicyStatus = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            };
            s.Children.Add(_contentPolicyStatus);
            RefreshContentPolicyStatus();
        }

        void SaveContentPolicyFromUi()
        {
            if (_contentPolicyBusy) return;
            try
            {
                var rtcTurningOn = _blockWebRtcToggle.IsChecked == true && !_settings.BlockWebRtc;
                _settings.BlockJs = _blockJsToggle.IsChecked == true;
                _settings.BlockWebRtc = _blockWebRtcToggle.IsChecked == true;
                _settings.BlockCookies = _blockCookiesToggle.IsChecked == true;
                _settings.Save();
                try { _engine.BlockJs = _settings.BlockJs; } catch { }
                try { _engine.BlockWebRtc = _settings.BlockWebRtc; } catch { }
                try { _engine.BlockCookies = _settings.BlockCookies; } catch { }
                _status("Content filters saved (instant): "
                    + (_settings.BlockJs ? "BlockJS ON" : "BlockJS off")
                    + " · " + (_settings.BlockWebRtc ? "WebRTC block ON" : "WebRTC block off")
                    + " · " + (_settings.BlockCookies ? "Cookie block ON" : "Cookie block off")
                    + ". HTTPS coverage needs inspection ON + trusted CA.");
                // Automagic UDP cover: proxies can't touch WebRTC's UDP, so
                // enabling the block also engages packet-layer lockdown when
                // possible (the status line says what actually happened).
                if (rtcTurningOn)
                    _ = EnsureWebRtcCoverageAsync();
            }
            catch (Exception ex) { _status("Content policy save failed: " + ex.Message); }
            RefreshContentPolicyStatus();
        }

        async Task EnsureWebRtcCoverageAsync()
        {
            try { _status(await Task.Run(() => _engine.EnsureWebRtcCoverageAsync())); }
            catch (Exception ex) { _status("WebRTC UDP cover failed: " + ex.Message); }
            finally { try { RefreshContentPolicyStatus(); } catch { } }
        }

        async Task MitmToggledAsync(bool on)
        {
            if (_contentPolicyBusy) return;
            _contentPolicyBusy = true;
            try { _mitmToggle.IsEnabled = false; } catch { }
            try
            {
                if (!on)
                {
                    _settings.MitmEnabled = false;
                    _settings.Save();
                    try { _engine.MitmEnabled = false; } catch { }
                    _status("HTTPS inspection OFF — CONNECT tunnels are opaque again (host/port gate only). The CA stays installed for next time.");
                    return;
                }
                var proceed = MessageBox.Show(this,
                    "Inspect HTTPS traffic?\n\nPTor will decrypt browser HTTPS with its local CA, apply your " +
                    "BlockJS / WebRTC / cookie filters inside, then re-encrypt to the real site through Tor. " +
                    "Origin certificates are still validated (invalid origins fail closed, revocation checked via Tor). " +
                    "HTTP/2 and HTTP/1.1 are both inspected natively — each side keeps its own protocol, no downgrade.\n\n" +
                    "Next: Windows asks once to trust the local CA (free, generated on this PC).",
                    "Inspect HTTPS", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (proceed != MessageBoxResult.Yes) { SyncMitmToggle(); return; }
                string setup;
                try { setup = await Task.Run(() => _engine.EnsureMitmCa()); }
                catch (Exception ex) { _status("HTTPS inspection failed: " + ex.Message); SyncMitmToggle(); return; }
                _settings.MitmEnabled = true;
                _settings.Save();
                try { _engine.MitmEnabled = true; } catch { }
                _status("HTTPS inspection ON (" + setup + ") — now trust the CA below so browsers accept it.");
                try
                {
                    var res = MessageBox.Show(this,
                        "Trust PTor's local CA now?\n\nThis installs its PUBLIC certificate into CurrentUser\\Root " +
                        "(Windows may show one confirmation). Without this, inspected sites show certificate errors.",
                        "Trust local CA", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (res == MessageBoxResult.Yes)
                    {
                        try { _status(await Task.Run(() => _engine.InstallMitmCa())); }
                        catch (Exception ex) { _status("CA install failed: " + ex.Message); }
                    }
                }
                catch { }
            }
            finally
            {
                try { _mitmToggle.IsEnabled = true; } catch { }
                try { SyncMitmToggle(); } catch { }
                try { RefreshContentPolicyStatus(); } catch { }
                _contentPolicyBusy = false;
            }
        }

        async Task CaButtonAsync(string op, Button btn)
        {
            try { btn.IsEnabled = false; } catch { }
            try
            {
                if (op == "regen")
                {
                    var confirm = MessageBox.Show(this,
                        "Generate a brand-new local CA?\n\nThe old CA stops working immediately: reinstall trust " +
                        "afterwards, and remove the old CA from CurrentUser\\Root if it was trusted.",
                        "Regenerate CA", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                    if (confirm != MessageBoxResult.Yes) return;
                }
                string msg;
                try
                {
                    msg = op switch
                    {
                        "install" => await Task.Run(() => _engine.InstallMitmCa()),
                        "remove" => await Task.Run(() => _engine.RemoveMitmCa()),
                        _ => await Task.Run(() => _engine.RegenerateMitmCa()),
                    };
                }
                catch (Exception ex) { msg = "CA operation failed: " + ex.Message; }
                _status(msg);
                RefreshContentPolicyStatus();
            }
            finally { try { btn.IsEnabled = true; } catch { } }
        }

        void SyncMitmToggle()
        {
            try { _mitmToggle.IsChecked = _settings.MitmEnabled && _engine.MitmEnabled; } catch { }
        }

        void RefreshContentPolicyStatus()
        {
            try
            {
                if (!_contentPolicyBusy)
                {
                    try { _blockJsToggle.IsChecked = _settings.BlockJs; } catch { }
                    try { _blockWebRtcToggle.IsChecked = _settings.BlockWebRtc; } catch { }
                    try { _blockCookiesToggle.IsChecked = _settings.BlockCookies; } catch { }
                    try { _mitmToggle.IsChecked = _settings.MitmEnabled; } catch { }
                }
                _contentPolicyStatus.Text = _engine.ContentPolicyStatus;
                try { _mitmStatus.Text = _engine.MitmCaStatus; } catch { }
            }
            catch { try { _contentPolicyStatus.Text = "Content policy: unknown."; } catch { } }
        }

        void RefreshPathStatus()
        {
            try
            {
                var countries = _settings.ExitGeoEnabled
                    ? TorPathOptions.ResolveExitCountries(_settings.ExitRegion, _settings.ExitCustomCountries)
                    : new System.Collections.Generic.List<string>();
                var pinEntry = TorProcessManager.ParsePinnedNodes(_settings.PinnedEntryNodes);
                var pinMiddle = TorProcessManager.ParsePinnedNodes(_settings.PinnedMiddleNodes);
                var pinExit = TorProcessManager.ParsePinnedNodes(_settings.PinnedExitNodes);
                var pinActive = _settings.PinnedCircuitEnabled && (pinEntry.Count + pinMiddle.Count + pinExit.Count) > 0;
                // Pin status line: what is pinned, what is overridden, and
                // what is wrong (enabled-but-empty or fully-invalid input).
                try
                {
                    if (!_settings.PinnedCircuitEnabled)
                        _pinStatus.Text = "Circuit pin: OFF (default).";
                    else if (!pinActive)
                        _pinStatus.Text = "Circuit pin: ON but no valid fingerprint/nickname listed — INACTIVE next start (normal path in use). List at least one valid relay.";
                    else
                    {
                        var segs = new System.Collections.Generic.List<string>();
                        if (pinEntry.Count > 0) segs.Add("entry " + string.Join(",", pinEntry));
                        if (pinMiddle.Count > 0) segs.Add("middle " + string.Join(",", pinMiddle));
                        if (pinExit.Count > 0) segs.Add("exit " + string.Join(",", pinExit));
                        _pinStatus.Text = "Circuit pin: ON next start → " + string.Join(" · ", segs) +
                            " (StrictNodes 1, MaxCircuitDirtiness 999999999, EnforceDistinctSubnets 0). Overrides stable / lifetime / geography / rotation." +
                            " A dead pin restarts unpinned once, then re-pins to a live relay automatically.";
                        // Still-hop warnings: the pin constrains which relays
                        // Tor may use, not Tor's circuit lifecycle — say so
                        // HERE (before the start) rather than after the hop.
                        try
                        {
                            foreach (var w in TorProcessManager.PinStabilityWarnings(pinEntry, pinMiddle, pinExit))
                                _pinStatus.Text += "\nPin still hops because: " + w;
                        }
                        catch { }
                    }
                }
                catch { try { _pinStatus.Text = "Circuit pin: unknown."; } catch { } }
                // Grey out overridden controls so the override is visible,
                // not just documented. Values are still saved underneath, so
                // turning pin off restores them untouched.
                try { UpdatePinDependentUi(pinActive); } catch { }
                var parts = new System.Collections.Generic.List<string>();
                if (pinActive)
                {
                    parts.Add("CIRCUIT PIN ON (StrictNodes 1, lifetime 999999999, subnets 0)");
                    var segs = new System.Collections.Generic.List<string>();
                    if (pinEntry.Count > 0) segs.Add("entry " + string.Join(",", pinEntry));
                    if (pinMiddle.Count > 0) segs.Add("middle " + string.Join(",", pinMiddle));
                    if (pinExit.Count > 0) segs.Add("exit " + string.Join(",", pinExit));
                    parts.Add(segs.Count > 0 ? "pinned: " + string.Join(" · ", segs) : "pinned: (none valid)");
                    parts.Add("stable / lifetime / geography / rotation: OVERRIDDEN by pin");
                }
                else
                {
                    parts.Add(_settings.StableExitEnabled
                        ? "stable connection ON (24h circuits, rotation paused)"
                        : "stable connection off");
                    parts.Add(_settings.StableExitEnabled
                        ? "circuit lifetime pinned 24h by stable mode"
                        : $"circuit lifetime: {TorProcessManager.SanitizeDirtinessSec(_settings.CircuitDirtinessSec)}s");
                }
                var streamSecs = TorProcessManager.SanitizeStreamTimeoutSec(_settings.CircuitStreamTimeoutSec);
                parts.Add(streamSecs == 0
                    ? "stream retry: Tor internal schedule"
                    : $"stream retry: {streamSecs}s");
                parts.Add(_settings.RestrictiveFirewallOnly
                    ? "guard links: 80/443 only (restrictive firewall)"
                    : "guard links: all ports");
                if (!pinActive)
                    parts.Add(_settings.ExitGeoEnabled
                        ? (countries.Count > 0 ? "exit preference: " + string.Join(",", countries) + " (fallback: any)" : "geo ON but nothing valid selected")
                        : "geo off (any country)");
                _pathStatus.Text = "Effective next start: " + string.Join(" · ", parts) + ".";
            }
            catch { _pathStatus.Text = "Entry/exit path: unknown."; }
        }

        void UpdatePinDependentUi(bool pinActive)
        {
            try
            {
                // While pin is active these settings are saved but ignored
                // (engine + torrc force pin values). Disable to prevent the
                // "I set 600s but torrc says 999999999" confusion.
                try { _stableToggle.IsEnabled = !pinActive; } catch { }
                try { _circuitDirtinessInput.IsEnabled = !pinActive; } catch { }
                try { _geoToggle.IsEnabled = !pinActive; } catch { }
                try { _geoRegionBox.IsEnabled = !pinActive; } catch { }
                try { _geoCustomInput.IsEnabled = !pinActive; } catch { }
            }
            catch { }
        }

        void RefreshBridgeStatus()
        {
            try
            {
                var text = _engine.BridgeStatus;
                var mode = BridgeModeFromIndex(_bridgeModeBox.SelectedIndex);
                // Legacy custom installs (saved before manual input was
                // removed): say what happens to their lines.
                if (_settings.BridgeMode == BridgeMode.Custom)
                {
                    var legacy = 0;
                    try { legacy = _settings.CustomBridgeLines?.Count ?? 0; } catch { }
                    text += $"\nLegacy custom mode ({legacy} saved line(s)): still honored at start and feeding Automatic's private tier. Manual editing is gone — pick an automatic mode to move on.";
                }
                if (mode is BridgeMode.Obfs4Default or BridgeMode.SnowflakeDefault or BridgeMode.WebTunnel)
                {
                    var want = mode == BridgeMode.WebTunnel ? "webtunnel"
                        : mode == BridgeMode.Obfs4Default ? "obfs4" : "snowflake";
                    AutoBridgeCache.CachedBridges? cached = null;
                    try { cached = AutoBridgeCache.Load(); } catch { }
                    if (cached != null && string.Equals(cached.Transport, want, StringComparison.OrdinalIgnoreCase)
                        && cached.Lines.Count > 0)
                    {
                        var age = AutoBridgeCache.DescribeAge(cached, DateTime.UtcNow);
                        text += $"\n{cached.Lines.Count} live {want} line(s) cached ({age})" +
                            (AutoBridgeCache.IsFresh(cached, DateTime.UtcNow)
                                ? " — tried first at next start."
                                : " — STALE, a fresh fetch runs at next start.");
                    }
                    else
                    {
                        text += $"\nNo cached {want} lines — the next start fetches automatically (bundled file as fallback).";
                    }
                }
                else if (mode == BridgeMode.Auto)
                {
                    text += "\nAutomatic fetches per tier at start (live directory → cache → bundled).";
                }
                _bridgeStatus.Text = text;
            }
            catch { _bridgeStatus.Text = "Bridges: unknown."; }
        }

        void RefreshTorLog()
        {
            try
            {
                List<string> lines;
                try { lines = _engine.GetTorLogTail() ?? new List<string>(); }
                catch { lines = new List<string>(); }
                _torLogBox.Text = lines.Count == 0
                    ? ( torRunningHint() )
                    : string.Join(Environment.NewLine, lines);
                try { _torLogBox.ScrollToEnd(); } catch { }
            }
            catch { try { _torLogBox.Text = "Log unavailable."; } catch { } }

            string torRunningHint()
            {
                try { return _engine.IsTorRunning ? "(tor running, no log lines captured yet)" : "(tor not running — start routing to capture its log)"; }
                catch { return "(tor log unavailable)"; }
            }
        }

        // File reads + JSON stay off the UI thread.
        async System.Threading.Tasks.Task RefreshBrowserStatusAsync()
        {
            if (_browserBusy) return;
            _browserBusy = true;
            try
            {
                var notes = await System.Threading.Tasks.Task.Run(() => BrowserDnsCheck.Run());
                var parts = new List<string>();
                var bad = 0;
                foreach (var n in notes)
                {
                    parts.Add((n.Bad ? "✕ " : "✓ ") + n.Browser + ": " + n.Detail);
                    if (n.Bad) bad++;
                }
                _browserStatus.Text = string.Join(Environment.NewLine, parts);
                if (bad > 0)
                    _status($"Browser checklist: {bad} Secure-DNS issue(s) — see Config. Likely why some browsers fail while others work.");
            }
            catch (Exception ex)
            {
                _browserStatus.Text = "Checklist failed: " + ex.Message;
            }
            finally { _browserBusy = false; }
        }

        void RefreshDnsStatus()
        {
            try { _dnsStatus.Text = _engine.DnsStatus; }
            catch { _dnsStatus.Text = "DNS: unknown."; }
        }

        void SyncEnforceToggle() => _enforceToggle.IsChecked = _engine.EnforcementActive;

        void PersistEnforcePreference()
        {
            try
            {
                _settings.EnforceTorOnly = _engine.EnforcementActive;
                _settings.Save();
            }
            catch { }
        }

        async Task EnforceToggledAsync(bool on)
        {
            if (_enforceBusy) return;
            _enforceBusy = true;
            try { _enforceToggle.IsEnabled = false; } catch { }
            try
            {
                if (!on)
                {
                    if (!_engine.EnforcementActive) { PersistEnforcePreference(); return; }
                    var confirm = MessageBox.Show(this,
                        "Stop enforcement? Apps regain direct internet access and system DNS is restored (proxy routing continues)." +
                        (_settings.BlockWebRtc ? "\n\nNote: the WebRTC block is ON — without lockdown its UDP half (voice/video, QUIC) is NOT covered." : ""),
                        "Stop enforcement", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (confirm != MessageBoxResult.Yes) { SyncEnforceToggle(); return; }
                    // UI thread: hop to pool, the gate wait is bounded but blocking.
                    try { _status(await Task.Run(() => _engine.DisableEnforcement())); }
                    catch (Exception ex) { _status("Stop enforcement failed: " + ex.Message); }
                    PersistEnforcePreference();
                    RefreshEnforcementStatus();
                    RefreshDnsStatus();
                    try
                    {
                        if (_settings.BlockWebRtc)
                            _status("Lockdown off — WebRTC UDP is NOT covered now. It re-engages on next start while the WebRTC block is on (turn that off too to stay off).");
                        RefreshContentPolicyStatus();
                    }
                    catch { }
                    return;
                }

                // UI-thread pre-checks first: common failures shouldn't throw through Task.Run.
                if (!_engine.RoutingActive)
                {
                    MessageBox.Show(this,
                        "Start Tor + routing first — enforcement without a working Tor underneath would take the whole machine offline.",
                        "Tor not active", MessageBoxButton.OK, MessageBoxImage.Warning);
                    SyncEnforceToggle();
                    return;
                }
                if (!_engine.EnforcementAvailable)
                {
                    MessageBox.Show(this,
                        "WinDivert driver files not found (expected tools\\WinDivert\\x64 or \\x86 with WinDivert.dll + .sys).",
                        "Enforcement unavailable", MessageBoxButton.OK, MessageBoxImage.Warning);
                    SyncEnforceToggle();
                    return;
                }
                if (!AdminHelper.IsAdministrator())
                {
                    if (_requestRestartAsAdmin != null)
                    {
                        var restart = MessageBox.Show(this,
                            "Packet enforcement needs administrator rights — restart PTor as administrator.\n\nRestart PTor as administrator now? (Tor stops, then the elevated copy auto-starts.)",
                            "Administrator required", MessageBoxButton.YesNo, MessageBoxImage.Question);
                        if (restart == MessageBoxResult.Yes)
                        {
                            try { await _requestRestartAsAdmin(); }
                            catch (Exception ex) { _status("Elevation failed (UAC declined?): " + ex.Message); }
                        }
                    }
                    else
                    {
                        MessageBox.Show(this,
                            "Packet enforcement needs administrator rights — restart PTor as administrator.",
                            "Administrator required", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                    SyncEnforceToggle();
                    return;
                }

                var proceed = MessageBox.Show(this,
                    "Enforce Tor-only networking at the packet layer?\n\n" +
                    "From now on ONLY Tor's own traffic and loopback leave this PC. " +
                    "Apps that ignore the proxy will FAIL (connection errors) instead of leaking — " +
                    "point them at the proxy or accept them offline.\n\n" +
                    "System DNS is also pointed at Tor while lockdown is on (restored afterward). " +
                    "A rollback checkpoint is snapshotted first. Killing PTor, power loss, or deleted " +
                    "files all restore normal traffic instantly.",
                    "Enforce Tor-only", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (proceed != MessageBoxResult.Yes) { SyncEnforceToggle(); return; }

                try
                {
                    _status(await Task.Run(() => _engine.EnableEnforcement()));
                }
                catch (NeedAdminException ex)
                {
                    // Admin lost between pre-check and driver open.
                    _status("Enforce failed: " + ex.Message);
                    if (_requestRestartAsAdmin != null)
                    {
                        var restart = MessageBox.Show(this,
                            ex.Message + "\n\nRestart PTor as administrator now? (Tor stops, then the elevated copy auto-starts.)",
                            "Administrator required", MessageBoxButton.YesNo, MessageBoxImage.Question);
                        if (restart == MessageBoxResult.Yes)
                        {
                            try { await _requestRestartAsAdmin(); }
                            catch (Exception rex) { _status("Elevation failed (UAC declined?): " + rex.Message); }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _status("Enforce failed: " + ex.Message);
                }
                PersistEnforcePreference();
                RefreshEnforcementStatus();
                    RefreshDnsStatus();
            }
            finally
            {
                try { _enforceToggle.IsEnabled = true; } catch { }
                // Sync under busy: programmatic IsChecked also fires Checked/Unchecked.
                try { SyncEnforceToggle(); } catch { }
                _enforceBusy = false;
            }
        }

        static TextBox DialogTextBox(string text, Brush textBrush) => new TextBox
        {
            Text = text,
            Background = BgBrush,
            Foreground = textBrush,
            BorderBrush = BorderBrushStatic,
            Padding = new Thickness(8, 5, 8, 5),
            VerticalContentAlignment = VerticalAlignment.Center
        };

        static ContextMenu DeleteMenu(Action onDelete)
        {
            var ctx = new ContextMenu();
            var item = new MenuItem { Header = "Delete" };
            item.Click += (_, __) => onDelete();
            ctx.Items.Add(item);
            return ctx;
        }

        void PersistBlockedDomains()
        {
            try
            {
                _settings.BlockedDomains = _blockedDomains.ToList();
                _settings.Save();
                // Live to every layer: HTTP proxy, SOCKS, inspected HTTPS,
                // and Tor-DNS (NXDOMAIN) — no restart needed.
                try { _engine.SetBlockedDomains(_blockedDomains); } catch { }
            }
            catch { }
        }

        void AddBlockedDomain()
        {
            var d = _domainInput.Text.Trim().ToLowerInvariant();
            if (d.Length == 0) return;
            if (!_blockedDomains.Contains(d))
            {
                _blockedDomains.Add(d);
                PersistBlockedDomains();
            }
            _domainInput.Text = string.Empty;
        }

        void RemoveSelectedDomains()
        {
            var sel = _domainListBox.SelectedItems.Cast<string>().ToList();
            if (sel.Count == 0) return;
            foreach (var s in sel) _blockedDomains.Remove(s);
            PersistBlockedDomains();
            _status($"Removed {sel.Count} blocked domain(s).");
        }

        void SaveUserAgentFromUi()
        {
            var err = _applyUserAgent(_userAgentInput.Text);
            if (err != null)
            {
                _status(err);
                return;
            }
            _status(string.IsNullOrWhiteSpace(_userAgentInput.Text)
                ? "User-Agent cleared — system default will be sent."
                : "Custom User-Agent applied to PTor's own requests.");
        }

        void RefreshLinkStatus()
        {
            try { _linkStatus.Text = _engine.TorLinkStatus; }
            catch { _linkStatus.Text = "Tor link: unknown."; }
        }

        void RefreshProxyStatus()
        {
            try
            {
                var s = _engine.GetProxySnapshot();
                var proxyPart = s.ManagedByPTor
                    ? $"Proxy now: ON via PTor (enabled={s.Enabled}, server={s.Server}). Your previous settings are backed up and come back on stop."
                    : (s.Enabled == 1
                        ? $"Proxy now: ON but NOT PTor's (server={Truncate(s.Server, 90)}). PTor left it alone."
                        : "Proxy now: direct (no system proxy).");
                _proxyStatus.Text = proxyPart + "\n" + _engine.GetEnvStatus();
            }
            catch { _proxyStatus.Text = "Proxy now: unknown (could not read settings)."; }
        }

        static string Truncate(string v, int max) =>
            string.IsNullOrEmpty(v) ? "(empty)" : (v.Length <= max ? v : v[..max] + "…");

        DockPanel EndpointRow(string label, string endpoint, Brush textBrush, Brush accentBrush)
        {
            var row = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
            row.Children.Add(new TextBlock
            {
                Text = label,
                Foreground = DimBrushStatic,
                Width = 140,
                VerticalAlignment = VerticalAlignment.Center
            });
            var copy = new Button
            {
                Content = "Copy",
                Background = accentBrush,
                Foreground = Brushes.Black,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(14, 6, 14, 6),
                Margin = new Thickness(8, 0, 0, 0),
                Cursor = System.Windows.Input.Cursors.Hand
            };
            copy.Click += (_, __) =>
            {
                try { Clipboard.SetText(endpoint); _status("Copied: " + endpoint); }
                catch (Exception ex) { _status("Copy failed: " + ex.Message); }
            };
            DockPanel.SetDock(copy, Dock.Right);

            row.Children.Add(copy);
            row.Children.Add(new TextBox
            {
                Text = endpoint,
                IsReadOnly = true,
                Background = BgBrush,
                Foreground = textBrush,
                BorderBrush = BorderBrushStatic,
                Padding = new Thickness(8, 5, 8, 5),
                VerticalContentAlignment = VerticalAlignment.Center
            });
            return row;
        }

    }

}
