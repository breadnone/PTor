using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
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
        readonly ObservableCollection<string> _blockFiles = new();
        TextBlock _proxyStatus;
        TextBlock _linkStatus;
        TextBlock _verifyResult;
        ListBox _domainListBox;
        TextBox _domainInput;
        ListBox _blockFileList;
        TextBox _blockUrlInput;
        TextBlock _blocklistStatus;
        TextBox _userAgentInput;
        TextBlock _enforceStatus;
        TextBlock _dnsStatus;
        ComboBox _bridgeModeBox = null!;
        TextBox _bridgeCustomInput = null!;
        TextBlock _bridgeStatus = null!;
        bool _bridgeUiReady;
        CheckBox _stableToggle = null!;
        CheckBox _geoToggle = null!;
        ComboBox _geoRegionBox = null!;
        TextBox _geoCustomInput = null!;
        TextBlock _pathStatus = null!;
        CheckBox _enforceToggle = null!;
        bool _enforceBusy;
        readonly Func<Task>? _requestRestartAsAdmin;

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
            foreach (var f in _settings.BlocklistUrls ?? new System.Collections.Generic.List<string>())
                if (!_blockFiles.Contains(f))
                    _blockFiles.Add(f);

            Title = "Config — routing, blocking & identity";
            Width = 920;
            Height = 620;
            MinWidth = 720;
            MinHeight = 480;
            Background = new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20));
            FontFamily = new FontFamily("Segoe UI Variable, Segoe UI");
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            var panelBrush = new SolidColorBrush(Color.FromRgb(0x2B, 0x2B, 0x2B));
            var textBrush = Brushes.WhiteSmoke;
            var dimBrush = new SolidColorBrush(Color.FromRgb(0xA0, 0xA0, 0xA0));
            var accentBrush = new SolidColorBrush(Color.FromRgb(0x60, 0xCD, 0xFF));
            var goodBrush = new SolidColorBrush(Color.FromRgb(0x4C, 0xD9, 0x64));

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
                Foreground = new SolidColorBrush(Color.FromRgb(0xA0, 0xA0, 0xA0)),
                Width = 140,
                VerticalAlignment = VerticalAlignment.Center
            };
            DockPanel.SetDock(spoofLabel, Dock.Left);
            spoofRow.Children.Add(spoofLabel);
            var spoofInput = new TextBox
            {
                Text = _engine.HeaderSpoof,
                Background = new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20)),
                Foreground = textBrush,
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x45, 0x45, 0x45)),
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
                    "(never anyone else's), restores your proxy + env. The in-app blocklist is memory-only and needs no rollback.",
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
                Background = new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20)),
                Foreground = textBrush,
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x45, 0x45, 0x45)),
                Padding = new Thickness(8, 5, 8, 5),
                Margin = new Thickness(0, 0, 0, 8)
            };
            // The drop-down popup paints the system (white) background, so
            // items need explicit dark-on-light styling to stay readable.
            var itemStyle = new Style(typeof(ComboBoxItem));
            itemStyle.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.Black));
            itemStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.White));
            _bridgeModeBox.ItemContainerStyle = itemStyle;
            _bridgeModeBox.Items.Add("Direct (no bridges)");
            _bridgeModeBox.Items.Add("obfs4 — bundled bridges");
            _bridgeModeBox.Items.Add("Snowflake — bundled");
            _bridgeModeBox.Items.Add("Custom bridge lines");
            _bridgeModeBox.Items.Add("Automatic (all tiers)");
            _bridgeModeBox.SelectedIndex = Math.Max(0, Math.Min(4, (int)_settings.BridgeMode));
            bridge.Children.Add(_bridgeModeBox);
            _bridgeCustomInput = new TextBox
            {
                Text = string.Join(Environment.NewLine, _settings.CustomBridgeLines ?? new System.Collections.Generic.List<string>()),
                Background = new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20)),
                Foreground = textBrush,
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x45, 0x45, 0x45)),
                Padding = new Thickness(8, 5, 8, 5),
                AcceptsReturn = true,
                TextWrapping = TextWrapping.Wrap,
                Height = 90,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Visibility = _settings.BridgeMode == BridgeMode.Custom ? Visibility.Visible : Visibility.Collapsed
            };
            _bridgeCustomInput.LostFocus += (_, __) => SaveBridgeSettingsFromUi();
            bridge.Children.Add(_bridgeCustomInput);
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
                Text = "Use where Tor entry guards are blocked or fingerprinted. Bundled defaults age — paste fresh lines (one per line: obfs4/snowflake/conjure/webtunnel or plain IP:port + fingerprint) for Custom. " +
                       "Snowflake needs direct UDP from its helper and Conjure phones its registration endpoint — both stay inside lockdown automatically. " +
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
                Text = "Ctrl/Shift+click selects multiple. Delete key, right-click → Delete, or double-click removes."
            });

            var adBox = new Border
            {
                Background = panelBrush,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 10)
            };
            DockPanel.SetDock(adBox, Dock.Top);
            root.Children.Add(adBox);

            var ad = new StackPanel();
            adBox.Child = ad;
            ad.Children.Add(new TextBlock
            {
                Text = "Ad Blocklist (filter-list URLs)",
                Foreground = textBrush,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 6)
            });
            _blockFileList = new ListBox
            {
                Background = new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x45, 0x45, 0x45)),
                BorderThickness = new Thickness(1),
                Foreground = textBrush,
                Height = 70,
                SelectionMode = SelectionMode.Extended,
                ItemsSource = _blockFiles,
                ContextMenu = DeleteMenu(RemoveSelectedBlockFiles)
            };
            _blockFileList.KeyDown += (_, e) =>
            {
                if (e.Key == System.Windows.Input.Key.Delete) { RemoveSelectedBlockFiles(); e.Handled = true; }
            };
            _blockFileList.MouseDoubleClick += (_, __) => RemoveSelectedBlockFiles();
            ad.Children.Add(_blockFileList);

            var urlAddRow = new DockPanel { Margin = new Thickness(0, 8, 0, 0) };
            ad.Children.Add(urlAddRow);
            var urlAddBtn = SafetyBtn("Add URL", panelBrush, textBrush);
            DockPanel.SetDock(urlAddBtn, Dock.Right);
            urlAddBtn.Margin = new Thickness(8, 0, 0, 0);
            urlAddBtn.Click += (_, __) => AddBlocklistUrl();
            urlAddRow.Children.Add(urlAddBtn);
            _blockUrlInput = DialogTextBox("https://…/list.txt", textBrush);
            _blockUrlInput.KeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) AddBlocklistUrl(); };
            urlAddRow.Children.Add(_blockUrlInput);

            var adBtnRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
            ad.Children.Add(adBtnRow);
            var updateBlBtn = SafetyBtn("Update Block List", panelBrush, textBrush);
            updateBlBtn.Click += async (_, __) => await UpdateBlockListsAsync();
            adBtnRow.Children.Add(updateBlBtn);
            var clearBlBtn = SafetyBtn("Clear", panelBrush, textBrush);
            clearBlBtn.Margin = new Thickness(8, 0, 0, 0);
            clearBlBtn.Click += async (_, __) => await ClearBlocklistAsync();
            adBtnRow.Children.Add(clearBlBtn);

            _blocklistStatus = new TextBlock
            {
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            };
            ad.Children.Add(_blocklistStatus);
            ad.Children.Add(new TextBlock
            {
                Text = "Filter lists (EasyList-style: ||rules, exceptions, plain hosts) download to a local cache and block inside PTor's own DNS + relays, on boot and on Update. No admin rights, no system files touched — the OS hosts file is never modified. Applies to relayed app traffic and Tor-DNS while PTor runs.",
                Foreground = dimBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            });

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
            _ = RefreshBlocklistStatusAsync();
            RefreshEnforcementStatus();
            RefreshDnsStatus();
            RefreshBridgeStatus();
            RefreshPathStatus();
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
            BorderBrush = new SolidColorBrush(Color.FromRgb(0x45, 0x45, 0x45)),
            Padding = new Thickness(12, 6, 12, 6),
            Cursor = System.Windows.Input.Cursors.Hand
        };

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

        void RefreshAll()
        {
            RefreshProxyStatus();
            RefreshLinkStatus();
            _ = RefreshBlocklistStatusAsync();
            RefreshEnforcementStatus();
            RefreshDnsStatus();
            RefreshBridgeStatus();
            RefreshPathStatus();
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

        void SaveBridgeSettingsFromUi()
        {
            try
            {
                var mode = (BridgeMode)Math.Max(0, Math.Min(4, _bridgeModeBox.SelectedIndex));
                _settings.BridgeMode = mode;
                var lines = new System.Collections.Generic.List<string>();
                foreach (var raw in (_bridgeCustomInput.Text ?? "").Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
                {
                    var t = raw.Trim();
                    if (t.Length > 0) lines.Add(t);
                }
                _settings.CustomBridgeLines = lines;
                _settings.Save();
                _bridgeCustomInput.Visibility = mode == BridgeMode.Custom ? Visibility.Visible : Visibility.Collapsed;
                _status(mode == BridgeMode.Direct
                    ? "Bridge mode: direct guards (change takes effect on next Tor start)."
                    : $"Bridge mode: {mode} saved — takes effect on next Tor start.");
            }
            catch (Exception ex) { _status("Bridge settings save failed: " + ex.Message); }
            RefreshBridgeStatus();
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
                Background = new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20)),
                Foreground = textBrush,
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x45, 0x45, 0x45)),
                Padding = new Thickness(8, 5, 8, 5),
                Margin = new Thickness(0, 6, 0, 0)
            };
            var regionStyle = new Style(typeof(ComboBoxItem));
            regionStyle.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.Black));
            regionStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.White));
            _geoRegionBox.ItemContainerStyle = regionStyle;
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
                Margin = new Thickness(0, 4, 0, 0)
            });
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

        void SavePathSettingsFromUi()
        {
            try
            {
                _settings.StableExitEnabled = _stableToggle.IsChecked == true;
                _settings.ExitGeoEnabled = _geoToggle.IsChecked == true;
                _settings.ExitRegion = _geoRegionBox.SelectedItem as string ?? "";
                _settings.ExitCustomCountries = _geoCustomInput.Text ?? "";
                _settings.Save();
                _status("Entry/exit path saved — takes effect on next Tor start.");
            }
            catch (Exception ex) { _status("Path settings save failed: " + ex.Message); }
            RefreshPathStatus();
        }

        void RefreshPathStatus()
        {
            try
            {
                var countries = _settings.ExitGeoEnabled
                    ? TorPathOptions.ResolveExitCountries(_settings.ExitRegion, _settings.ExitCustomCountries)
                    : new System.Collections.Generic.List<string>();
                var parts = new System.Collections.Generic.List<string>();
                parts.Add(_settings.StableExitEnabled
                    ? "stable connection ON (24h circuits, rotation paused)"
                    : "stable connection off");
                parts.Add(_settings.ExitGeoEnabled
                    ? (countries.Count > 0 ? "exit preference: " + string.Join(",", countries) + " (fallback: any)" : "geo ON but nothing valid selected")
                    : "geo off (any country)");
                _pathStatus.Text = "Effective next start: " + string.Join(" · ", parts) + ".";
            }
            catch { _pathStatus.Text = "Entry/exit path: unknown."; }
        }

        void RefreshBridgeStatus()
        {
            try
            {
                var text = _engine.BridgeStatus;
                if (_bridgeModeBox.SelectedIndex == (int)BridgeMode.Custom)
                {
                    var (_, errors) = BridgeConfigEngine.ValidateCustomLines(
                        (_bridgeCustomInput.Text ?? "").Split(new[] { "\r\n", "\n" }, StringSplitOptions.None));
                    if (errors.Count > 0)
                        text += "\nCustom lines problem: " + string.Join(" ", errors.Take(2));
                    else
                        text += "\nCustom lines look valid.";
                }
                _bridgeStatus.Text = text;
            }
            catch { _bridgeStatus.Text = "Bridges: unknown."; }
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
                        "Stop enforcement? Apps regain direct internet access and system DNS is restored (proxy routing continues).",
                        "Stop enforcement", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (confirm != MessageBoxResult.Yes) { SyncEnforceToggle(); return; }
                    // UI thread: hop to pool, the gate wait is bounded but blocking.
                    try { _status(await Task.Run(() => _engine.DisableEnforcement())); }
                    catch (Exception ex) { _status("Stop enforcement failed: " + ex.Message); }
                    PersistEnforcePreference();
                    RefreshEnforcementStatus();
                    RefreshDnsStatus();
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
            Background = new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20)),
            Foreground = textBrush,
            BorderBrush = new SolidColorBrush(Color.FromRgb(0x45, 0x45, 0x45)),
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

        void RemoveSelectedBlockFiles()
        {
            var sel = _blockFileList.SelectedItems.Cast<string>().ToList();
            if (sel.Count == 0) return;
            foreach (var f in sel)
            {
                _blockFiles.Remove(f);
                _settings.BlocklistUrls.Remove(f);
                try
                {
                    var cache = HostBlocklist.CachePathFor(HostBlocklist.DefaultCacheDir(), f);
                    if (File.Exists(cache)) File.Delete(cache);
                }
                catch { }
            }
            _settings.Save();
            _status($"Removed {sel.Count} blocklist URL(s).");
            _ = RefreshBlocklistStatusAsync();
        }

        void AddBlocklistUrl()
        {
            var url = (_blockUrlInput.Text ?? "").Trim();
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                MessageBox.Show(this, "Enter a valid http(s) filter-list URL.",
                    "Ad blocklist", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            url = uri.ToString();
            if (!_blockFiles.Contains(url))
            {
                _blockFiles.Add(url);
                _settings.BlocklistUrls.Add(url);
                _settings.Save();
                _status("Blocklist URL added — hit Update Block List to download + block in-app.");
            }
            _blockUrlInput.Text = string.Empty;
            _ = RefreshBlocklistStatusAsync();
        }

        bool _blBusy;

        // File I/O + untrusted-content regex stay off the UI thread.
        async System.Threading.Tasks.Task RefreshBlocklistStatusAsync()
        {
            if (_blBusy) return;
            _blBusy = true;
            try
            {
                var files = new System.Collections.Generic.List<string>(_blockFiles);
                _blocklistStatus.Text = await System.Threading.Tasks.Task.Run(() => DescribeBlocklist(files));
            }
            catch (Exception ex)
            {
                _blocklistStatus.Text = "Status failed: " + ex.Message;
            }
            finally { _blBusy = false; }
        }

        static string DescribeBlocklist(System.Collections.Generic.List<string> urls)
        {
            try
            {
                var active = HostBlocklist.GetActiveCount();
                if (urls.Count == 0)
                {
                    return active > 0
                        ? $"No lists configured, but {active} host(s) still blocking in memory — Clear to drop them."
                        : "No lists. Add filter-list URLs above, then Update Block List.";
                }
                string cacheDir;
                try { cacheDir = HostBlocklist.DefaultCacheDir(); }
                catch (Exception ex) { return "Status failed: " + ex.Message; }
                var cached = urls
                    .Select(u => { try { return HostBlocklist.CachePathFor(cacheDir, u); } catch { return ""; } })
                    .Where(File.Exists)
                    .ToList();
                if (cached.Count == 0)
                    return $"{urls.Count} URL(s) configured, nothing downloaded yet — hit Update Block List. · {active} blocking in-app";
                var parsed = HostBlocklist.ParseFiles(cached);
                var parts = $"{urls.Count} URL(s) · {cached.Count} cached · {parsed.Hosts.Count:N0} hosts parsed";
                try
                {
                    var oldest = cached
                        .Select(f => { try { return File.GetLastWriteTimeUtc(f); } catch { return DateTime.UtcNow; } })
                        .Min();
                    var age = DateTime.UtcNow - oldest;
                    parts += age.TotalHours < 25
                        ? " · cache updated today"
                        : $" · cache {Math.Max(1, (int)age.TotalDays)}d old";
                }
                catch { }
                if (parsed.AllowedExceptions > 0)
                    parts += $" · {parsed.AllowedExceptions} allow-exceptions";
                if (parsed.SkippedWildcard > 0)
                    parts += $" · {parsed.SkippedWildcard} wildcard(s) skipped";
                if (parsed.SkippedUnsupported > 0)
                    parts += $" · {parsed.SkippedUnsupported} line(s) skipped";
                parts += $" · {active} blocking in-app";
                try
                {
                    if (HostBlocklist.HasLegacyHostsSection())
                        parts += " · legacy hosts section still present (PTor ignores it; manual admin edit only)";
                }
                catch { }
                return parts;
            }
            catch (Exception ex)
            {
                return "Status failed: " + ex.Message;
            }
        }

        async System.Threading.Tasks.Task UpdateBlockListsAsync()
        {
            var urls = new System.Collections.Generic.List<string>(_blockFiles);
            if (urls.Count == 0)
            {
                MessageBox.Show(this, "Add at least one filter-list URL first.",
                    "Ad blocklist", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            _status("Updating blocklists (download, in-app — no admin needed)...");
            var (ok, message) = await HostBlocklist.UpdateFromUrlsAsync(urls);
            _status(message);
            await RefreshBlocklistStatusAsync();
            if (!ok)
                MessageBox.Show(this, message, "Ad blocklist", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        async System.Threading.Tasks.Task ClearBlocklistAsync()
        {
            var confirm = MessageBox.Show(this,
                "Clear the in-memory blocklist? (Your list URLs and caches are kept.)",
                "Clear ad blocklist", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;

            _status("Clearing in-app blocklist...");
            var (ok, message) = await HostBlocklist.ClearAsync();
            _status(message);
            await RefreshBlocklistStatusAsync();
            MessageBox.Show(this, message, "Ad blocklist",
                MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
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
                Foreground = new SolidColorBrush(Color.FromRgb(0xA0, 0xA0, 0xA0)),
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
                Background = new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20)),
                Foreground = textBrush,
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x45, 0x45, 0x45)),
                Padding = new Thickness(8, 5, 8, 5),
                VerticalContentAlignment = VerticalAlignment.Center
            });
            return row;
        }

    }

}
