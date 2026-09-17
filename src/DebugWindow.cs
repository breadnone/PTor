using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace PTor
{

    // Secret diagnostics panel: reachable ONLY via the Ctrl+Shift+Esc hotkey
    // handled in MainWindow (no button, no menu entry, nothing in Config).
    // Read-only by design: Refresh rebuilds the proof report, Copy puts it
    // on the clipboard, Close hides. Never throws out of event handlers.
    public class DebugWindow : Window
    {
        readonly TorEngine _engine;
        readonly TextBox _reportBox;
        readonly Button _refreshBtn;

        static readonly SolidColorBrush Bg = new(Color.FromRgb(0x19, 0x1C, 0x22));
        static readonly SolidColorBrush Panel = new(Color.FromRgb(0x22, 0x26, 0x2E));
        static readonly SolidColorBrush Border = new(Color.FromRgb(0x34, 0x3A, 0x46));
        static readonly SolidColorBrush Text = new(Colors.WhiteSmoke);
        static readonly SolidColorBrush Dim = new(Color.FromRgb(0x9A, 0xA3, 0xB2));
        static readonly SolidColorBrush Accent = new(Color.FromRgb(0x60, 0xCD, 0xFF));

        static DebugWindow()
        {
            try { Bg.Freeze(); Panel.Freeze(); Border.Freeze(); Text.Freeze(); Dim.Freeze(); Accent.Freeze(); }
            catch { }
        }

        public DebugWindow(TorEngine engine)
        {
            _engine = engine;
            Title = "PTor Diagnostics";
            Width = 760;
            Height = 620;
            MinWidth = 520;
            MinHeight = 380;
            Background = Bg;
            Foreground = Text;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ShowInTaskbar = false;

            var root = new DockPanel { Background = Bg };
            Content = root;

            var hint = new TextBlock
            {
                Text = "Secret proof panel (Ctrl+Shift+Esc) — read-only. Note: Windows also opens Task Manager on this combo; that is the OS, not PTor.",
                Foreground = Dim,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(12, 10, 12, 6),
            };
            DockPanel.SetDock(hint, Dock.Top);
            root.Children.Add(hint);

            var bar = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(12, 0, 12, 8),
            };
            DockPanel.SetDock(bar, Dock.Top);
            root.Children.Add(bar);

            _refreshBtn = new Button
            {
                Content = "Refresh",
                Foreground = Text,
                Background = Panel,
                BorderBrush = Border,
                Padding = new Thickness(14, 4, 14, 4),
                Margin = new Thickness(0, 0, 8, 0),
            };
            _refreshBtn.Click += async (_, __) => await RefreshAsync();
            bar.Children.Add(_refreshBtn);

            var copyBtn = new Button
            {
                Content = "Copy report",
                Foreground = Text,
                Background = Panel,
                BorderBrush = Border,
                Padding = new Thickness(14, 4, 14, 4),
                Margin = new Thickness(0, 0, 8, 0),
            };
            copyBtn.Click += (_, __) =>
            {
                try { Clipboard.SetText(_reportBox.Text ?? ""); } catch { }
            };
            bar.Children.Add(copyBtn);

            var closeBtn = new Button
            {
                Content = "Close",
                Foreground = Text,
                Background = Panel,
                BorderBrush = Border,
                Padding = new Thickness(14, 4, 14, 4),
            };
            closeBtn.Click += (_, __) => { try { Close(); } catch { } };
            bar.Children.Add(closeBtn);

            _reportBox = new TextBox
            {
                IsReadOnly = true,
                AcceptsReturn = true,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                FontFamily = new FontFamily("Consolas, Cascadia Code, Courier New"),
                FontSize = 12,
                Foreground = Text,
                Background = Panel,
                BorderBrush = Border,
                Padding = new Thickness(8),
                TextWrapping = TextWrapping.NoWrap,
                Margin = new Thickness(12, 0, 12, 12),
                Text = "Loading…",
            };
            root.Children.Add(_reportBox);

            Loaded += async (_, __) => await RefreshAsync();
        }

        public async System.Threading.Tasks.Task RefreshAsync()
        {
            try { _refreshBtn.IsEnabled = false; } catch { }
            try
            {
                _reportBox.Text = "Collecting…";
                string report;
                try { report = await _engine.BuildDebugReportAsync(); }
                catch (Exception ex) { report = "report failed: " + ex.Message; }
                _reportBox.Text = report ?? "(empty)";
                try { _reportBox.ScrollToHome(); } catch { }
            }
            finally { try { _refreshBtn.IsEnabled = true; } catch { } }
        }
    }
}
