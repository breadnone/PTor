using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;

namespace PTor
{

    public class MonitoredApp : INotifyPropertyChanged
    {
        static readonly SolidColorBrush RoutedBrush = new(Color.FromRgb(0x4C, 0xD9, 0x64));
        static readonly SolidColorBrush DirectBrush = new(Color.FromRgb(0xFF, 0x6B, 0x6B));
        static readonly SolidColorBrush DimBrush = new(Color.FromRgb(0xA0, 0xA0, 0xA0));

        public int Pid { get; }

        string _name;
        public string Name { get => _name; set { if (_name != value) { _name = value; Raise(nameof(Name)); } } }

        string _exePath;
        public string ExePath { get => _exePath; set { if (_exePath != value) { _exePath = value; Raise(nameof(ExePath)); } } }

        string _health = "…";
        public string Health { get => _health; private set { if (_health != value) { _health = value; Raise(nameof(Health)); } } }

        string _detail = "";
        public string Detail { get => _detail; private set { if (_detail != value) { _detail = value; Raise(nameof(Detail)); } } }

        public int HealthKind { get; private set; }

        Brush _healthBrush = DimBrush;
        public Brush HealthBrush { get => _healthBrush; private set { if (!ReferenceEquals(_healthBrush, value)) { _healthBrush = value; Raise(nameof(HealthBrush)); } } }

        public MonitoredApp(int pid, string name, string exePath)
        {
            Pid = pid;
            _name = name;
            _exePath = exePath;
        }

        public void SetHealth(string label, int kind, string detail)
        {
            Health = label;
            Detail = detail;
            HealthKind = kind;
            HealthBrush = kind switch
            {
                1 => RoutedBrush,
                2 => DirectBrush,
                _ => DimBrush
            };
        }

        public static GridViewColumn CreateHealthColumn(double width = 80)
        {
            var col = new GridViewColumn { Header = "Health", Width = width };
            var factory = new FrameworkElementFactory(typeof(TextBlock));
            factory.SetBinding(TextBlock.TextProperty, new Binding("Health"));
            factory.SetBinding(TextBlock.ForegroundProperty, new Binding("HealthBrush"));
            factory.SetValue(TextBlock.FontWeightProperty, FontWeights.SemiBold);
            col.CellTemplate = new DataTemplate { VisualTree = factory };
            return col;
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        void Raise(string prop) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
    }
}
