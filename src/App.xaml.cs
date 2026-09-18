using System;
using System.Configuration;

using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;


namespace PTor;


public partial class App : Application

{

    // True only for the instance that owns the lock and shows UI. The
    // main window auto-starts tor on Loaded behind this flag, so rejected
    // second instances can never start tor, apply proxy settings, or flash.
    public static bool IsPrimaryInstance { get; private set; }

    // Logon-startup launches pass --minimized (see StartupManager): land in
    // the tray instead of popping a window on every boot. Tor still
    // auto-starts — only the window stays hidden.
    public static bool StartMinimized { get; private set; }

    public static bool HasArg(string[] args, params string[] names)
    {
        try
        {
            foreach (var a in args ?? Array.Empty<string>())
                foreach (var n in names)
                    if (a.Equals(n, StringComparison.OrdinalIgnoreCase))
                        return true;
        }
        catch { }
        return false;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { SingleInstance.Release(); } catch { }
        base.OnExit(e);
    }

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // Never-Eco first: power-throttling state is inherited by children,
        // so tor must be spawned from an unthrottled process (a throttled
        // tunnel stalls and leaks). Covers every launch mode below.
        try { EcoModeGuard.OptOutCurrentProcess(); } catch { }
        if (!AcquireSingleInstanceOrTakeover(e.Args))
        {
            var wantsRepair = e.Args.Any(a =>
                    a.Equals("--fix-network", StringComparison.OrdinalIgnoreCase) ||
                    a.Equals("--repair", StringComparison.OrdinalIgnoreCase));
            MessageBox.Show(
                wantsRepair
                    ? "PTor is already running — close it first, then run the network repair."
                    : "PTor is already running (check the system tray). Only one copy can run at a time.",
                "PTor already running",
                MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown(1);
            return;
        }
        try
        {
            if (e.Args.Any(a =>
                    a.Equals("--fix-network", StringComparison.OrdinalIgnoreCase) ||
                    a.Equals("--repair", StringComparison.OrdinalIgnoreCase)))
            {
                // Headless repair: never create the main window. Shutdown()
                // here prevents any window from ever appearing.
                var lines = new System.Collections.Generic.List<string>
                {
                    "Close PTor first if it is running — this restores shared network settings unconditionally."
                };
                try
                {
                    var engine = new TorEngine(AppDomain.CurrentDomain.BaseDirectory);
                    try { lines.AddRange(await engine.RepairNetworkAsync()); }
                    finally { try { await engine.DisposeAsync(); } catch { } }
                }
                catch (Exception ex)
                {
                    lines.Add("Repair failed: " + ex.Message);
                }
                MessageBox.Show(string.Join("\n", lines), "PTor network repair",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown();
                return;
            }
        }
        catch { }
        // Exit-teardown guard: a sibling is (or just was) mid-teardown —
        // proxy half-restored, tor half-dead. A fresh non-takeover launch
        // right now would auto-start tor into the mess and orphan it.
        // Takeover launches are legitimate handovers and bypass the block.
        try
        {
            if (SingleInstance.ParseTakeoverPid(e.Args ?? Array.Empty<string>()) <= 0 &&
                ExitMarker.IsFreshBlock())
            {
                try
                {
                    var args = string.Join(" ", e.Args ?? Array.Empty<string>());
                    int ppid = -1;
                    try { ppid = RunningAppEnumerator.GetParentPid(Environment.ProcessId); } catch { }
                    ExitTrace.Log($"[exit-guard] blocked spurious start during teardown (parent {ppid}, args: {args}; markers: {string.Join(", ", ExitMarker.DescribeFresh())})");
                }
                catch { }
                Shutdown(0);
                return;
            }
        }
        catch { }
        try { ExitMarker.ClearAll(); } catch { }
        IsPrimaryInstance = true;
        try { StartMinimized = HasArg(e.Args ?? Array.Empty<string>(), "--minimized", "--startup", "-minimized"); } catch { }
        // Primary only: the window (and its Loaded auto-start) exists solely here.
        MainWindow = new MainWindow();
        MainWindow.Show();
    }

    // Normal path: take the lock or refuse. Restart-handover path
    // (--takeover-from <old pid>): the old copy is mid-exit and still holds
    // the lock, so wait for it to die first (bounded), then take over.
    static bool AcquireSingleInstanceOrTakeover(string[] args)
    {
        if (SingleInstance.TryAcquire()) return true;
        try
        {
            var pid = SingleInstance.ParseTakeoverPid(args ?? Array.Empty<string>());
            if (pid > 0 && SingleInstance.WaitForPidExit(pid, TimeSpan.FromSeconds(30)))
                return SingleInstance.TryAcquire();
        }
        catch { }
        return false;
    }

}
