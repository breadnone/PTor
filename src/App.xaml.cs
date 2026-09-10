using System;
using System.Configuration;

using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;


namespace PTor;


public partial class App : Application

{

    protected override void OnExit(ExitEventArgs e)
    {
        try { SingleInstance.Release(); } catch { }
        base.OnExit(e);
    }

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
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
                // here prevents the StartupUri window from ever appearing.
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
            }
        }
        catch { }
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
