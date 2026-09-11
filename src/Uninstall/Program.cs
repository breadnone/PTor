// PTor Uninstall companion (Uninstall.exe).
//
// Removes every trace PTor can leave on a system. Same concept as
// rescue-internet.bat (compare-before-restore, only ours goes, full
// reporting) plus uninstall-only extras (keys, folders, reboot):
//   1. stops running PTor.exe (+ orphaned tor.exe under the app folder),
//   2. restores HKCU proxy / env vars and HKLM DNS resolvers PTor managed,
//   3. deletes PTor's registry keys (HKCU\Software\PTor, HKLM\SOFTWARE\PTor),
//   4. removes the WinDivert driver service — but ONLY when it is PTor's own
//      (our checkpoint says we created it, or it points at our bundled .sys).
//      A foreign WinDivert service is left untouched and reported.
//   5. deletes the per-user (%AppData%\PTor) and machine (%ProgramData%\PTor)
//      special folders, flushes the DNS cache,
//   5b.marker-less fallbacks (proxy env vars / WinHTTP proxy still aimed at
//      our loopback bridge with no markers left to prove it),
//   6. optionally deletes the program folder itself (scheduled after exit).
//
// Flags: --dry-run (print everything, change nothing), --yes (no prompts).
// Never touches the OS hosts file.

using System.Diagnostics;
using Microsoft.Win32;
using PTor;

var cli = Environment.GetCommandLineArgs().Skip(1).ToArray();
bool dryRun = cli.Any(a => a.Equals("--dry-run", StringComparison.OrdinalIgnoreCase));
bool assumeYes = cli.Any(a => a.Equals("--yes", StringComparison.OrdinalIgnoreCase)
    || a.Equals("-y", StringComparison.OrdinalIgnoreCase));
bool noReboot = cli.Any(a => a.Equals("--no-reboot", StringComparison.OrdinalIgnoreCase));
if (cli.Any(a => a.Equals("--help", StringComparison.OrdinalIgnoreCase)
    || a.Equals("-h", StringComparison.OrdinalIgnoreCase)
    || a.Equals("/?", StringComparison.OrdinalIgnoreCase)))
{
    Console.WriteLine("PTor Uninstall — removes all PTor traces (proxy/env/DNS restore,");
    Console.WriteLine("registry keys, own WinDivert service, %AppData%\\PTor, %ProgramData%\\PTor).");
    Console.WriteLine("Usage: Uninstall [--dry-run] [--yes|-y] [--no-reboot] [--log <file>]");
    Console.WriteLine("  --dry-run    show what would happen, change nothing (no reboot scheduled)");
    Console.WriteLine("  --yes        no prompts (reboot still scheduled unless --no-reboot)");
    Console.WriteLine("  --no-reboot  skip the enforced restart (not recommended)");
    Console.WriteLine("  --log        write all output to <file>");
    return 0;
}
string? logPath = null;
for (int i = 0; i < cli.Length; i++)
    if (cli[i].Equals("--log", StringComparison.OrdinalIgnoreCase) && i + 1 < cli.Length)
        logPath = cli[i + 1];

// All output goes through Say so --log can capture it for support/debugging.
var logged = new List<string>();
void Say(string s)
{
    try { logged.Add(s); } catch { }
    try { Console.WriteLine(s); } catch { }
}
void FlushLog()
{
    try { if (!string.IsNullOrWhiteSpace(logPath)) File.WriteAllLines(logPath, logged); } catch { }
}

Say("PTor Uninstall" + (dryRun ? "  [--dry-run: no changes will be made]" : ""));
Say(new string('-', 60));

string appDir;
try { appDir = Path.GetFullPath(AppContext.BaseDirectory); }
catch { appDir = Environment.CurrentDirectory; }
Say("App folder: " + appDir);

// Manifest already demands admin, but double-check (e.g. manifest stripped).
if (!dryRun && !AdminHelper.IsAdministrator())
{
    Say("ERROR: run Uninstall.exe as administrator (HKLM/service cleanup needs it).");
    return Pause(2);
}

// --- 1. stop PTor (+ orphaned tor.exe under our folder) ---
var ptor = Process.GetProcessesByName("PTor");
if (ptor.Length > 0)
{
    Say($"Found {ptor.Length} running PTor.exe — it must be stopped first.");
    if (!dryRun && !Ask("Terminate PTor now?", defaultYes: true)) return Pause(2);
    foreach (var p in ptor)
    {
        try
        {
            if (!dryRun) { p.Kill(entireProcessTree: true); p.WaitForExit(10000); }
            Say($"  {(dryRun ? "would terminate" : "terminated")} PTor (PID {p.Id}).");
        }
        catch (Exception ex) { Say($"  Could not terminate PID {p.Id}: {ex.Message}"); }
        finally { try { p.Dispose(); } catch { } }
    }
}
foreach (var p in Process.GetProcessesByName("tor"))
{
    string? path = null;
    try { path = p.MainModule?.FileName; } catch { }
    try
    {
        // Only OUR tor.exe (under the app folder) — never e.g. Tor Browser's.
        if (!string.IsNullOrEmpty(path) && path.StartsWith(appDir, StringComparison.OrdinalIgnoreCase))
        {
            if (!dryRun) { p.Kill(entireProcessTree: true); p.WaitForExit(10000); }
            Say($"  {(dryRun ? "would terminate" : "terminated")} orphaned {path}.");
        }
    }
    catch { }
    finally { try { p.Dispose(); } catch { } }
}

// --- 2. restore managed network settings (compare-before-restore: safe) ---
Say(Do("Proxy", () => new SystemProxyManager().Disable()));
Say(Do("Env  ", () => new UserEnvManager().Disable()));
Say(Do("DNS  ", () => new SystemDnsManager().Disable()));

// --- 3. delete PTor's own registry keys (deepest first) ---
DeleteKeyTree(Registry.CurrentUser, @"Software\PTor", "HKCU\\Software\\PTor");
DeleteKeyTreeIfEmpty(Registry.LocalMachine, @"SOFTWARE\PTor\Dns", "HKLM\\SOFTWARE\\PTor\\Dns");
DeleteKeyTreeIfEmpty(Registry.LocalMachine, @"SOFTWARE\PTor", "HKLM\\SOFTWARE\\PTor");

// --- 4. WinDivert driver service: remove ONLY if ours ---
var svc = dryRun ? null : SafeServiceInfo();
if (dryRun)
{
    var live = DivertNative.GetServiceInfo();
    Say($"WinDivert service now: {(live == null ? "unknown (cannot query)" : live.Exists ? $"present ({live.ImagePath}, {live.State})" : "absent")} — would remove only if PTor's own.");
}
else if (svc == null)
{
    Say("WinDivert service state unreadable — leaving as-is (no changes).");
}
else if (!svc.Exists)
{
    Say("WinDivert service: not installed — nothing to remove.");
}
else
{
    bool staleOurs = false;
    try
    {
        var cp = EnforcementCheckpoint.Load();
        staleOurs = cp != null && cp.DriverService == "created";
    }
    catch { }
    if (staleOurs || ServiceLooksOurs(OurSysPath(appDir), svc.ImagePath))
        Say("WinDivert service (PTor's own): " + DivertNative.RemoveService());
    else
        Say($"WinDivert service is FOREIGN ({svc.ImagePath}, {svc.State}) — left untouched. Remove it manually (sc delete WinDivert) only if you know which app installed it.");
}
if (!dryRun) { try { EnforcementCheckpoint.Delete(); } catch { } }

// --- 5. special folders + DNS flush ---
DeleteDir(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PTor"), "%AppData%\\PTor");
DeleteDir(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PTor"), "%ProgramData%\\PTor");
FlushDns();

// --- 5b. marker-less fallbacks (mirrors rescue-internet.bat tail: proxy env
// vars and WinHTTP proxy still aimed at our loopback bridge with no markers
// left to prove it — only exact matches go, everything else is untouched) ---
FallbackProxyEnvVars();
FallbackWinHttpProxy();

// --- 6. optional: program folder itself ---
bool looksLikeInstall = File.Exists(Path.Combine(appDir, "PTor.exe"))
    || Directory.Exists(Path.Combine(appDir, "tools", "WinDivert"));
if (looksLikeInstall && !dryRun && Ask($"Delete the program folder itself ({appDir})?", defaultYes: false))
{
    try
    {
        // Self-delete: schedule rd after this process exits.
        var cmd = $"/c timeout /t 3 /nobreak >nul & rd /s /q \"{appDir}\"";
        Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            Arguments = cmd,
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        Say("Program folder will be deleted in a few seconds. Goodbye.");
    }
    catch (Exception ex) { Say("Could not schedule folder deletion: " + ex.Message); }
}
else if (dryRun && looksLikeInstall)
{
    Say($"Would offer to delete the program folder ({appDir}).");
}

Say(new string('-', 60));
Say(dryRun ? "Dry run complete — nothing was changed." : "Uninstall complete. Restart apps/browsers so they pick up the restored settings.");

// Enforced reboot: in-use driver/network leftovers only clear fully on a
// restart. Interactive default is Yes; --yes schedules it; only --no-reboot
// (or a dry run) skips it — and then the user is told to reboot by hand.
if (!dryRun && !noReboot)
{
    if (assumeYes || Ask("Restart Windows now to finish the uninstall?", defaultYes: true))
        ScheduleReboot();
    else
        Say("WARNING: reboot skipped — restart Windows manually before going online. Leftover driver/network state may keep you offline until then.");
}
else if (!dryRun && noReboot)
{
    Say("WARNING: --no-reboot given — restart Windows manually before going online.");
}
return Pause(0);

// ---------- helpers ----------

string Do(string tag, Func<string> fn)
{
    if (dryRun) return $"{tag}: would restore if PTor-managed.";
    try { return $"{tag}: {fn()}"; }
    catch (Exception ex) { return $"{tag}: FAILED ({ex.Message})"; }
}

void DeleteKeyTree(RegistryKey hive, string subKey, string display)
{
    try
    {
        if (hive.OpenSubKey(subKey, writable: false) == null)
        {
            Say($"{display}: absent — nothing to delete.");
            return;
        }
        if (dryRun) { Say($"{display}: would delete (PTor's own key)."); return; }
        hive.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
        Say($"{display}: deleted.");
    }
    catch (Exception ex) { Say($"{display}: could not delete ({ex.Message})."); }
}

void DeleteKeyTreeIfEmpty(RegistryKey hive, string subKey, string display)
{
    // HKLM key holds only our Dns values; still, only remove when empty.
    try
    {
        using var k = hive.OpenSubKey(subKey, writable: true);
        if (k == null) { Say($"{display}: absent — nothing to delete."); return; }
        bool empty = k.GetValueNames().Length == 0 && k.GetSubKeyNames().Length == 0;
        if (!empty) { Say($"{display}: not empty (unexpected values) — left as-is."); return; }
        if (dryRun) { Say($"{display}: would delete (empty, PTor's own key)."); return; }
        hive.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
        Say($"{display}: deleted (was empty).");
    }
    catch (Exception ex) { Say($"{display}: could not delete ({ex.Message})."); }
}

void DeleteDir(string path, string display)
{
    try
    {
        if (!Directory.Exists(path)) { Say($"{display}: absent — nothing to delete."); return; }
        if (dryRun) { Say($"{display}: would delete."); return; }
        Directory.Delete(path, recursive: true);
        Say($"{display}: deleted.");
    }
    catch (Exception ex) { Say($"{display}: could not delete ({ex.Message})."); }
}

void FlushDns()
{
    if (dryRun) { Say("DNS cache: would flush."); return; }
    try
    {
        using var p = Process.Start(new ProcessStartInfo
        {
            FileName = "ipconfig", Arguments = "/flushdns",
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        });
        if (p != null) p.WaitForExit(15000);
        Say("DNS cache: flushed.");
    }
    catch (Exception ex) { Say("DNS cache: flush failed (" + ex.Message + ")."); }
}

void FallbackProxyEnvVars()
{
    // Same marker as the rescue script: our bridge default. .NET's setter
    // broadcasts WM_SETTINGCHANGE itself (the bat needs its setx trick).
    const string marker = "127.0.0.1:9080";
    string[] vars = { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy" };
    int total = 0;
    foreach (var scope in new[] { EnvironmentVariableTarget.User, EnvironmentVariableTarget.Machine })
    {
        foreach (var name in vars)
        {
            string? cur = null;
            try { cur = Environment.GetEnvironmentVariable(name, scope); } catch { continue; }
            if (string.IsNullOrEmpty(cur) || cur.IndexOf(marker, StringComparison.OrdinalIgnoreCase) < 0)
                continue;
            if (dryRun) { total++; continue; }
            try { Environment.SetEnvironmentVariable(name, null, scope); total++; }
            catch (Exception ex) { Say($"  FALLBACK ENV: could not clear {scope}/{name} ({ex.Message})."); }
        }
    }
    Say(total > 0
        ? $"FALLBACK ENV: {(dryRun ? "would clear " : "cleared ")}{total} leftover proxy variable(s) pointing at {marker}."
        : $"FALLBACK ENV: no leftover {marker} proxy variables found.");
}

void FallbackWinHttpProxy()
{
    const string marker = "127.0.0.1:9080";
    if (dryRun) { Say("WinHTTP proxy: would reset if pointing at 127.0.0.1:9080."); return; }
    try
    {
        string Netsh() => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");
        string output = "";
        using (var p = Process.Start(new ProcessStartInfo
        {
            FileName = Netsh(), Arguments = "winhttp show proxy",
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        }))
        {
            if (p != null)
            {
                p.WaitForExit(15000);
                try { output = p.StandardOutput.ReadToEnd() ?? ""; } catch { }
            }
        }
        if (output.IndexOf(marker, StringComparison.OrdinalIgnoreCase) < 0)
        {
            Say("FALLBACK PROXY: WinHTTP proxy not pointing at 127.0.0.1:9080, left as-is.");
            return;
        }
        using (var q = Process.Start(new ProcessStartInfo
        {
            FileName = Netsh(), Arguments = "winhttp reset proxy",
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        }))
        {
            q?.WaitForExit(15000);
        }
        Say("FALLBACK PROXY: WinHTTP proxy was still set to 127.0.0.1:9080, reset to direct access.");
    }
    catch (Exception ex) { Say("FALLBACK PROXY check failed (" + ex.Message + ")."); }
}

void ScheduleReboot()
{
    try
    {
        using var p = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "shutdown.exe"),
            Arguments = "/r /t 60 /c \"PTor uninstall complete - restarting to clear leftover network and driver state.\"",
            UseShellExecute = false, CreateNoWindow = true,
        });
        if (p == null) throw new InvalidOperationException("could not start shutdown.exe");
        p.WaitForExit(15000);
        if (p.ExitCode == 0)
            Say("Restart scheduled in 60 seconds. To abort it: shutdown /a");
        else
            Say($"Could not schedule restart (exit {p.ExitCode}) — please reboot manually.");
    }
    catch (Exception ex) { Say("Could not schedule restart (" + ex.Message + ") — please reboot manually."); }
}

DivertNative.DivertServiceInfo? SafeServiceInfo()
{
    try { return DivertNative.GetServiceInfo(); } catch { return null; }
}

string? OurSysPath(string dir)
{
    try
    {
        var sub = Path.Combine(dir, "tools", "WinDivert", Environment.Is64BitProcess ? "x64" : "x86");
        var sys = Path.Combine(sub, Environment.Is64BitProcess ? "WinDivert64.sys" : "WinDivert32.sys");
        return File.Exists(sys) && File.Exists(Path.Combine(sub, "WinDivert.dll")) ? sys : null;
    }
    catch { return null; }
}

bool ServiceLooksOurs(string? ourSys, string? image)
{
    try
    {
        if (string.IsNullOrWhiteSpace(ourSys) || string.IsNullOrWhiteSpace(image)) return false;
        return string.Equals(Norm(ourSys), Norm(image), StringComparison.OrdinalIgnoreCase);
    }
    catch { return false; }
}

string Norm(string p)
{
    var s = p.Trim().Trim('"').Trim();
    if (s.StartsWith(@"\\?\", StringComparison.Ordinal)) s = s.Substring(4);
    try { s = Environment.ExpandEnvironmentVariables(s); } catch { }
    try { s = Path.GetFullPath(s); } catch { }
    return s.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
}

bool Ask(string question, bool defaultYes)
{
    if (assumeYes) { Say(question + " [auto-yes]"); return true; }
    Console.Write($"{question} [{(defaultYes ? "Y/n" : "y/N")}] ");
    var answer = (Console.ReadLine() ?? "").Trim();
    if (answer.Length == 0) return defaultYes;
    return answer.StartsWith("y", StringComparison.OrdinalIgnoreCase);
}

int Pause(int code)
{
    try { FlushLog(); } catch { }
    if (!assumeYes)
    {
        Say("Press Enter to close...");
        try { FlushLog(); } catch { }
        try { Console.ReadLine(); } catch { }
    }
    return code;
}
