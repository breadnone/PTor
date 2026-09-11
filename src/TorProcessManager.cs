using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{
    public enum TorState
    {
        Stopped,
        Starting,
        Bootstrapping,
        Connected,
        Reconnecting,
        Error
    }

    public class TorStateChangedEventArgs : EventArgs
    {
        public TorState State { get; init; }
        public string Message { get; init; } = "";
        public int? BootstrapPercent { get; init; }
    }

    public class TorProcessManager : IDisposable
    {
        readonly string _toolsDir;
        readonly string _dataDir;
        readonly string _torrcPath;

        Process? _proc;

        // Death-pact job handle: open for tor's whole life, closed only
        // after it is down. Closing it kills any remaining job members.
        IntPtr _jobHandle = IntPtr.Zero;

        void CloseJob()
        {
            try
            {
                var h = _jobHandle;
                _jobHandle = IntPtr.Zero;
                ProcessDeathPact.Close(h);
            }
            catch { }
        }

        public int SocksPort { get; }
        public int ControlPort { get; }
        public int DnsPort { get; }
        public string TorExePath { get; }
        public string ControlCookiePath => Path.Combine(_dataDir, "control_auth_cookie");

        // Entry/exit path options, set before Start, persist across
        // reconnects (same torrc regenerated). Sanitized lists only.
        public List<string> ExitCountries { get; set; } = new();
        // Circuit dirtiness: how long Tor reuses circuits (default 600s).
        // Stable mode raises it so exits hop as rarely as possible.
        public int MaxCircuitDirtinessSec { get; set; } = 600;
        public bool IsRunning => _proc != null && !_proc.HasExited;

        public int? CurrentPid
        {
            get
            {
                try
                {
                    var p = _proc;
                    return (p != null && !p.HasExited) ? p.Id : null;
                }
                catch { return null; }
            }
        }

        public event EventHandler<TorStateChangedEventArgs>? StateChanged;
        public event EventHandler? UnexpectedExit;

        public TorProcessManager(string appBaseDir, int socksPort = 9050, int controlPort = 9051, int dnsPort = 9053)
        {
            _toolsDir = Path.Combine(appBaseDir, "tools");
            TorExePath = Path.Combine(_toolsDir, "Tor", "tor.exe");
            if (!File.Exists(TorExePath))
            {

                var alt = Path.Combine(_toolsDir, "tor.exe");
                if (File.Exists(alt)) TorExePath = alt;
            }

            _dataDir = Path.Combine(appBaseDir, "tordata");
            Directory.CreateDirectory(_dataDir);
            _torrcPath = Path.Combine(_dataDir, "torrc.generated");

            SocksPort = socksPort;
            ControlPort = controlPort;
            DnsPort = dnsPort;
        }

        internal static string BuildTorrcContent(
            int socksPort, int controlPort, int dnsPort,
            string dataDir, string? geoV4, string? geoV6,
            ResolvedBridges? bridges,
            int dirtinessSec = 600,
            IEnumerable<string>? exitCountries = null)
        {
            var torrc = $@"
SocksPort 127.0.0.1:{socksPort}
ControlPort 127.0.0.1:{controlPort}
CookieAuthentication 1
DNSPort 127.0.0.1:{dnsPort}
DataDirectory {dataDir.Replace("\\", "/")}
{(geoV4 != null ? $"GeoIPFile {geoV4.Replace("\\", "/")}" : "# GeoIPFile <bundle geoip not found - country lookup unavailable>")}
{(geoV6 != null ? $"GeoIPv6File {geoV6.Replace("\\", "/")}" : "# GeoIPv6File <bundle geoip6 not found - country lookup unavailable>")}
AvoidDiskWrites 1
ClientOnly 1
KeepalivePeriod 60
MaxClientCircuitsPending 64
MaxCircuitDirtiness {Math.Max(60, dirtinessSec)}
Log notice stdout
";
            if (bridges != null && bridges.UseBridges)
            {
                torrc += "UseBridges 1\n";
                foreach (var plugin in bridges.PluginLines)
                    torrc += plugin + "\n";
                foreach (var line in bridges.BridgeLines)
                    torrc += "Bridge " + line + "\n";
            }
            if (exitCountries != null)
            {
                var codes = exitCountries
                    .Where(c => !string.IsNullOrWhiteSpace(c))
                    .Select(c => c.Trim().ToLowerInvariant())
                    .Where(c => c.Length == 2 && c.All(char.IsLetter))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                if (codes.Count > 0)
                {
                    // StrictNodes 0 (the default, stated explicitly): fall
                    // back to any country when preferred exits are unavailable.
                    torrc += "ExitNodes " + string.Join(",", codes.Select(c => "{" + c + "}")) + "\n";
                    torrc += "StrictNodes 0\n";
                }
            }
            return torrc;
        }

        void WriteTorrc(ResolvedBridges? bridges)
        {

            var geoV4 = FindBundleFile("geoip");
            var geoV6 = FindBundleFile("geoip6");

            File.WriteAllText(_torrcPath, BuildTorrcContent(
                SocksPort, ControlPort, DnsPort, _dataDir, geoV4, geoV6, bridges,
                MaxCircuitDirtinessSec, ExitCountries));
        }

        string? FindBundleFile(string name)
        {
            try
            {
                var exeDir = Path.GetDirectoryName(TorExePath);
                var candidates = new[]
                {
                    exeDir != null ? Path.Combine(exeDir, name) : null,
                    Path.Combine(_toolsDir, name),
                    Path.Combine(_toolsDir, "Tor", name),
                    Path.Combine(_toolsDir, "data", name)
                };
                foreach (var c in candidates)
                    if (!string.IsNullOrEmpty(c) && File.Exists(c))
                        return c;
            }
            catch { }
            return null;
        }

        // Crash orphans: a killed PTor strands tor.exe + pluggable transports
        // (lyrebird/snowflake helpers) that pile up across restarts, wasting
        // RAM/sockets and fighting over files. Anything running from OUR
        // tools dir is ours by construction (single instance; Tor Browser et
        // al live elsewhere) — reap it before launching. Never throws.
        static readonly string[] StaleSweepNames = { "tor", "lyrebird", "conjure-client", "snowflake-client" };

        void ReclaimStaleProcesses()
        {
            try
            {
                string root;
                try { root = Path.GetFullPath(_toolsDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar; }
                catch { return; }
                var me = Environment.ProcessId;
                var reaped = 0;
                Process[] all;
                try { all = Process.GetProcesses(); }
                catch { return; }
                foreach (var p in all)
                {
                    string name = "";
                    try
                    {
                        if (p.Id == me || p.HasExited) continue;
                        name = p.ProcessName ?? "";
                    }
                    catch { try { p.Dispose(); } catch { } continue; }
                    bool wanted = false;
                    foreach (var n in StaleSweepNames)
                        if (name.Equals(n, StringComparison.OrdinalIgnoreCase)) { wanted = true; break; }
                    if (!wanted) { try { p.Dispose(); } catch { } continue; }
                    try
                    {
                        var exe = RunningAppEnumerator.TryGetExePath(p.Id);
                        if (string.IsNullOrEmpty(exe) ||
                            !Path.GetFullPath(exe).StartsWith(root, StringComparison.OrdinalIgnoreCase))
                            continue; // same name, different owner (e.g. Tor Browser) — hands off
                        try { p.Kill(entireProcessTree: true); } catch { continue; }
                        try { p.WaitForExit(3000); } catch { }
                        reaped++;
                    }
                    catch { }
                    finally { try { p.Dispose(); } catch { } }
                }
                if (reaped > 0)
                    RaiseState(TorState.Starting,
                        $"Removed {reaped} stale Tor/transport process(es) orphaned by a previous run.");
            }
            catch { }
        }

        void ReclaimOurPorts()
        {
            foreach (var port in new[] { (ushort)SocksPort, (ushort)ControlPort, (ushort)DnsPort })
            {
                int? pid;
                try { pid = AppTrafficMonitor.GetTcpListenerOwner(port); }
                catch { continue; }
                if (pid == null) continue;

                string? exe = null;
                try { exe = RunningAppEnumerator.TryGetExePath(pid.Value); } catch { }

                if (string.IsNullOrEmpty(exe) ||
                    !string.Equals(exe, TorExePath, StringComparison.OrdinalIgnoreCase))
                {
                    var who = string.IsNullOrEmpty(exe) ? $"PID {pid.Value}" : $"{exe} (PID {pid.Value})";
                    throw new InvalidOperationException(
                        $"Port {port} is already in use by {who} — not our tor. Free the port (or stop the other program) and try again. " +
                        "(Launching tor anyway would die with tor's cryptic 'Failed to bind / Reading config failed'.)");
                }

                var stopped = false;
                string stopErr = "";
                try
                {
                    using var p = Process.GetProcessById(pid.Value);
                    try
                    {
                        p.Kill();

                        try { p.WaitForExit(5000); } catch { }
                        stopped = true;
                    }
                    catch (Exception ex) { stopErr = ex.GetType().Name; }
                }
                catch { stopped = true; }
                if (!stopped)
                    throw new InvalidOperationException(
                        $"Port {port} is held by our tor.exe (PID {pid.Value}) but stopping it failed ({stopErr}) — kill it in Task Manager and retry.");
                RaiseState(TorState.Starting,
                    $"Removed stale tor.exe (PID {pid.Value}) holding port {port} — likely orphaned by a crash.");
            }
        }

        public void Start(ResolvedBridges? bridges = null)
        {
            if (IsRunning) return;
            TorUpdater.RecoverIncompleteInstall(_toolsDir, msg => RaiseState(TorState.Starting, msg));
            if (!File.Exists(TorExePath))
                throw new FileNotFoundException(
                    $"tor.exe not found. Expected the Tor Expert Bundle extracted under: {_toolsDir}");

            ReclaimStaleProcesses();
            ReclaimOurPorts();

            WriteTorrc(bridges);
            RaiseState(TorState.Starting, "Launching tor.exe...");

            var psi = new ProcessStartInfo
            {
                FileName = TorExePath,
                Arguments = $"-f \"{_torrcPath}\"",
                WorkingDirectory = Path.GetDirectoryName(TorExePath)!,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            _proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            _proc.OutputDataReceived += (_, e) => ParseLogLine(e.Data);
            _proc.ErrorDataReceived += (_, e) => ParseLogLine(e.Data);
            _proc.Exited += (_, __) =>
            {
                if (!_disposing && !_stopping)
                {
                    RaiseState(TorState.Error, "tor.exe exited unexpectedly.");
                    UnexpectedExit?.Invoke(this, EventArgs.Empty);
                }
            };

            _proc.Start();
            _proc.BeginOutputReadLine();
            _proc.BeginErrorReadLine();

            // Death pact BEFORE anything else can crash us: from this point
            // on, our death (even Task Manager kill) takes tor + its
            // transports with it — no orphans, ever.
            CloseJob();
            _jobHandle = ProcessDeathPact.Assign(_proc);
            if (_jobHandle == IntPtr.Zero)
                RaiseState(TorState.Starting,
                    "Tor death-pact unavailable (sandboxed launch?) — stale-process sweep on next start remains as backstop.");

            RaiseState(TorState.Bootstrapping, "Waiting for Tor to bootstrap...");
        }

        void ParseLogLine(string? line)
        {
            if (string.IsNullOrWhiteSpace(line)) return;
            PushLogTail(line.Trim());

            var idx = line.IndexOf("Bootstrapped ", StringComparison.Ordinal);
            if (idx >= 0)
            {
                var rest = line[(idx + "Bootstrapped ".Length)..];
                var pctEnd = rest.IndexOf('%');
                if (pctEnd > 0 && int.TryParse(rest[..pctEnd], out var pct))
                {
                    var state = pct >= 100 ? TorState.Connected : TorState.Bootstrapping;
                    RaiseState(state, line.Trim(), pct);
                    return;
                }
            }

            if (line.Contains("[warn]") || line.Contains("[err]"))
            {
                RaiseState(TorState.Error, line.Trim());
            }
        }

        volatile bool _disposing;
        // Cross-thread stop flag: volatile so an in-flight Exited event can't misread a clean stop as a crash.
        volatile bool _stopping;

        // Rolling tail of tor's own stdout/stderr (1st-boot failures say WHY
        // here: port binds, missing files, guard/TLS issues). Shown in Config.
        readonly System.Collections.Concurrent.ConcurrentQueue<string> _logTail = new();
        const int LogTailCap = 300;

        void PushLogTail(string line)
        {
            try
            {
                _logTail.Enqueue(line);
                while (_logTail.Count > LogTailCap && _logTail.TryDequeue(out _)) { }
            }
            catch { }
        }

        public List<string> GetLogTail()
        {
            try { return _logTail.ToList(); }
            catch { return new List<string>(); }
        }

        public async Task StopAsync(bool gracefulShutdownRequested)
        {
            var proc = _proc;
            if (proc == null) return;
            _stopping = true; // first: quiet any in-flight Exited event
            _disposing = true;
            try
            {
                // Event-driven stop. When a graceful SHUTDOWN was requested via
                // control, the Exited handler below fires the moment tor dies:
                // an already-dead or fast-dying daemon returns instantly with
                // zero fixed grace sleeps. (CloseMainWindow is gone on purpose:
                // tor is a console process with no window, so that call was a
                // placebo burning 3s every stop.) Without a graceful request
                // nothing will make it exit on its own, so SIGKILL goes out
                // immediately instead of waiting on nothing.
                if (!SafeHasExited(proc))
                {
                    if (gracefulShutdownRequested)
                    {
                        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                        EventHandler? onExit = null;
                        onExit = (_, __) => { try { tcs.TrySetResult(true); } catch { } };
                        try { proc.Exited += onExit; } catch { }
                        try
                        {
                            // Re-check after subscribing: died in the race window.
                            if (!SafeHasExited(proc))
                            {
                                // Bounded fallback ONLY: a wedged daemon that
                                // ignores the SHUTDOWN still gets SIGKILLed.
                                // This timeout is a last resort, not a grace
                                // period — the event above is the real path.
                                var exited = await Task.WhenAny(tcs.Task, Task.Delay(8000)) == tcs.Task;
                                if (!exited)
                                    ExitTrace.Log("tor stop: no exit event in 8s, killing");
                                if (!exited || !SafeHasExited(proc))
                                {
                                    try { proc.Kill(entireProcessTree: true); } catch { }
                                    try { await Task.Run(() => proc.WaitForExit(5000)); } catch { }
                                    ExitTrace.Log("tor stop: kill waited, exited=" + SafeHasExited(proc));
                                }
                                else ExitTrace.Log("tor stop: exited gracefully");
                            }
                            else ExitTrace.Log("tor stop: already exited");
                        }
                        catch (Exception ex) { ExitTrace.Log("tor stop: " + ex.GetType().Name); }
                        finally { try { proc.Exited -= onExit; } catch { } }
                    }
                    else
                    {
                        try { proc.Kill(entireProcessTree: true); } catch { }
                        try { await Task.Run(() => proc.WaitForExit(5000)); } catch { }
                    }
                }
                else ExitTrace.Log("tor stop: already exited");
            }
            finally
            {
                try { proc.Dispose(); } catch { }
                if (ReferenceEquals(_proc, proc)) _proc = null;
                // tor is down: closing the pact handle reaps any stragglers
                // (transports) the tree-kill may have missed.
                CloseJob();
                RaiseState(TorState.Stopped, "Tor stopped.");
                _disposing = false;
                _stopping = false;
            }
        }

        static bool SafeHasExited(Process proc)
        {
            try { return proc.HasExited; }
            catch { return true; } // uninterrogable: treat as gone, disposal below still runs
        }

        void RaiseState(TorState state, string msg, int? pct = null) =>
            StateChanged?.Invoke(this, new TorStateChangedEventArgs { State = state, Message = msg, BootstrapPercent = pct });

        public void Dispose()
        {
            _stopping = true;
            _disposing = true;
            try { if (_proc != null && !_proc.HasExited) _proc.Kill(entireProcessTree: true); } catch { }
            try { _proc?.Dispose(); } catch { }
            _proc = null;
            CloseJob();
        }

        // Last-resort kill used by stop verification: the normal StopAsync
        // path should already have reaped the daemon; if it somehow survived
        // (wedged process, kill race), this makes sure nothing lingers to
        // hold ports or circuits after quit.
        public void ForceKill()
        {
            _stopping = true;
            _disposing = true;
            try
            {
                var p = _proc;
                _proc = null;
                if (p != null)
                {
                    try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { }
                    try { p.WaitForExit(5000); } catch { }
                    try { p.Dispose(); } catch { }
                }
                CloseJob();
                RaiseState(TorState.Stopped, "Tor force-stopped.");
            }
            catch { }
            finally
            {
                _disposing = false;
                _stopping = false;
            }
        }
    }
}
