using System;
using System.IO;

namespace PTor
{

    // Shutdown/exit tracer: timestamped append-only log of every exit and
    // stop milestone. If the app ever hangs on exit again, this file says
    // exactly which step stuck instead of leaving silence. Best-effort and
    // silent: logging must never break the path it observes.
    static class ExitTrace
    {
        static readonly object _gate = new();

        public static void Log(string msg)
        {
            try
            {
                lock (_gate)
                {
                    var dir = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PTor");
                    Directory.CreateDirectory(dir);
                    var path = Path.Combine(dir, "exit-trace.log");
                    try
                    {
                        if (new FileInfo(path).Length > 200 * 1024)
                        {
                            File.Delete(path);
                            File.AppendAllText(path, $"[{DateTime.Now:HH:mm:ss.fff}] log rotated (was >200KB)\n");
                        }
                    }
                    catch { }
                    File.AppendAllText(path,
                        $"[{DateTime.Now:HH:mm:ss.fff}] [tid {Environment.CurrentManagedThreadId}] {msg}\n");
                }
            }
            catch { }
        }
    }
}
