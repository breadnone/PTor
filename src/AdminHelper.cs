using System;
using System.Diagnostics;
using System.Security.Principal;

namespace PTor
{

    public class NeedAdminException : InvalidOperationException
    {
        public NeedAdminException(string message) : base(message) { }
    }

    static class AdminHelper
    {
        public static bool IsAdministrator()
        {
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        public static void RestartElevated(string extraArgs = "")
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe))
            {
                try { exe = Process.GetCurrentProcess().MainModule?.FileName; } catch { }
            }
            if (string.IsNullOrEmpty(exe))
                throw new InvalidOperationException("Could not locate own executable for elevation.");
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = extraArgs ?? "",
                UseShellExecute = true,
                Verb = "runas"
            };
            try
            {
                using var p = Process.Start(psi);
                if (p == null) throw new InvalidOperationException("Elevated launch returned nothing.");
            }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                throw new OperationCanceledException("Elevation declined at the UAC prompt.", ex);
            }
        }
    }
}
