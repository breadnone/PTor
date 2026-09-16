using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace PTor
{
    // Firefox (and Thunderbird) ignore the Windows certificate store by
    // default, so trusting PTor's local CA in CurrentUser\Root alone leaves
    // Firefox showing certificate errors on inspected sites. This helper
    // closes that gap automatically — no about:config trips, no manual
    // ca.crt imports:
    //
    // - EnableEnterpriseRoots: writes
    //     user_pref("security.enterprise_roots.enabled", true);
    //   into a user.js in every Firefox/Thunderbird profile of the current
    //   user (plus every local user when running elevated). user.js is used
    //   instead of prefs.js because Firefox rewrites prefs.js on exit and
    //   would silently drop a prefs.js edit made while it runs; user.js is
    //   re-applied on every start and never clobbered.
    // - DisableEnterpriseRoots: removes exactly the lines we added (the rest
    //   of the user's user.js is preserved byte-for-byte).
    //
    // All methods are best-effort and never throw: they return a human-
    // readable report for the status line / uninstall log.
    public static class FirefoxTrust
    {
        const string PrefName = "security.enterprise_roots.enabled";
        const string Marker = "PTor-local-CA";

        static string PrefLine() => $"user_pref(\"{PrefName}\", true); // {Marker}: trust Windows store (PTor inspection CA)";

        static bool IsOurLine(string line)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(line)) return false;
                return line.Contains(Marker, StringComparison.Ordinal)
                    || (line.Contains(PrefName, StringComparison.Ordinal)
                        && line.Contains("PTor", StringComparison.OrdinalIgnoreCase));
            }
            catch { return false; }
        }

        public sealed record ProfileDir(string Path, string Owner);

        // Every Firefox/Thunderbird profile dir for the CURRENT user, found
        // via profiles.ini (authoritative) plus a direct Profiles scan
        // (covers installs.ini/custom layouts the ini may miss).
        public static List<ProfileDir> FindCurrentUserProfiles()
        {
            var out_ = new List<ProfileDir>();
            try
            {
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                ScanAppProfiles(Path.Combine(appData, "Mozilla", "Firefox"), Environment.UserName, out_);
                ScanAppProfiles(Path.Combine(appData, "Thunderbird"), Environment.UserName, out_);
            }
            catch { }
            return out_.GroupBy(p => p.Path, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First()).ToList();
        }

        // All local users' profiles (admin only — used by uninstall). Never
        // throws; returns what it could see.
        public static List<ProfileDir> FindAllUsersProfiles()
        {
            var out_ = new List<ProfileDir>();
            try { out_.AddRange(FindCurrentUserProfiles()); } catch { }
            try
            {
                var users = Path.GetPathRoot(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
                var usersDir = Path.Combine(users ?? "C:\\", "Users");
                if (!Directory.Exists(usersDir)) return Dedupe(out_);
                foreach (var home in Directory.GetDirectories(usersDir))
                {
                    string owner;
                    try { owner = Path.GetFileName(home); } catch { continue; }
                    if (owner.Equals(Environment.UserName, StringComparison.OrdinalIgnoreCase))
                        continue; // already covered above
                    if (owner.StartsWith("All ", StringComparison.OrdinalIgnoreCase)
                        || owner.Equals("Public", StringComparison.OrdinalIgnoreCase)
                        || owner.Equals("Default", StringComparison.OrdinalIgnoreCase)
                        || owner.StartsWith("Default ", StringComparison.OrdinalIgnoreCase))
                        continue;
                    try
                    {
                        ScanAppProfiles(Path.Combine(home, "AppData", "Roaming", "Mozilla", "Firefox"), owner, out_);
                        ScanAppProfiles(Path.Combine(home, "AppData", "Roaming", "Thunderbird"), owner, out_);
                    }
                    catch { }
                }
            }
            catch { }
            return Dedupe(out_);
        }

        static List<ProfileDir> Dedupe(List<ProfileDir> list) =>
            list.GroupBy(p => p.Path, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First()).ToList();

        static void ScanAppProfiles(string appDir, string owner, List<ProfileDir> out_)
        {
            try
            {
                if (!Directory.Exists(appDir)) return;
                // profiles.ini first (handles custom locations).
                try
                {
                    var ini = Path.Combine(appDir, "profiles.ini");
                    if (File.Exists(ini))
                    {
                        var iniDir = Path.GetDirectoryName(ini) ?? appDir;
                        foreach (var p in ParseProfilesIni(ini, iniDir))
                            out_.Add(new ProfileDir(p, owner));
                    }
                    var installs = Path.Combine(appDir, "installs.ini");
                    if (File.Exists(installs))
                    {
                        var iniDir = Path.GetDirectoryName(installs) ?? appDir;
                        foreach (var p in ParseProfilesIni(installs, iniDir))
                            out_.Add(new ProfileDir(p, owner));
                    }
                }
                catch { }
                // Direct scan fallback.
                foreach (var cand in new[] { Path.Combine(appDir, "Profiles") })
                {
                    try
                    {
                        if (!Directory.Exists(cand)) continue;
                        foreach (var d in Directory.GetDirectories(cand))
                            out_.Add(new ProfileDir(d, owner));
                    }
                    catch { }
                }
            }
            catch { }
        }

        static List<string> ParseProfilesIni(string iniPath, string iniDir)
        {
            var out_ = new List<string>();
            try
            {
                var lines = File.ReadAllLines(iniPath);
                string? path = null;
                var isRelative = true;
                void Flush()
                {
                    try
                    {
                        if (string.IsNullOrWhiteSpace(path)) return;
                        var full = isRelative ? Path.Combine(iniDir, path) : path;
                        if (Directory.Exists(full)) out_.Add(full);
                    }
                    catch { }
                    finally { path = null; isRelative = true; }
                }
                foreach (var raw in lines)
                {
                    var line = raw.Trim();
                    if (line.StartsWith("[", StringComparison.Ordinal))
                    {
                        Flush();
                        continue;
                    }
                    var eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    var key = line.Substring(0, eq).Trim();
                    var val = line.Substring(eq + 1).Trim();
                    if (key.Equals("Path", StringComparison.OrdinalIgnoreCase)) path = val;
                    else if (key.Equals("IsRelative", StringComparison.OrdinalIgnoreCase))
                        isRelative = !val.Equals("0", StringComparison.Ordinal);
                }
                Flush();
            }
            catch { }
            return out_;
        }

        // Idempotent: existing PTor lines are replaced, everything else kept.
        // Returns true when the file now contains the pref. Internal for tests.
        internal static bool EnsureUserJs(string profileDir)
        {
            var userJs = Path.Combine(profileDir, "user.js");
            List<string> lines = new();
            try
            {
                if (File.Exists(userJs))
                {
                    var info = new FileInfo(userJs);
                    if (info.Length > 1024 * 1024) return false; // absurd: don't touch
                    lines = File.ReadAllLines(userJs).ToList();
                }
            }
            catch { return false; }
            try
            {
                var kept = lines.Where(l => !IsOurLine(l)).ToList();
                // Already enabled by the user themselves? Leave their line
                // alone and just report success — nothing to do.
                if (kept.Any(l => l.Contains(PrefName, StringComparison.Ordinal)))
                    return true;
                kept.Add(PrefLine());
                // Atomic: this is the USER's file — a torn user.js (crash
                // mid-write) breaks their Firefox prefs. Same-dir temp + move
                // leaves either the old or the new content, never a truncation.
                // createParent: false — a profile dir that isn't there must
                // not be conjured into existence (missing dir reads as false).
                if (!SafeFiles.WriteAllLinesAtomic(userJs, kept, createParent: false)) return false;
                return true;
            }
            catch { return false; }
        }

        // Removes only our lines; deletes user.js if we made it and nothing
        // else remains. Returns true when no PTor line remains. Internal for tests.
        internal static bool RemoveOurUserJs(string profileDir)
        {
            var userJs = Path.Combine(profileDir, "user.js");
            try
            {
                if (!File.Exists(userJs)) return true;
                var info = new FileInfo(userJs);
                if (info.Length > 1024 * 1024) return false;
                var lines = File.ReadAllLines(userJs).ToList();
                if (!lines.Any(IsOurLine)) return true;
                var kept = lines.Where(l => !IsOurLine(l)).ToList();
                if (kept.Count == 0)
                {
                    try { File.Delete(userJs); } catch { return false; }
                    return true;
                }
                // Atomic, same reason as above: never truncate the user's file.
                if (!SafeFiles.WriteAllLinesAtomic(userJs, kept, createParent: false)) return false;
                return true;
            }
            catch { return false; }
        }

        public static string EnableEnterpriseRoots()
        {
            try
            {
                var profiles = FindCurrentUserProfiles();
                if (profiles.Count == 0)
                    return "no Firefox/Thunderbird profiles found (nothing to configure — the CA still covers Chrome/Edge/system apps)";
                var ok = 0;
                foreach (var p in profiles)
                    try { if (EnsureUserJs(p.Path)) ok++; } catch { }
                return ok == profiles.Count
                    ? $"Firefox trust auto-enabled in {ok} profile(s) (security.enterprise_roots.enabled via user.js — takes effect on next browser start)"
                    : $"Firefox trust auto-enabled in {ok}/{profiles.Count} profile(s) (the rest need about:config → security.enterprise_roots.enabled = true)";
            }
            catch (Exception ex) { return "Firefox auto-config skipped (" + ex.Message + ")"; }
        }

        public static string DisableEnterpriseRoots()
        {
            try
            {
                var profiles = FindCurrentUserProfiles();
                var ok = 0;
                foreach (var p in profiles)
                    try { if (RemoveOurUserJs(p.Path)) ok++; } catch { }
                return $"Firefox auto-config removed from {ok}/{profiles.Count} profile(s)";
            }
            catch (Exception ex) { return "Firefox cleanup skipped (" + ex.Message + ")"; }
        }

        // Admin uninstall path: every local user's profiles.
        public static string DisableEnterpriseRootsAllUsers()
        {
            try
            {
                var profiles = FindAllUsersProfiles();
                var ok = 0;
                foreach (var p in profiles)
                    try { if (RemoveOurUserJs(p.Path)) ok++; } catch { }
                return $"Firefox auto-config removed from {ok}/{profiles.Count} profile(s) across all users";
            }
            catch (Exception ex) { return "all-users Firefox cleanup skipped (" + ex.Message + ")"; }
        }
    }
}
