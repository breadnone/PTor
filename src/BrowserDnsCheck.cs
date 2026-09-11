using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PTor
{

    public record BrowserDnsNote(string Browser, string Detail, bool Bad);

    // Read-only Secure-DNS (DoH) readout. Explains the classic split where
    // Edge works but Firefox doesn't: Edge/Chrome default to automatic (they
    // fall back when Tor's DNS can't do DoH), while Firefox enables DoH by
    // default in several regions. DoH bypasses Tor DNS (privacy leak) without
    // lockdown, and breaks page loads entirely under lockdown (direct DoH is
    // dropped by design — point the browser at the proxy with Secure DNS off
    // instead). Never writes anything.
    public static class BrowserDnsCheck
    {
        static readonly Regex FirefoxTrrRx = new(
            @"user_pref\(""network\.trr\.mode"",\s*(\d+)\)",
            RegexOptions.Compiled, TimeSpan.FromSeconds(2));

        public static List<BrowserDnsNote> Run()
        {
            var out_ = new List<BrowserDnsNote>();
            try { out_.AddRange(CheckFirefox()); } catch { }
            try { out_.AddRange(CheckChromium("Edge", "Microsoft", "Edge")); } catch { }
            try { out_.AddRange(CheckChromium("Chrome", "Google", "Chrome")); } catch { }
            if (out_.Count == 0)
                out_.Add(new BrowserDnsNote("Browsers", "no Firefox/Edge/Chrome profiles found", false));
            return out_;
        }

        static List<BrowserDnsNote> CheckFirefox()
        {
            var out_ = new List<BrowserDnsNote>();
            string profiles;
            try
            {
                profiles = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Mozilla", "Firefox", "Profiles");
                if (!Directory.Exists(profiles)) return out_;
            }
            catch { return out_; }
            string[] dirs;
            try { dirs = Directory.GetDirectories(profiles); }
            catch { return out_; }
            foreach (var dir in dirs)
            {
                if (out_.Count >= 24) break;
                string name;
                try { name = Path.GetFileName(dir); }
                catch { continue; }
                string prefs;
                try { prefs = Path.Combine(dir, "prefs.js"); if (!File.Exists(prefs)) continue; }
                catch { continue; }
                string text;
                try
                {
                    var info = new FileInfo(prefs);
                    if (info.Length > 4 * 1024 * 1024) continue;
                    text = File.ReadAllText(prefs);
                }
                catch { out_.Add(new BrowserDnsNote("Firefox (" + name + ")", "prefs unreadable", false)); continue; }
                int mode = -1;
                try
                {
                    var m = FirefoxTrrRx.Match(text);
                    if (m.Success) mode = int.Parse(m.Groups[1].Value);
                }
                catch { }
                out_.Add(mode switch
                {
                    -1 => new BrowserDnsNote("Firefox (" + name + ")", "Secure DNS off (default) — OK", false),
                    0 or 5 => new BrowserDnsNote("Firefox (" + name + ")", "Secure DNS off — OK", false),
                    1 => new BrowserDnsNote("Firefox (" + name + ")", "Secure DNS race-mode — falls back, OK", false),
                    4 => new BrowserDnsNote("Firefox (" + name + ")", "Secure DNS shadow-mode — OK", false),
                    2 => new BrowserDnsNote("Firefox (" + name + ")", "Secure DNS TRR-first — bypasses Tor DNS; BREAKS under lockdown (turn Secure DNS off)", true),
                    _ => new BrowserDnsNote("Firefox (" + name + ")", "Secure DNS TRR-only — BREAKS under lockdown (turn Secure DNS off)", true),
                });
            }
            return out_;
        }

        static List<BrowserDnsNote> CheckChromium(string browser, string vendor, string product)
        {
            var out_ = new List<BrowserDnsNote>();
            string userData;
            try
            {
                userData = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    vendor, product, "User Data");
                if (!Directory.Exists(userData)) return out_;
            }
            catch { return out_; }
            string[] dirs;
            try { dirs = Directory.GetDirectories(userData); }
            catch { return out_; }
            foreach (var dir in dirs)
            {
                if (out_.Count >= 24) break;
                string name;
                try { name = Path.GetFileName(dir); }
                catch { continue; }
                if (!name.Equals("Default", StringComparison.OrdinalIgnoreCase) &&
                    !name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
                    continue;
                string prefs;
                try { prefs = Path.Combine(dir, "Preferences"); if (!File.Exists(prefs)) continue; }
                catch { continue; }
                string mode = "";
                bool unreadable = false;
                try
                {
                    if (new FileInfo(prefs).Length > 16 * 1024 * 1024) continue;
                    using var doc = JsonDocument.Parse(File.ReadAllText(prefs));
                    if (doc.RootElement.TryGetProperty("dns_over_https", out var doh) &&
                        doh.ValueKind == JsonValueKind.Object &&
                        doh.TryGetProperty("mode", out var m) &&
                        m.ValueKind == JsonValueKind.String)
                        mode = (m.GetString() ?? "").Trim().ToLowerInvariant();
                }
                catch { unreadable = true; }
                if (unreadable)
                {
                    out_.Add(new BrowserDnsNote(browser + " (" + name + ")", "settings unreadable (browser running?)", false));
                    continue;
                }
                out_.Add(mode switch
                {
                    "secure" => new BrowserDnsNote(browser + " (" + name + ")",
                        "Secure DNS FORCED — bypasses Tor DNS; BREAKS under lockdown (set to automatic/off)", true),
                    _ => new BrowserDnsNote(browser + " (" + name + ")",
                        string.IsNullOrEmpty(mode) ? "Secure DNS automatic/off — OK (falls back)" : $"Secure DNS '{mode}' — OK", false),
                });
            }
            return out_;
        }
    }
}
