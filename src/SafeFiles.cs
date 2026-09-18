using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PTor
{

    // Single choke point for every physical-file touch: capped reads and
    // atomic writes. Covers the whole edge-case family in one place —
    // missing/locked/growing files, absurd sizes (a planted 2GB
    // "settings.json" must not OOM us), directories passed as files, bad
    // chars, read-only destinations, and torn writes from a crash mid-save.
    // Every method is total: it returns a failure value, never throws.
    internal static class SafeFiles
    {
        // Bounded read: null when the path is unusable, the file is missing,
        // locked, a directory, bigger than maxBytes, or grows past the cap
        // between the size check and the read (TOCTOU re-verified on the
        // decoded text: UTF-8 chars never outnumber source bytes).
        public static string? ReadAllTextCapped(string? path, long maxBytes)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || maxBytes <= 0) return null;
                string full;
                try { full = Path.GetFullPath(path); }
                catch { return null; }
                try
                {
                    var len = new FileInfo(full).Length;
                    if (len < 0 || len > maxBytes) return null;
                }
                catch { return null; }
                string text;
                try { text = File.ReadAllText(full); }
                catch { return null; }
                try { if (text == null || text.Length > maxBytes) return null; }
                catch { return null; }
                return text;
            }
            catch { return null; }
        }

        // Byte twin of the above (cookie, pfx). Same total contract.
        public static byte[]? ReadAllBytesCapped(string? path, long maxBytes)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || maxBytes <= 0) return null;
                string full;
                try { full = Path.GetFullPath(path); }
                catch { return null; }
                try
                {
                    var len = new FileInfo(full).Length;
                    if (len < 0 || len > maxBytes) return null;
                }
                catch { return null; }
                byte[] bytes;
                try { bytes = File.ReadAllBytes(full); }
                catch { return null; }
                try { if (bytes == null || bytes.LongLength > maxBytes) return null; }
                catch { return null; }
                return bytes;
            }
            catch { return null; }
        }

        // Crash-atomic text write: same-dir temp + overwrite move, so a kill
        // mid-save leaves the previous good file, never a truncation. Creates
        // the parent dir unless createParent is false (foreign dirs, e.g. a
        // Firefox profile that isn't there, must never be conjured into
        // existence); clears a read-only destination best-effort; always
        // cleans its own temp. True on success, false on any failure (caller
        // keeps old state — which is still valid).
        public static bool WriteAllTextAtomic(string? path, string content, bool createParent = true)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || content == null) return false;
                string full;
                try { full = Path.GetFullPath(path); }
                catch { return false; }
                try
                {
                    var dir = Path.GetDirectoryName(full);
                    if (createParent && !string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                }
                catch { return false; }
                var tmp = full + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    File.WriteAllText(tmp, content, new UTF8Encoding(false));
                    ClearReadOnly(full);
                    File.Move(tmp, full, overwrite: true);
                    return true;
                }
                catch { return false; }
                finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
            }
            catch { return false; }
        }

        public static bool WriteAllBytesAtomic(string? path, byte[] bytes, bool createParent = true)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || bytes == null) return false;
                string full;
                try { full = Path.GetFullPath(path); }
                catch { return false; }
                try
                {
                    var dir = Path.GetDirectoryName(full);
                    if (createParent && !string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                }
                catch { return false; }
                var tmp = full + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    File.WriteAllBytes(tmp, bytes);
                    ClearReadOnly(full);
                    File.Move(tmp, full, overwrite: true);
                    return true;
                }
                catch { return false; }
                finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
            }
            catch { return false; }
        }

        // Same encoding as File.WriteAllLines (UTF-8, no BOM).
        public static bool WriteAllLinesAtomic(string? path, IEnumerable<string> lines, bool createParent = true)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || lines == null) return false;
                string full;
                try { full = Path.GetFullPath(path); }
                catch { return false; }
                try
                {
                    var dir = Path.GetDirectoryName(full);
                    if (createParent && !string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                }
                catch { return false; }
                var tmp = full + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    File.WriteAllLines(tmp, lines, new UTF8Encoding(false));
                    ClearReadOnly(full);
                    File.Move(tmp, full, overwrite: true);
                    return true;
                }
                catch { return false; }
                finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
            }
            catch { return false; }
        }

        static void ClearReadOnly(string full)
        {
            try
            {
                if (File.Exists(full) && (File.GetAttributes(full) & FileAttributes.ReadOnly) != 0)
                    File.SetAttributes(full, FileAttributes.Normal);
            }
            catch { }
        }
    }
}
