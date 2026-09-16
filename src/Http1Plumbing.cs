using System;
using System.Buffers;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{
    // Shared HTTP/1.1 framing primitives for the inspection paths.
    // Single implementation used by the plain-HTTP bridge filter, the
    // decrypted h1 loop, and both H1/H2 translators — one place to fix.
    static class Http1Plumbing
    {
        // Reads one HTTP/1.x header block: decoded text + any bytes already
        // read past the terminator (forwarded verbatim by the caller).
        // Pooled chunk, byte-level terminator scan, 64 KB cap. Empty text =
        // peer closed, oversize block, or garbage without a terminator:
        // fail-closed (callers drop the connection) — a truncated block must
        // never be returned as complete and forwarded malformed.
        public static async Task<(string text, byte[] extra)> ReadHeadersAsync(Stream stream, CancellationToken ct)
        {
            var chunk = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                using var ms = new MemoryStream();
                while (true)
                {
                    int read;
                    try { read = await stream.ReadAsync(chunk.AsMemory(0, 8192), ct); }
                    catch (OperationCanceledException) { throw; }
                    catch { break; }
                    if (read <= 0) break;
                    ms.Write(chunk, 0, read);
                    if (ms.Length > 64 * 1024) break;
                    if (FindHeaderEnd(ms) is int end)
                    {
                        var buf = ms.GetBuffer();
                        var text = Encoding.Latin1.GetString(buf, 0, end);
                        var extraLen = (int)ms.Length - end;
                        var extra = Array.Empty<byte>();
                        if (extraLen > 0)
                        {
                            extra = new byte[extraLen];
                            Buffer.BlockCopy(buf, end, extra, 0, extraLen);
                        }
                        return (text, extra);
                    }
                }
                return ("", Array.Empty<byte>());
            }
            finally { ArrayPool<byte>.Shared.Return(chunk); }
        }

        // Index just past the first \r\n\r\n, or null. Byte scan: no decode.
        static int? FindHeaderEnd(MemoryStream ms)
        {
            try
            {
                var buf = ms.GetBuffer();
                var len = (int)ms.Length;
                for (var i = 0; i + 3 < len; i++)
                {
                    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
                        return i + 4;
                }
                return null;
            }
            catch { return null; }
        }

        // Interim 1xx (100 Continue, 102, 103…): not the final response.
        // 101 Switching Protocols is deliberately NOT interim here — it IS
        // the final headers of an upgrade the pump must carry verbatim.
        public static bool IsInterim1xx(string[] lines)
        {
            try
            {
                if (lines == null || lines.Length == 0) return false;
                var first = lines[0] ?? "";
                var sp = first.Split(' ');
                if (sp.Length < 2) return false;
                if (!sp[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)) return false;
                if (sp[1].Length != 3 || sp[1][0] != '1') return false;
                if (!int.TryParse(sp[1], out var code)) return false;
                return code is >= 100 and <= 199 && code != 101;
            }
            catch { return false; }
        }

        // True when a REQUEST carries a body per its framing headers
        // (chunked or positive Content-Length).
        public static bool RequestHasBody(string[] lines)
        {
            try
            {
                var te = ContentFilter.GetHeaderValue(lines, "Transfer-Encoding") ?? "";
                if (te.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0) return true;
                var cl = ContentFilter.GetHeaderValue(lines, "Content-Length");
                return cl != null && long.TryParse(cl.Trim(), out var len) && len > 0;
            }
            catch { return false; }
        }

        public static async Task<bool> TryReadExactAsync(Stream s, byte[] buffer, CancellationToken ct)
        {
            var off = 0;
            while (off < buffer.Length)
            {
                int n;
                try { n = await s.ReadAsync(buffer.AsMemory(off, buffer.Length - off), ct); }
                catch (OperationCanceledException) { throw; }
                catch { return false; }
                if (n <= 0) return false;
                off += n;
            }
            return true;
        }
    }
}
