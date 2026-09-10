using System;
using System.Collections.Generic;

namespace PTor
{

    // In-memory ad/track blocklist. Blocking is enforced 100% inside PTor's
    // own data path (DNS forwarder + SOCKS/HTTP relays + own HTTP client).
    // PTor NEVER reads-for-apply nor writes the OS hosts file.
    //
    // Hot path: IsBlocked runs per DNS query and per relayed connection, so
    // it allocates NOTHING on a lookup — span walking over the stored sets
    // (case-insensitive alternate lookup, no lowercase/trim/substring
    // temporaries). Sets are swap-replaced under a lock; lookups work on a
    // captured reference and never take the lock.
    public sealed class AdBlockStore
    {
        public static AdBlockStore Instance { get; } = new AdBlockStore();

        readonly object _gate = new();
        HashSet<string> _hosts = new(StringComparer.OrdinalIgnoreCase);
        // @@ allow-exceptions from the lists: most-specific match wins, so an
        // exception for ok.ads.com unblocks it (and its subdomains) even when
        // a parent like ads.com is blocked — same intent as EasyList.
        HashSet<string> _allowed = new(StringComparer.OrdinalIgnoreCase);

        public DateTime LastUpdatedUtc { get; private set; } = DateTime.MinValue;
        public int SourceFileCount { get; private set; }

        AdBlockStore() { }

        public void SetHosts(HashSet<string> hosts, int fileCount = 0, HashSet<string>? allowed = null)
        {
            lock (_gate)
            {
                _hosts = hosts != null
                    ? new HashSet<string>(hosts, StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                _allowed = allowed != null
                    ? new HashSet<string>(allowed, StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                SourceFileCount = fileCount;
                LastUpdatedUtc = DateTime.UtcNow;
            }
        }

        public void Clear()
        {
            lock (_gate)
            {
                _hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                _allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                SourceFileCount = 0;
            }
        }

        public int Count
        {
            get { lock (_gate) { return _hosts.Count; } }
        }

        // Exact host or any parent domain: "a.b.ads.com" matches "ads.com".
        public bool IsBlocked(string? host)
        {
            try
            {
                if (string.IsNullOrEmpty(host)) return false;
                HashSet<string> hosts, allowed;
                lock (_gate)
                {
                    hosts = _hosts;
                    allowed = _allowed;
                    if (hosts.Count == 0 && allowed.Count == 0) return false;
                }
                // Span normalize (no alloc): trim whitespace + one trailing
                // dot, matching the old Trim().TrimEnd('.') semantics.
                ReadOnlySpan<char> h = host.AsSpan().Trim();
                while (h.Length > 0 && h[h.Length - 1] == '.')
                    h = h.Slice(0, h.Length - 1);
                if (h.IsEmpty || h.Length > 253) return false;
                var blockLookup = hosts.GetAlternateLookup<ReadOnlySpan<char>>();
                var allowLookup = allowed.GetAlternateLookup<ReadOnlySpan<char>>();
                // Most-specific level first: exact allow beats parent block.
                while (true)
                {
                    if (allowLookup.Contains(h)) return false;
                    if (blockLookup.Contains(h)) return true;
                    var dot = h.IndexOf('.');
                    if (dot < 0) return false;
                    h = h.Slice(dot + 1);
                }
            }
            catch { return false; }
        }
    }
}
