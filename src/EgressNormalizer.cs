using System;
using System.Runtime.InteropServices;

namespace PTor
{

    // Pins IPv4 TTL / IPv6 Hop Limit on Tor-attested outbound TCP against
    // guard-side OS fingerprinting. Caller scopes (TCP/Tor/outbound only);
    // never throws (false = leave the packet alone).
    // IPv4 needs an IP-checksum fixup (TCP checksum excludes TTL); IPv6 needs
    // none (no header checksum; Hop Limit outside the TCP pseudo-header).
    public static class EgressNormalizer
    {
        public const byte TargetTtl = 64;

        public static bool TryNormalizeTtl(IntPtr pkt, int len, bool v6, byte proto, byte targetTtl = TargetTtl)
        {
            try
            {
                if (pkt == IntPtr.Zero) return false;
                if (proto != 6) return false; // TCP only
                if (!v6)
                {
                    if (len < 20) return false;
                    var b0 = Marshal.ReadByte(pkt, 0);
                    if ((b0 >> 4) != 4) return false;
                    var ihl = (b0 & 0xF) * 4;
                    if (ihl < 20 || len < ihl) return false;
                    if (Marshal.ReadByte(pkt, 8) == targetTtl) return false;
                    Marshal.WriteByte(pkt, 8, targetTtl);
                    Marshal.WriteByte(pkt, 10, 0);
                    Marshal.WriteByte(pkt, 11, 0);
                    var c = IpHeaderChecksum(pkt, ihl);
                    Marshal.WriteByte(pkt, 10, (byte)(c >> 8));
                    Marshal.WriteByte(pkt, 11, (byte)(c & 0xFF));
                    return true;
                }
                else
                {
                    if (len < 40) return false;
                    if ((Marshal.ReadByte(pkt, 0) >> 4) != 6) return false;
                    if (Marshal.ReadByte(pkt, 7) == targetTtl) return false;
                    Marshal.WriteByte(pkt, 7, targetTtl);
                    return true;
                }
            }
            catch { return false; }
        }

        public static ushort IpHeaderChecksum(IntPtr header, int headerLength)
        {
            uint sum = 0;
            var i = 0;
            for (; i + 1 < headerLength; i += 2)
                sum += (uint)((Marshal.ReadByte(header, i) << 8) | Marshal.ReadByte(header, i + 1));
            if (i < headerLength)
                sum += (uint)(Marshal.ReadByte(header, i) << 8);
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }
    }
}
