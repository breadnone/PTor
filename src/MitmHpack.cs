using System;
using System.Collections.Generic;
using System.Text;

namespace PTor
{
    // HPACK (RFC 7541) for HTTP/2 inspection. BCL-only, no new dependencies.
    //
    // Decoder: FULL (indexed, all literal forms, Huffman with the static
    // table from Appendix B, dynamic table with eviction). Strict and
    // fail-closed: any malformed input throws HpackException (the relay
    // maps it to COMPRESSION_ERROR and tears the connection down — never
    // a silent misdecode).
    // Encoder: minimal but compliant — indexed exact static matches,
    // literal-without-indexing otherwise (static-name or new name), plain
    // (non-Huffman) strings, never touches the dynamic table. Sensitive
    // fields (cookie/authorization/set-cookie, or peer-marked
    // never-indexed) are re-encoded never-indexed per RFC 7541 §6.2.3.
    public sealed class HpackException : Exception
    {
        public HpackException(string message) : base(message) { }
    }

    public readonly record struct HpackField(string Name, string Value, bool Sensitive);

    public static class HpackStaticTable
    {
        public static readonly (string Name, string Value)[] Entries =
        {
            ("", ""), // 0: unused placeholder so C# index == RFC index
            (":authority", ""), (":method", "GET"), (":method", "POST"),
            (":path", "/"), (":path", "/index.html"),
            (":scheme", "http"), (":scheme", "https"),
            (":status", "200"), (":status", "204"), (":status", "206"),
            (":status", "304"), (":status", "400"), (":status", "404"),
            (":status", "500"),
            ("accept-charset", ""), ("accept-encoding", "gzip, deflate"),
            ("accept-language", ""), ("accept-ranges", ""), ("accept", ""),
            ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
            ("authorization", ""), ("cache-control", ""), ("content-disposition", ""),
            ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
            ("content-location", ""), ("content-range", ""), ("content-type", ""),
            ("cookie", ""), ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""),
            ("from", ""), ("host", ""), ("if-match", ""), ("if-modified-since", ""),
            ("if-none-match", ""), ("if-range", ""), ("if-unmodified-since", ""),
            ("last-modified", ""), ("link", ""), ("location", ""), ("max-forwards", ""),
            ("proxy-authenticate", ""), ("proxy-authorization", ""), ("range", ""),
            ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
            ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
            ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
        };

        public const int Count = 61;

        public static int FindExact(string name, string value)
        {
            for (var i = 1; i <= Count; i++)
                if (Entries[i].Name == name && Entries[i].Value == value)
                    return i;
            return -1;
        }

        public static int FindName(string name)
        {
            for (var i = 1; i <= Count; i++)
                if (Entries[i].Name == name)
                    return i;
            return -1;
        }
    }

    // Static Huffman table, RFC 7541 Appendix B: (symbol, code, bit length).
    // Transcribed from the authoritative text; validated at startup by
    // Kraft-sum == 1 (complete prefix code) and a conflict-free tree build.
    // Public for test cross-checks against the RFC text (see harness).
    public static class HpackHuffmanTable
    {
        public static readonly (int Sym, uint Code, int Bits)[] Rows =
        {
            (0, 0x1ff8, 13), (1, 0x7fffd8, 23), (2, 0xfffffe2, 28), (3, 0xfffffe3, 28),
            (4, 0xfffffe4, 28), (5, 0xfffffe5, 28), (6, 0xfffffe6, 28), (7, 0xfffffe7, 28),
            (8, 0xfffffe8, 28), (9, 0xffffea, 24), (10, 0x3ffffffc, 30), (11, 0xfffffe9, 28),
            (12, 0xfffffea, 28), (13, 0x3ffffffd, 30), (14, 0xfffffeb, 28), (15, 0xfffffec, 28),
            (16, 0xfffffed, 28), (17, 0xfffffee, 28), (18, 0xfffffef, 28), (19, 0xffffff0, 28),
            (20, 0xffffff1, 28), (21, 0xffffff2, 28), (22, 0x3ffffffe, 30), (23, 0xffffff3, 28),
            (24, 0xffffff4, 28), (25, 0xffffff5, 28), (26, 0xffffff6, 28), (27, 0xffffff7, 28),
            (28, 0xffffff8, 28), (29, 0xffffff9, 28), (30, 0xffffffa, 28), (31, 0xfffffffb, 28),
            (32, 0x14, 6), (33, 0x3f8, 10), (34, 0x3f9, 10), (35, 0xffa, 12),
            (36, 0x1ff9, 13), (37, 0x15, 6), (38, 0xf8, 8), (39, 0x7fa, 11),
            (40, 0x3fa, 10), (41, 0x3fb, 10), (42, 0xf9, 8), (43, 0x7fb, 11),
            (44, 0xfa, 8), (45, 0x16, 6), (46, 0x17, 6), (47, 0x18, 6),
            (48, 0x0, 5), (49, 0x1, 5), (50, 0x2, 5), (51, 0x19, 6),
            (52, 0x1a, 6), (53, 0x1b, 6), (54, 0x1c, 6), (55, 0x1d, 6),
            (56, 0x1e, 6), (57, 0x1f, 6), (58, 0x5c, 7), (59, 0xfb, 8),
            (60, 0x7ffc, 15), (61, 0x20, 6), (62, 0xffb, 12), (63, 0x3fc, 10),
            (64, 0x1ffa, 13), (65, 0x21, 6), (66, 0x5d, 7), (67, 0x5e, 7),
            (68, 0x5f, 7), (69, 0x60, 7), (70, 0x61, 7), (71, 0x62, 7),
            (72, 0x63, 7), (73, 0x64, 7), (74, 0x65, 7), (75, 0x66, 7),
            (76, 0x67, 7), (77, 0x68, 7), (78, 0x69, 7), (79, 0x6a, 7),
            (80, 0x6b, 7), (81, 0x6c, 7), (82, 0x6d, 7), (83, 0x6e, 7),
            (84, 0x6f, 7), (85, 0x70, 7), (86, 0x71, 7), (87, 0x72, 7),
            (88, 0xfc, 8), (89, 0x73, 7), (90, 0xfd, 8), (91, 0x1ffb, 13),
            (92, 0x7fff0, 19), (93, 0x1ffc, 13), (94, 0x3ffc, 14), (95, 0x22, 6),
            (96, 0x7ffd, 15), (97, 0x3, 5), (98, 0x23, 6), (99, 0x4, 5),
            (100, 0x24, 6), (101, 0x5, 5), (102, 0x25, 6), (103, 0x26, 6),
            (104, 0x27, 6), (105, 0x6, 5), (106, 0x74, 7), (107, 0x75, 7),
            (108, 0x28, 6), (109, 0x29, 6), (110, 0x2a, 6), (111, 0x7, 5),
            (112, 0x2b, 6), (113, 0x76, 7), (114, 0x2c, 6), (115, 0x8, 5),
            (116, 0x9, 5), (117, 0x2d, 6), (118, 0x77, 7), (119, 0x78, 7),
            (120, 0x79, 7), (121, 0x7a, 7), (122, 0x7b, 7), (123, 0x7ffe, 15),
            (124, 0x7fc, 11), (125, 0x3ffd, 14), (126, 0x1ffd, 13), (127, 0xffffffc, 28),
            (128, 0xfffe6, 20), (129, 0x3fffd2, 22), (130, 0xfffe7, 20), (131, 0xfffe8, 20),
            (132, 0x3fffd3, 22), (133, 0x3fffd4, 22), (134, 0x3fffd5, 22), (135, 0x7fffd9, 23),
            (136, 0x3fffd6, 22), (137, 0x7fffda, 23), (138, 0x7fffdb, 23), (139, 0x7fffdc, 23),
            (140, 0x7fffdd, 23), (141, 0x7fffde, 23), (142, 0xffffeb, 24), (143, 0x7fffdf, 23),
            (144, 0xffffec, 24), (145, 0xffffed, 24), (146, 0x3fffd7, 22), (147, 0x7fffe0, 23),
            (148, 0xffffee, 24), (149, 0x7fffe1, 23), (150, 0x7fffe2, 23), (151, 0x7fffe3, 23),
            (152, 0x7fffe4, 23), (153, 0x1fffdc, 21), (154, 0x3fffd8, 22), (155, 0x7fffe5, 23),
            (156, 0x3fffd9, 22), (157, 0x7fffe6, 23), (158, 0x7fffe7, 23), (159, 0xffffef, 24),
            (160, 0x3fffda, 22), (161, 0x1fffdd, 21), (162, 0xfffe9, 20), (163, 0x3fffdb, 22),
            (164, 0x3fffdc, 22), (165, 0x7fffe8, 23), (166, 0x7fffe9, 23), (167, 0x1fffde, 21),
            (168, 0x7fffea, 23), (169, 0x3fffdd, 22), (170, 0x3fffde, 22), (171, 0xfffff0, 24),
            (172, 0x1fffdf, 21), (173, 0x3fffdf, 22), (174, 0x7fffeb, 23), (175, 0x7fffec, 23),
            (176, 0x1fffe0, 21), (177, 0x1fffe1, 21), (178, 0x3fffe0, 22), (179, 0x1fffe2, 21),
            (180, 0x7fffed, 23), (181, 0x3fffe1, 22), (182, 0x7fffee, 23), (183, 0x7fffef, 23),
            (184, 0xfffea, 20), (185, 0x3fffe2, 22), (186, 0x3fffe3, 22), (187, 0x3fffe4, 22),
            (188, 0x7ffff0, 23), (189, 0x3fffe5, 22), (190, 0x3fffe6, 22), (191, 0x7ffff1, 23),
            (192, 0x3ffffe0, 26), (193, 0x3ffffe1, 26), (194, 0xfffeb, 20), (195, 0x7fff1, 19),
            (196, 0x3fffe7, 22), (197, 0x7ffff2, 23), (198, 0x3fffe8, 22), (199, 0x1ffffec, 25),
            (200, 0x3ffffe2, 26), (201, 0x3ffffe3, 26), (202, 0x3ffffe4, 26), (203, 0x7ffffde, 27),
            (204, 0x7ffffdf, 27), (205, 0x3ffffe5, 26), (206, 0xfffff1, 24), (207, 0x1ffffed, 25),
            (208, 0x7fff2, 19), (209, 0x1fffe3, 21), (210, 0x3ffffe6, 26), (211, 0x7ffffe0, 27),
            (212, 0x7ffffe1, 27), (213, 0x3ffffe7, 26), (214, 0x7ffffe2, 27), (215, 0xfffff2, 24),
            (216, 0x1fffe4, 21), (217, 0x1fffe5, 21), (218, 0x3ffffe8, 26), (219, 0x3ffffe9, 26),
            (220, 0xffffffd, 28), (221, 0x7ffffe3, 27), (222, 0x7ffffe4, 27), (223, 0x7ffffe5, 27),
            (224, 0xfffec, 20), (225, 0xfffff3, 24), (226, 0xfffed, 20), (227, 0x1fffe6, 21),
            (228, 0x3fffe9, 22), (229, 0x1fffe7, 21), (230, 0x1fffe8, 21), (231, 0x7ffff3, 23),
            (232, 0x3fffea, 22), (233, 0x3fffeb, 22), (234, 0x1ffffee, 25), (235, 0x1ffffef, 25),
            (236, 0xfffff4, 24), (237, 0xfffff5, 24), (238, 0x3ffffea, 26), (239, 0x7ffff4, 23),
            (240, 0x3ffffeb, 26), (241, 0x7ffffe6, 27), (242, 0x3ffffec, 26), (243, 0x3ffffed, 26),
            (244, 0x7ffffe7, 27), (245, 0x7ffffe8, 27), (246, 0x7ffffe9, 27), (247, 0x7ffffea, 27),
            (248, 0x7ffffeb, 27), (249, 0xffffffe, 28), (250, 0x7ffffec, 27), (251, 0x7ffffed, 27),
            (252, 0x7ffffee, 27), (253, 0x7ffffef, 27), (254, 0x7fffff0, 27), (255, 0x3ffffee, 26),
            (256, 0x3fffffff, 30),
        };

        sealed class Node
        {
            public int Symbol = -1;
            public Node? Zero;
            public Node? One;
        }

        static readonly Node Root = BuildAndValidate();

        static Node BuildAndValidate()
        {
            var root = new Node();
            // Kraft sum over 2^30: a complete prefix code sums to exactly 2^30.
            long kraft = 0;
            foreach (var (sym, code, bits) in Rows)
            {
                if (bits < 1 || bits > 30)
                    throw new HpackException("Bad Huffman table: bit length out of range.");
                kraft += 1L << (30 - bits);
                var node = root;
                for (var i = bits - 1; i >= 0; i--)
                {
                    var bit = (code >> i) & 1;
                    if (i == 0)
                    {
                        if (bit == 0)
                        {
                            if (node.Zero != null) throw new HpackException("Bad Huffman table: duplicate code.");
                            node.Zero = new Node { Symbol = sym };
                        }
                        else
                        {
                            if (node.One != null) throw new HpackException("Bad Huffman table: duplicate code.");
                            node.One = new Node { Symbol = sym };
                        }
                    }
                    else
                    {
                        if (bit == 0) node = node.Zero ??= new Node();
                        else node = node.One ??= new Node();
                        if (node.Symbol >= 0)
                            throw new HpackException("Bad Huffman table: code is a prefix of another.");
                    }
                }
            }
            if (Rows.Length != 257)
                throw new HpackException("Bad Huffman table: expected 257 rows.");
            if (kraft != (1L << 30))
                throw new HpackException("Bad Huffman table: Kraft sum mismatch.");
            return root;
        }

        public static byte[] Decode(ReadOnlySpan<byte> data)
        {
            var out_ = new List<byte>(data.Length * 2);
            var node = Root;
            int pending = 0;
            foreach (var b in data)
            {
                for (var i = 7; i >= 0; i--)
                {
                    var bit = (b >> i) & 1;
                    node = bit == 0 ? node.Zero : node.One;
                    if (node == null)
                        throw new HpackException("Invalid Huffman encoding.");
                    pending++;
                    if (node.Symbol >= 0)
                    {
                        if (node.Symbol == 256)
                            throw new HpackException("Huffman EOS in string.");
                        out_.Add((byte)node.Symbol);
                        node = Root;
                        pending = 0;
                    }
                }
            }
            // Trailing bits are padding: at most 7, all ones (EOS prefix).
            if (pending > 0)
            {
                if (pending > 7)
                    throw new HpackException("Huffman padding too long.");
                // Re-walk the pending bits to confirm they are all 1s: the
                // decoder only reaches a non-root node via the actual bits,
                // so verify by checking the last `pending` bits of input.
                var last = data[data.Length - 1];
                var mask = (1 << pending) - 1;
                if ((last & mask) != mask)
                    throw new HpackException("Huffman padding not EOS bits.");
            }
            return out_.ToArray();
        }
    }

    public static class HpackInteger
    {
        public const long MaxValue = 16 * 1024 * 1024;
        const int MaxOctets = 10;

        public static void Encode(List<byte> dst, long value, int prefixBits, byte firstByteMask)
        {
            var maxFirst = (1 << prefixBits) - 1;
            if (value < maxFirst)
            {
                dst.Add((byte)(firstByteMask | value));
                return;
            }
            dst.Add((byte)(firstByteMask | maxFirst));
            value -= maxFirst;
            while (value >= 128)
            {
                dst.Add((byte)((value % 128) + 128));
                value /= 128;
            }
            dst.Add((byte)value);
        }

        public static long Decode(ReadOnlySpan<byte> data, ref int pos, int prefixBits)
        {
            if (prefixBits < 1 || prefixBits > 8)
                throw new HpackException("Bad integer prefix.");
            if (pos >= data.Length)
                throw new HpackException("Truncated integer.");
            var maxFirst = (1 << prefixBits) - 1;
            long value = data[pos] & maxFirst;
            pos++;
            if (value < maxFirst) return value;
            long m = 0;
            var octets = 0;
            while (true)
            {
                if (pos >= data.Length)
                    throw new HpackException("Truncated integer continuation.");
                if (++octets > MaxOctets)
                    throw new HpackException("Integer too long.");
                var b = data[pos++];
                checked
                {
                    value += (long)(b & 127) << (int)m;
                }
                if (value > MaxValue)
                    throw new HpackException("Integer too large.");
                if ((b & 128) == 0) return value;
                m += 7;
                if (m > 60)
                    throw new HpackException("Integer too large.");
            }
        }
    }

    public sealed class HpackDecoder
    {
        const int MaxFieldBytes = 64 * 1024;
        const int MaxListBytes = 256 * 1024;

        readonly List<(byte[] Name, byte[] Value)> _dynamic = new();
        int _dynamicSize;
        int _maxTableSize;
        readonly int _protocolLimit;

        public HpackDecoder(int protocolLimit = 4096)
        {
            _protocolLimit = protocolLimit;
            _maxTableSize = Math.Min(4096, protocolLimit);
        }

        public int MaxTableSize => _maxTableSize;

        public void SetProtocolLimit(int n)
        {
            // Peer lowered SETTINGS_HEADER_TABLE_SIZE: shrink decoder max.
            if (n < _maxTableSize)
            {
                _maxTableSize = Math.Max(0, n);
                EvictToFit(0);
            }
        }

        void EvictToFit(int extra)
        {
            while (_dynamic.Count > 0 && _dynamicSize + extra > _maxTableSize)
            {
                var last = _dynamic[_dynamic.Count - 1];
                _dynamicSize -= last.Name.Length + last.Value.Length + 32;
                _dynamic.RemoveAt(_dynamic.Count - 1);
            }
            if (_dynamicSize < 0) _dynamicSize = 0;
        }

        void InsertDynamic(byte[] name, byte[] value)
        {
            var size = name.Length + value.Length + 32;
            if (size > _maxTableSize)
            {
                _dynamic.Clear();
                _dynamicSize = 0;
                return;
            }
            EvictToFit(size);
            _dynamic.Insert(0, (name, value));
            _dynamicSize += size;
        }

        (byte[] Name, byte[] Value) Lookup(int index)
        {
            if (index <= 0)
                throw new HpackException("Index 0 is forbidden.");
            if (index <= HpackStaticTable.Count)
                return (Encoding.Latin1.GetBytes(HpackStaticTable.Entries[index].Name),
                        Encoding.Latin1.GetBytes(HpackStaticTable.Entries[index].Value));
            var dyn = index - HpackStaticTable.Count - 1;
            if (dyn < 0 || dyn >= _dynamic.Count)
                throw new HpackException("Index beyond table.");
            return _dynamic[dyn];
        }

        static byte[] DecodeString(ReadOnlySpan<byte> data, ref int pos)
        {
            if (pos >= data.Length)
                throw new HpackException("Truncated string.");
            var huffman = (data[pos] & 0x80) != 0;
            var len = (int)HpackInteger.Decode(data, ref pos, 7);
            if (len < 0 || len > MaxFieldBytes)
                throw new HpackException("String too long.");
            if (pos + len > data.Length)
                throw new HpackException("Truncated string data.");
            var raw = data.Slice(pos, len).ToArray();
            pos += len;
            return huffman ? HpackHuffmanTable.Decode(raw) : raw;
        }

        public List<HpackField> DecodeHeaderBlock(byte[] block, int offset, int count)
        {
            var fields = new List<HpackField>();
            long listBytes = 0;
            var data = new ReadOnlySpan<byte>(block, offset, count);
            var pos = 0;
            while (pos < data.Length)
            {
                var b = data[pos];
                if ((b & 0x80) != 0)
                {
                    var index = (int)HpackInteger.Decode(data, ref pos, 7);
                    var (n, v) = Lookup(index);
                    fields.Add(ToField(n, v, false, ref listBytes));
                }
                else if ((b & 0xC0) == 0x40)
                {
                    var index = (int)HpackInteger.Decode(data, ref pos, 6);
                    byte[] name = index == 0 ? DecodeString(data, ref pos) : Lookup(index).Name;
                    var value = DecodeString(data, ref pos);
                    InsertDynamic(name, value);
                    fields.Add(ToField(name, value, false, ref listBytes));
                }
                else if ((b & 0xE0) == 0x20)
                {
                    var max = (int)HpackInteger.Decode(data, ref pos, 5);
                    if (max > _protocolLimit)
                        throw new HpackException("Table size update exceeds limit.");
                    _maxTableSize = max;
                    EvictToFit(0);
                }
                else
                {
                    var never = (b & 0xF0) == 0x10;
                    var index = (int)HpackInteger.Decode(data, ref pos, 4);
                    byte[] name = index == 0 ? DecodeString(data, ref pos) : Lookup(index).Name;
                    var value = DecodeString(data, ref pos);
                    fields.Add(ToField(name, value, never, ref listBytes));
                }
                if (listBytes > MaxListBytes)
                    throw new HpackException("Header list too large.");
            }
            return fields;
        }

        static HpackField ToField(byte[] name, byte[] value, bool sensitive, ref long listBytes)
        {
            if (name.Length == 0 || name.Length > 8192 || value.Length > MaxFieldBytes)
                throw new HpackException("Bad field size.");
            foreach (var c in name)
            {
                if (c >= 'A' && c <= 'Z')
                    throw new HpackException("Uppercase header name.");
                if (c == 0 || c == 0x7F || c < 0x20)
                    throw new HpackException("Control char in header name.");
            }
            var n = Encoding.Latin1.GetString(name);
            var v = Encoding.Latin1.GetString(value);
            listBytes += name.Length + value.Length;
            return new HpackField(n, v, sensitive);
        }
    }

    public static class HpackEncoder
    {
        static void WriteString(List<byte> dst, string latin1)
        {
            var raw = Encoding.Latin1.GetBytes(latin1);
            if (raw.Length > 65536)
                throw new HpackException("Field too large to encode.");
            HpackInteger.Encode(dst, raw.Length, 7, 0x00); // H=0: plain
            dst.AddRange(raw);
        }

        // sensitive=true forces never-indexed form (RFC 7541 §6.2.3), used
        // for cookie/authorization-style values and for peer-marked fields.
        public static byte[] EncodeFields(IList<HpackField> fields)
        {
            var dst = new List<byte>(fields.Count * 32);
            foreach (var f in fields)
            {
                var exact = HpackStaticTable.FindExact(f.Name, f.Value);
                if (exact > 0 && !f.Sensitive)
                {
                    HpackInteger.Encode(dst, exact, 7, 0x80);
                    continue;
                }
                var nameIdx = HpackStaticTable.FindName(f.Name);
                HpackInteger.Encode(dst, nameIdx < 0 ? 0 : nameIdx, 4, f.Sensitive ? (byte)0x10 : (byte)0x00);
                if (nameIdx < 0) WriteString(dst, f.Name);
                WriteString(dst, f.Value);
            }
            return dst.ToArray();
        }

        public static bool IsSensitiveName(string name) =>
            name.Equals("cookie", StringComparison.OrdinalIgnoreCase)
            || name.Equals("cookie2", StringComparison.OrdinalIgnoreCase)
            || name.Equals("authorization", StringComparison.OrdinalIgnoreCase)
            || name.Equals("proxy-authorization", StringComparison.OrdinalIgnoreCase)
            || name.Equals("set-cookie", StringComparison.OrdinalIgnoreCase)
            || name.Equals("set-cookie2", StringComparison.OrdinalIgnoreCase);
    }
}
