using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{
    // HTTP/2 inspection relay (RFC 9113) plus H1/H2 translators.
    //
    // Modes (chosen by ALPN on the two TLS legs — each leg always uses its
    // own best protocol, never a forced downgrade):
    // - H2H2: full-duplex filtered relay, 1:1 stream mapping (same IDs).
    // - H2H1: multiplexed h2 client -> one plain h1 origin connection PER
    //   REQUEST (each with own SOCKS dial + TLS + validation). Slightly
    //   more handshakes in this corner, but trivially correct: no
    //   cross-stream state, no head-of-line blocking, full concurrency.
    // - H1H2: sequential h1 client -> one shared h2 origin session, one
    //   transaction at a time (h1 clients are sequential by nature).
    //
    // Filtering mirrors the HTTP/1.1 policy exactly (BlockJS / WebRTC /
    // cookies / CSP), reusing ContentFilter through a string[]-lines
    // adapter so the two stacks can never drift apart.
    // Fail-closed throughout: any malformed frame/HPACK/pseudo-header tears
    // the whole tunnel down (connection error), never a silent bypass.

    public sealed class MitmSessionOptions
    {
        public bool BlockJs;
        public bool BlockWebRtc;
        public bool BlockCookies;
        public string SpoofHost = "";
        public string ConnectHost = "";
        public int ConnectPort;
        public string TlsTarget = "";
        public Action<string, int, string, string>? OnRelayed;
        // Per-request origin dial for translators (TCP via Tor).
        public Func<string, int, CancellationToken, Task<TcpClient?>>? SocksDial;
        // Origin TLS + validation (+OCSP gate). False = fail closed.
        public Func<SslStream, string, CancellationToken, Task<bool>>? AuthenticateUpstream;
        // Manual user blocklist (live provider; null = no list). Checked on
        // every request/response leg, HTTP/2 and HTTP/1.1 alike.
        public Func<string[]>? BlockedDomains;

        public bool IsBlocked(string? host)
        {
            try
            {
                var p = BlockedDomains;
                if (p == null) return false;
                string[] list;
                try { list = p(); } catch { return false; }
                return ContentFilter.IsBlockedDomain(host, list);
            }
            catch { return false; }
        }

        public void Relay(string mode)
        {
            try { OnRelayed?.Invoke(ConnectHost, ConnectPort, mode, TlsTarget); }
            catch { }
        }
    }

    static class H2Lines
    {
        public static string[] RequestToLines(string method, string path, string authority, List<HpackField> regular)
        {
            var lines = new List<string>(regular.Count + 3) { $"{method} {path} HTTP/2", "Host: " + authority };
            foreach (var h in regular) lines.Add(h.Name + ": " + h.Value);
            lines.Add("");
            return lines.ToArray();
        }

        public static string[] ResponseToLines(string status, List<HpackField> regular)
        {
            var lines = new List<string>(regular.Count + 2) { "HTTP/2 " + status + " " };
            foreach (var h in regular) lines.Add(h.Name + ": " + h.Value);
            lines.Add("");
            return lines.ToArray();
        }

        public static List<HpackField> FieldsFromLines(string[] lines, Dictionary<string, bool>? wasSensitive)
        {
            var out_ = new List<HpackField>();
            var end = Array.IndexOf(lines, "");
            if (end < 0) end = lines.Length;
            for (var i = 1; i < end; i++)
            {
                var line = lines[i];
                var colon = line.IndexOf(':');
                if (colon <= 0) continue;
                var name = line.Substring(0, colon).Trim().ToLowerInvariant();
                // Proxy hop-by-hop credentials must never reach origins (or
                // re-enter H2 where IsConnectionSpecific would kill the
                // stream): strip defense-in-depth alongside host/connection.
                if (name == "host" || name == "connection" || name == "keep-alive"
                    || name == "proxy-authorization" || name == "proxy-authenticate"
                    || name == "proxy-connection") continue;
                var value = line.Substring(colon + 1).Trim();
                var sens = HpackEncoder.IsSensitiveName(name)
                    || (wasSensitive != null && wasSensitive.TryGetValue(name, out var s) && s);
                out_.Add(new HpackField(name, value, sens));
            }
            return out_;
        }

        public static Dictionary<string, bool> SensitiveMap(List<HpackField> fields)
        {
            var m = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (var f in fields)
                if (!m.ContainsKey(f.Name)) m[f.Name] = f.Sensitive;
            return m;
        }
    }

    static class H2Pseudo
    {
        public sealed class Request
        {
            public string Method = "";
            public string Scheme = "";
            public string Path = "";
            public string Authority = "";
            public string? Protocol;
            public List<HpackField> Headers = new();
            public Dictionary<string, bool> WasSensitive = new(StringComparer.OrdinalIgnoreCase);
        }

        public sealed class Response
        {
            public string Status = "";
            public List<HpackField> Headers = new();
            public Dictionary<string, bool> WasSensitive = new(StringComparer.OrdinalIgnoreCase);
        }

        static bool IsConnectionSpecific(string name) =>
            name == "connection" || name == "keep-alive" || name == "proxy-authenticate"
            || name == "proxy-authorization" || name == "proxy-connection"
            || name == "transfer-encoding" || name == "upgrade";

        // Throws Http2Exception (PROTOCOL_ERROR) on any malformed request.
        public static Request ParseRequest(List<HpackField> fields)
        {
            var r = new Request();
            string? method = null, scheme = null, path = null, authority = null, protocol = null;
            var seenPseudo = false;
            var pseudoDone = false;
            foreach (var f in fields)
            {
                if (f.Name.Length == 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Empty header name.");
                if (f.Name[0] == ':')
                {
                    if (pseudoDone) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Pseudo after regular.");
                    seenPseudo = true;
                    switch (f.Name)
                    {
                        case ":method": if (method != null) throw Dup(); method = f.Value; break;
                        case ":scheme": if (scheme != null) throw Dup(); scheme = f.Value; break;
                        case ":path": if (path != null) throw Dup(); path = f.Value; break;
                        case ":authority": if (authority != null) throw Dup(); authority = f.Value; break;
                        case ":protocol": if (protocol != null) throw Dup(); protocol = f.Value; break;
                        default: throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Unknown pseudo-header.");
                    }
                }
                else
                {
                    pseudoDone = true;
                    if (IsConnectionSpecific(f.Name))
                        throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Connection-specific header in h2.");
                    if (f.Name == "te" && !f.Value.Trim().Equals("trailers", StringComparison.OrdinalIgnoreCase))
                        throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad TE in h2.");
                    r.Headers.Add(f);
                    if (!r.WasSensitive.ContainsKey(f.Name)) r.WasSensitive[f.Name] = f.Sensitive;
                }
            }
            if (!seenPseudo || method == null)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Missing pseudo-headers.");
            if (protocol != null)
            {
                // Extended CONNECT (RFC 8441): only WebSocket tunnels through.
                if (!method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase) || authority == null)
                    throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad extended CONNECT.");
                if (!protocol.Equals("websocket", StringComparison.OrdinalIgnoreCase))
                    throw new Http2Exception(Http2Const.REFUSED_STREAM, "Unsupported extended-CONNECT protocol.");
                r.Method = method; r.Authority = authority; r.Protocol = protocol;
                r.Scheme = scheme ?? "https"; r.Path = path ?? "/";
                return r;
            }
            if (scheme == null || path == null || authority == null)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Missing request pseudo-header.");
            if (!scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
                && !scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad :scheme.");
            if (path.Length == 0)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Empty :path.");
            r.Method = method; r.Scheme = scheme; r.Path = path; r.Authority = authority;
            return r;
        }

        static Http2Exception Dup() => new(Http2Const.PROTOCOL_ERROR, "Duplicate pseudo-header.");

        // Throws Http2Exception on malformed responses.
        public static Response ParseResponse(List<HpackField> fields)
        {
            var r = new Response();
            string? status = null;
            var pseudoDone = false;
            foreach (var f in fields)
            {
                if (f.Name.Length == 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Empty header name.");
                if (f.Name[0] == ':')
                {
                    if (pseudoDone) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Pseudo after regular.");
                    if (!f.Name.Equals(":status", StringComparison.Ordinal))
                        throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad response pseudo-header.");
                    if (status != null) throw Dup();
                    status = f.Value;
                }
                else
                {
                    pseudoDone = true;
                    if (IsConnectionSpecific(f.Name))
                        throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Connection-specific header in h2 response.");
                    r.Headers.Add(f);
                    if (!r.WasSensitive.ContainsKey(f.Name)) r.WasSensitive[f.Name] = f.Sensitive;
                }
            }
            if (status == null || status.Length != 3)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Missing :status.");
            if (!int.TryParse(status, out _))
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad :status.");
            if (status == "101")
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "101 in h2.");
            r.Status = status;
            return r;
        }
    }

    // h2 <-> h1 header translation (RFC 9113 §8.3-8.4).
    static class H2Translator
    {
        public static List<HpackField> RequestToH2(string method, string path, string authority, string[] h1Lines)
        {
            var fields = new List<HpackField>
            {
                new(":method", method, false),
                new(":scheme", "https", false),
                new(":path", path, false),
                new(":authority", authority, false),
            };
            var end = Array.IndexOf(h1Lines, "");
            if (end < 0) end = h1Lines.Length;
            for (var i = 1; i < end; i++)
            {
                var line = h1Lines[i];
                var colon = line.IndexOf(':');
                if (colon <= 0) continue;
                var name = line.Substring(0, colon).Trim().ToLowerInvariant();
                // Never forward proxy credentials to origins via H2 (would
                // leak to the exit and trip IsConnectionSpecific downstream).
                if (name == "host" || name == "connection" || name == "keep-alive"
                    || name == "proxy-authorization" || name == "proxy-authenticate"
                    || name == "proxy-connection" || name == "transfer-encoding"
                    || name == "upgrade" || name == "expect") continue;
                fields.Add(new HpackField(name, line.Substring(colon + 1).Trim(), HpackEncoder.IsSensitiveName(name)));
            }
            return fields;
        }
    }

    public static class MitmHttp2Relay
    {
        const int MaxStreams = 100;
        const int MaxHeaderBlock = 256 * 1024;

        // ---- session setup (shared by relay + translators) ----

        static byte[] OurSettings()
        {
            var b = new List<byte>();
            void Put(ushort id, uint v)
            {
                b.Add((byte)(id >> 8)); b.Add((byte)id);
                b.Add((byte)(v >> 24)); b.Add((byte)(v >> 16)); b.Add((byte)(v >> 8)); b.Add((byte)v);
            }
            Put(Http2Const.SETTINGS_HEADER_TABLE_SIZE, 4096);
            Put(Http2Const.SETTINGS_ENABLE_PUSH, 0);
            Put(Http2Const.SETTINGS_MAX_CONCURRENT_STREAMS, MaxStreams);
            Put(Http2Const.SETTINGS_INITIAL_WINDOW_SIZE, Http2Const.DefaultWindow);
            Put(Http2Const.SETTINGS_MAX_FRAME_SIZE, Http2Const.DefaultMaxFrame);
            return b.ToArray();
        }

        // Server side: validate client preface + first SETTINGS, send ours.
        public static async Task<Http2Leg> AcceptClientAsync(Stream transport, CancellationToken ct)
        {
            var magic = new byte[Http2Const.Preface.Length];
            if (!await Http2FrameCodec.TryReadExactAsync(transport, magic, ct))
                throw new Http2Exception(Http2Const.NO_ERROR, "EOF in client preface.");
            for (var i = 0; i < magic.Length; i++)
                if (magic[i] != Http2Const.Preface[i])
                    throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad client preface.");
            var leg = new Http2Leg(transport, isUpstream: false);
            await leg.WriteFrameAsync(Http2Const.SETTINGS, 0, 0, OurSettings(), ct);
            var first = await Http2FrameCodec.ReadFrameAsync(transport, ct);
            if (first.Type != Http2Const.SETTINGS || first.StreamId != 0 || (first.Flags & Http2Const.FLAG_ACK) != 0)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "First client frame must be SETTINGS.");
            leg.ApplyPeerSettings(first.Payload);
            await leg.SendSettingsAckAsync(ct);
            return leg;
        }

        // Client side: send preface + settings, read server SETTINGS.
        public static async Task<Http2Leg> OpenUpstreamAsync(Stream transport, CancellationToken ct)
        {
            var leg = new Http2Leg(transport, isUpstream: true);
            await transport.WriteAsync(Http2Const.Preface, ct);
            await leg.WriteFrameAsync(Http2Const.SETTINGS, 0, 0, OurSettings(), ct);
            var first = await Http2FrameCodec.ReadFrameAsync(transport, ct);
            if (first.Type != Http2Const.SETTINGS || first.StreamId != 0 || (first.Flags & Http2Const.FLAG_ACK) != 0)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "First origin frame must be SETTINGS.");
            leg.ApplyPeerSettings(first.Payload);
            await leg.SendSettingsAckAsync(ct);
            return leg;
        }

        // ---- H2H2 filtered relay ----

        sealed class StreamPair
        {
            public bool ReqEnded;      // client END_STREAM seen
            public bool ReqSent;       // request HEADERS forwarded upstream
            public bool RespFinal;     // final (non-1xx) response HEADERS seen
            public bool RespEnded;     // upstream END_STREAM seen
            public bool Blocked;       // locally answered (synthetic); drop upstream rest
            public bool WsTunnel;      // extended-CONNECT websocket: DATA pumps opaquely
        }

        public static async Task RunAsync(Stream clientT, Stream upstreamT, MitmSessionOptions opt, CancellationToken ct)
        {
            var client = await AcceptClientAsync(clientT, ct);
            var up = await OpenUpstreamAsync(upstreamT, ct);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var lct = cts.Token;
            var pairs = new ConcurrentDictionary<int, StreamPair>();
            try
            {
                var t1 = PumpAsync(client, up, fromClient: true, pairs, opt, lct);
                var t2 = PumpAsync(up, client, fromClient: false, pairs, opt, lct);
                await Task.WhenAny(t1, t2);
            }
            catch (Http2Exception hex)
            {
                await SendGoAwayBothAsync(client, up, hex.ErrorCode);
            }
            catch (OperationCanceledException) { throw; }
            catch { await SendGoAwayBothAsync(client, up, Http2Const.INTERNAL_ERROR); }
            finally
            {
                try { cts.Cancel(); } catch { }
                client.Dispose();
                up.Dispose();
            }
            opt.Relay("MITM-H2");
        }

        static async Task SendGoAwayBothAsync(Http2Leg a, Http2Leg b, uint code)
        {
            try { await a.SendGoAwayAsync(a.MaxSeenStreamId, code, CancellationToken.None); } catch { }
            try { await b.SendGoAwayAsync(b.MaxSeenStreamId, code, CancellationToken.None); } catch { }
        }

        sealed class HeaderAssembly
        {
            public int StreamId = -1;
            public bool PendingEndStream;
            public readonly MemoryStream Buf = new();

            public void Reset()
            {
                StreamId = -1;
                PendingEndStream = false;
                Buf.SetLength(0);
            }
        }

        static async Task PumpAsync(Http2Leg src, Http2Leg dst, bool fromClient,
            ConcurrentDictionary<int, StreamPair> pairs, MitmSessionOptions opt, CancellationToken ct)
        {
            var asm = new HeaderAssembly();
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var f = await Http2FrameCodec.ReadFrameAsync(src.Transport, ct, src.PeerMaxFrameSize);
                switch (f.Type)
                {
                    case Http2Const.SETTINGS:
                        if (f.StreamId != 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "SETTINGS on stream.");
                        if ((f.Flags & Http2Const.FLAG_ACK) != 0) break;
                        src.ApplyPeerSettings(f.Payload);
                        await src.SendSettingsAckAsync(ct);
                        break;
                    case Http2Const.PING:
                        if (f.StreamId != 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "PING on stream.");
                        if ((f.Flags & Http2Const.FLAG_ACK) != 0) break;
                        if (f.Payload.Length != 8) throw new Http2Exception(Http2Const.FRAME_SIZE_ERROR, "Bad PING.");
                        await src.SendPingAckAsync(f.Payload, ct);
                        break;
                    case Http2Const.WINDOW_UPDATE:
                        if (f.Payload.Length != 4) throw new Http2Exception(Http2Const.FRAME_SIZE_ERROR, "Bad WINDOW_UPDATE.");
                        ValidateStreamForWindowUpdate(src, f.StreamId);
                        src.OnWindowUpdate(f.StreamId, (f.Payload[0] << 24) | (f.Payload[1] << 16) | (f.Payload[2] << 8) | f.Payload[3]);
                        break;
                    case Http2Const.PRIORITY:
                        break; // deprecated; ignored
                    case Http2Const.RST_STREAM:
                        if (f.Payload.Length != 4) throw new Http2Exception(Http2Const.FRAME_SIZE_ERROR, "Bad RST_STREAM.");
                        if (f.StreamId == 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "RST on stream 0.");
                        if (src.GetStreamState(f.StreamId) == Http2StreamState.Idle)
                            throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "RST on idle stream.");
                        pairs.TryRemove(f.StreamId, out _);
                        src.NoteStream(f.StreamId, Http2StreamState.Closed);
                        if (dst.GetStreamState(f.StreamId) != Http2StreamState.Closed
                            && dst.GetStreamState(f.StreamId) != Http2StreamState.Idle)
                        {
                            var code = (uint)((f.Payload[0] << 24) | (f.Payload[1] << 16) | (f.Payload[2] << 8) | f.Payload[3]);
                            await dst.SendRstAsync(f.StreamId, code, ct);
                        }
                        break;
                    case Http2Const.GOAWAY:
                        try
                        {
                            var lastId = f.Payload.Length >= 4
                                ? ((f.Payload[0] << 24) | (f.Payload[1] << 16) | (f.Payload[2] << 8) | f.Payload[3]) & Http2Const.MaxStreamId
                                : 0;
                            _ = lastId;
                            await dst.SendGoAwayAsync(dst.MaxSeenStreamId, Http2Const.NO_ERROR, ct);
                        }
                        catch { }
                        return;
                    case Http2Const.PUSH_PROMISE:
                        throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "PUSH_PROMISE not supported.");
                    case Http2Const.DATA:
                        await HandleDataAsync(src, dst, fromClient, pairs, opt, f, ct);
                        break;
                    case Http2Const.HEADERS:
                        await HandleHeadersAsync(src, dst, fromClient, pairs, opt, f, asm, ct);
                        break;
                    case Http2Const.CONTINUATION:
                        if (asm.StreamId != f.StreamId)
                            throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Stray CONTINUATION.");
                        asm.Buf.Write(f.Payload, 0, f.Payload.Length);
                        if (asm.Buf.Length > MaxHeaderBlock)
                            throw new Http2Exception(Http2Const.COMPRESSION_ERROR, "Header block too large.");
                        if ((f.Flags & Http2Const.FLAG_END_HEADERS) != 0)
                        {
                            var streamId = asm.StreamId;
                            var endStream = asm.PendingEndStream || (f.Flags & Http2Const.FLAG_END_STREAM) != 0;
                            var block = asm.Buf.ToArray();
                            asm.Reset();
                            await ProcessHeaderBlockAsync(src, dst, fromClient, pairs, opt, streamId,
                                endStream, block, ct);
                        }
                        break;
                    default:
                        break; // unknown extension frames are ignored
                }
                try { await src.FlushWindowUpdatesAsync(ct); } catch { }
            }
        }

        static void ValidateStreamForWindowUpdate(Http2Leg leg, int streamId)
        {
            if (streamId == 0) return;
            var st = leg.GetStreamState(streamId);
            if (st == Http2StreamState.Idle)
            {
                if (streamId <= leg.MaxSeenStreamId) return; // late update for closed stream: ignore
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "WINDOW_UPDATE on idle stream.");
            }
        }

        static (byte[] Data, bool EndStream) Unpad(Http2Frame f)
        {
            var payload = f.Payload;
            var off = 0;
            if ((f.Flags & Http2Const.FLAG_PADDED) != 0)
            {
                if (payload.Length == 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad padding.");
                var padLen = payload[0];
                if (padLen >= payload.Length) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad padding length.");
                off = 1;
                return (payload[off..(payload.Length - padLen)], (f.Flags & Http2Const.FLAG_END_STREAM) != 0);
            }
            return (payload, (f.Flags & Http2Const.FLAG_END_STREAM) != 0);
        }

        static async Task HandleDataAsync(Http2Leg src, Http2Leg dst, bool fromClient,
            ConcurrentDictionary<int, StreamPair> pairs, MitmSessionOptions opt, Http2Frame f, CancellationToken ct)
        {
            if (f.StreamId == 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "DATA on stream 0.");
            var srcState = src.GetStreamState(f.StreamId);
            if (srcState == Http2StreamState.Idle)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "DATA on idle stream.");
            if (srcState == Http2StreamState.Closed
                || srcState == (fromClient ? Http2StreamState.HalfClosedRemote : Http2StreamState.HalfClosedLocal))
            {
                // Ended or closed: answer STREAM_CLOSED, drop (except races
                // on locally-blocked streams, which stay silent).
                if (!pairs.TryGetValue(f.StreamId, out var p0) || !p0.Blocked)
                {
                    try { await src.SendRstAsync(f.StreamId, Http2Const.STREAM_CLOSED, ct); } catch { }
                }
                return;
            }
            if (!pairs.TryGetValue(f.StreamId, out var pair))
            {
                // No relay record (e.g. refused earlier): drop after accounting.
                if (f.Payload.Length > 0) src.OnDataReceived(f.StreamId, DataLen(f));
                return;
            }
            if (pair.Blocked) return; // post-block race: drop silently
            var (data, endStream) = Unpad(f);
            if (data.Length > 0) src.OnDataReceived(f.StreamId, data.Length);
            dst.EnsureSendStream(f.StreamId);
            await dst.WriteDataAsync(f.StreamId, data, 0, data.Length, endStream, ct);
            if (fromClient) pair.ReqEnded |= endStream;
            else pair.RespEnded |= endStream;
            if (endStream)
            {
                src.NoteStream(f.StreamId,
                    fromClient ? Http2StreamState.HalfClosedRemote : Http2StreamState.HalfClosedLocal);
                dst.NoteStream(f.StreamId,
                    fromClient ? Http2StreamState.HalfClosedRemote : Http2StreamState.HalfClosedLocal);
                MaybeRetire(pairs, src, dst, f.StreamId);
            }
            opt.Relay("MITM-H2");
        }

        static int DataLen(Http2Frame f)
        {
            var len = f.Payload.Length;
            if ((f.Flags & Http2Const.FLAG_PADDED) != 0 && len > 0)
                len -= 1 + f.Payload[0];
            return Math.Max(0, len);
        }

        static void MaybeRetire(ConcurrentDictionary<int, StreamPair> pairs,
            Http2Leg legA, Http2Leg legB, int streamId)
        {
            // Fully closed in both directions -> forget (IDs never repeat)
            // and release the concurrency slot on BOTH legs.
            if (!pairs.TryGetValue(streamId, out var p)) return;
            if (p.ReqEnded && p.RespEnded)
            {
                pairs.TryRemove(streamId, out _);
                legA.NoteStream(streamId, Http2StreamState.Closed);
                legB.NoteStream(streamId, Http2StreamState.Closed);
            }
        }

        static async Task HandleHeadersAsync(Http2Leg src, Http2Leg dst, bool fromClient,
            ConcurrentDictionary<int, StreamPair> pairs, MitmSessionOptions opt,
            Http2Frame f, HeaderAssembly asm, CancellationToken ct)
        {
            if (f.StreamId == 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "HEADERS on stream 0.");
            byte[] frag = f.Payload;
            var off = 0;
            if ((f.Flags & Http2Const.FLAG_PADDED) != 0)
            {
                if (frag.Length == 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad HEADERS padding.");
                var padLen = frag[0];
                if (padLen >= frag.Length) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad HEADERS pad length.");
                frag = frag[1..(frag.Length - padLen)];
            }
            if ((f.Flags & Http2Const.FLAG_PRIORITY) != 0)
            {
                if (frag.Length < 5) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad HEADERS priority.");
                off = 5;
            }
            var body = frag[off..];
            if (asm.StreamId >= 0)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "HEADERS during CONTINUATION.");
            if ((f.Flags & Http2Const.FLAG_END_HEADERS) != 0)
            {
                await ProcessHeaderBlockAsync(src, dst, fromClient, pairs, opt, f.StreamId,
                    (f.Flags & Http2Const.FLAG_END_STREAM) != 0, body, ct);
            }
            else
            {
                asm.StreamId = f.StreamId;
                asm.Buf.SetLength(0);
                asm.Buf.Write(body, 0, body.Length);
                // END_STREAM with CONTINUATION pending is legal; the flag is
                // honored when the block completes (holder below).
                asm.PendingEndStream = (f.Flags & Http2Const.FLAG_END_STREAM) != 0;
            }
        }

        static async Task ProcessHeaderBlockAsync(Http2Leg src, Http2Leg dst, bool fromClient,
            ConcurrentDictionary<int, StreamPair> pairs, MitmSessionOptions opt,
            int streamId, bool endStream, byte[] block, CancellationToken ct)
        {
            List<HpackField> fields;
            try { fields = src.Hpack.DecodeHeaderBlock(block, 0, block.Length); }
            catch (HpackException hex) { throw new Http2Exception(Http2Const.COMPRESSION_ERROR, hex.Message); }

            var knownPair = pairs.TryGetValue(streamId, out var pair);
            if (fromClient)
            {
                if (!knownPair)
                {
                    // New request stream.
                    if (streamId % 2 == 0)
                        throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Client opened even stream.");
                    if (streamId <= src.MaxSeenStreamId)
                        throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Reused stream id.");
                    if (src.OpenStreamCount >= MaxStreams)
                    {
                        await src.SendRstAsync(streamId, Http2Const.REFUSED_STREAM, ct);
                        return;
                    }
                    var req = H2Pseudo.ParseRequest(fields);
                    await HandleNewRequestAsync(src, dst, pairs, opt, streamId, endStream, req, ct);
                }
                else
                {
                    // Trailers (must end the stream) or error.
                    if (pair!.ReqEnded)
                        throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "HEADERS after request end.");
                    if (!endStream)
                        throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Non-ending trailers.");
                    if (pair.Blocked) { pair.ReqEnded = true; return; }
                    var fwd = FilterTrailerFields(fields);
                    dst.EnsureSendStream(streamId);
                    await dst.WriteHeadersAsync(streamId, fwd, endStream: true, ct);
                    pair.ReqEnded = true;
                    src.NoteStream(streamId, Http2StreamState.HalfClosedRemote);
                    dst.NoteStream(streamId, Http2StreamState.HalfClosedRemote);
                    MaybeRetire(pairs, src, dst, streamId);
                }
            }
            else
            {
                // Origin side: responses only, on relay-created streams.
                if (streamId % 2 == 0 || !knownPair)
                    throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Unexpected origin HEADERS.");
                if (pair!.Blocked) return; // post-block race: drop
                if (pair.RespFinal)
                {
                    // Response trailers (must end the stream).
                    if (!endStream)
                        throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Non-ending response trailers.");
                    foreach (var tf in fields)
                        if (tf.Name.Length == 0 || tf.Name[0] == ':')
                            throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Pseudo in trailers.");
                    var fwdT = FilterTrailerFields(fields);
                    dst.EnsureSendStream(streamId);
                    await dst.WriteHeadersAsync(streamId, fwdT, endStream: true, ct);
                    pair.RespEnded = true;
                    src.NoteStream(streamId, Http2StreamState.HalfClosedLocal);
                    dst.NoteStream(streamId, Http2StreamState.HalfClosedLocal);
                    MaybeRetire(pairs, src, dst, streamId);
                    return;
                }
                var resp = H2Pseudo.ParseResponse(fields);
                await HandleResponseAsync(src, dst, pairs, opt, streamId, endStream, resp, pair, ct);
            }
        }

        static List<HpackField> FilterTrailerFields(List<HpackField> fields)
        {
            var out_ = new List<HpackField>(fields.Count);
            foreach (var f in fields)
            {
                if (f.Name.Length == 0 || f.Name[0] == ':') continue;
                if (f.Name == "cookie" || f.Name == "cookie2" || f.Name == "set-cookie" || f.Name == "set-cookie2"
                    || f.Name == "content-length" || f.Name == "transfer-encoding" || f.Name == "te"
                    || f.Name == "connection" || f.Name == "expect" || f.Name == "host")
                    continue;
                out_.Add(new HpackField(f.Name, f.Value, f.Sensitive || HpackEncoder.IsSensitiveName(f.Name)));
            }
            return out_;
        }

        static string PathOf(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path)) return "/";
                if (path.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                    || path.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    return new Uri(path).PathAndQuery;
                return path;
            }
            catch { return path ?? "/"; }
        }

        static async Task HandleNewRequestAsync(Http2Leg client, Http2Leg up,
            ConcurrentDictionary<int, StreamPair> pairs, MitmSessionOptions opt,
            int streamId, bool endStream, H2Pseudo.Request req, CancellationToken ct)
        {
            var pair = new StreamPair { ReqEnded = endStream };
            string path = PathOf(req.Path);
            var authority = string.IsNullOrWhiteSpace(req.Authority) ? opt.ConnectHost : req.Authority.Trim();

            if (opt.IsBlocked(StripPort(authority)) || opt.IsBlocked(opt.ConnectHost))
            {
                pair.Blocked = true;
                pairs[streamId] = pair;
                client.NoteStream(streamId, Http2StreamState.HalfClosedRemote);
                await SyntheticStatusAsync(client, streamId, "403",
                    "Domain blocked by PTor (Blocked Domains)", ct);
                opt.Relay("BLOCKED-DOMAIN");
                return;
            }

            // Extended-CONNECT websocket tunnels DATA opaquely after 2xx.
            var isWs = req.Protocol != null;

            // Policy on the neutral lines form (shared with HTTP/1.1).
            var lines = H2Lines.RequestToLines(req.Method, path, authority, req.Headers);
            string? block = null;
            if (opt.BlockWebRtc && ContentFilter.IsWebRtcTarget(StripPort(authority), opt.ConnectPort))
                block = "BLOCKED-RTC";
            else if (!isWs && opt.BlockJs && ContentFilter.IsJsRequestPath(path))
                block = "BLOCKED-JS";
            if (block != null)
            {
                pair.Blocked = true;
                pairs[streamId] = pair;
                client.NoteStream(streamId, Http2StreamState.HalfClosedRemote);
                await SyntheticStatusAsync(client, streamId, "403",
                    block == "BLOCKED-JS"
                        ? "JavaScript file blocked by PTor (BlockJS)"
                        : "WebRTC (STUN/TURN) blocked by PTor", ct);
                opt.Relay(block);
                return;
            }

            // Transform: strip cookies/proxy headers, spoof authority.
            ContentFilter.RemoveProxyHopHeaders(ref lines);
            if (opt.BlockCookies) ContentFilter.RemoveRequestCookies(ref lines);
            if (!string.IsNullOrWhiteSpace(opt.SpoofHost))
            {
                for (var i = 1; i < lines.Length; i++)
                    if (lines[i].StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                        lines[i] = "Host: " + opt.SpoofHost.Trim();
                authority = opt.SpoofHost.Trim();
            }
            var fwd = H2Lines.FieldsFromLines(lines, H2Lines.SensitiveMap(req.Headers));
            // Rebuild pseudo from (possibly normalized) values.
            var out_ = new List<HpackField>
            {
                new(":method", req.Method, false),
                new(":scheme", req.Scheme, false),
                new(":path", path, false),
                new(":authority", authority, false),
            };
            if (isWs) out_.Add(new HpackField(":protocol", req.Protocol!, false));
            out_.AddRange(fwd);

            if (up.OpenStreamCount >= Math.Min(MaxStreams, up.PeerMaxStreams))
            {
                await client.SendRstAsync(streamId, Http2Const.REFUSED_STREAM, ct);
                return;
            }
            pairs[streamId] = pair;
            client.OpenStream(streamId);
            up.OpenStream(streamId);
            client.NoteStream(streamId, endStream ? Http2StreamState.HalfClosedRemote : Http2StreamState.Open);
            up.NoteStream(streamId, endStream ? Http2StreamState.HalfClosedRemote : Http2StreamState.Open);
            await up.WriteHeadersAsync(streamId, out_, endStream, ct);
            pair.ReqSent = true;
            if (isWs) pair.WsTunnel = true;
            opt.Relay("MITM-H2");
        }

        static async Task HandleResponseAsync(Http2Leg up, Http2Leg client,
            ConcurrentDictionary<int, StreamPair> pairs, MitmSessionOptions opt,
            int streamId, bool endStream, H2Pseudo.Response resp, StreamPair pair, CancellationToken ct)
        {
            var status = resp.Status;
            var isInterim = status[0] == '1';
            var lines = H2Lines.ResponseToLines(status, resp.Headers);
            if (isInterim)
            {
                // 103 Early Hints etc.: forward verbatim, keep stream open.
                // (END_STREAM on informational is malformed.)
                if (endStream)
                    throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "END_STREAM on 1xx.");
                var fwdI = H2Lines.FieldsFromLines(lines, resp.WasSensitive);
                var outI = new List<HpackField> { new(":status", status, false) };
                outI.AddRange(fwdI);
                client.EnsureSendStream(streamId);
                await client.WriteHeadersAsync(streamId, outI, endStream: false, ct);
                return;
            }
            if (!pair.ReqSent)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Response before request.");
            // (Response trailers are handled by the caller before ParseResponse.)
            pair.RespFinal = true;

            var respType = ContentFilter.GetHeaderValue(lines, "Content-Type");
            string? block = null;
            if (!pair.WsTunnel && opt.BlockWebRtc && ContentFilter.IsSdpContentType(respType))
                block = "BLOCKED-RTC";
            else if (!pair.WsTunnel && opt.BlockJs && ContentFilter.IsJsContentType(respType))
                block = "BLOCKED-JS";
            if (block != null)
            {
                pair.Blocked = true;
                try { await up.SendRstAsync(streamId, Http2Const.CANCEL, ct); } catch { }
                await SyntheticStatusAsync(client, streamId, "403",
                    block == "BLOCKED-JS"
                        ? "JavaScript response blocked by PTor (BlockJS)"
                        : "WebRTC signaling (SDP) blocked by PTor", ct);
                opt.Relay(block);
                return;
            }
            if (opt.BlockJs && ContentFilter.IsHtmlContentType(respType))
                ContentFilter.TryInjectJsBlockCsp(ref lines);
            if (opt.BlockCookies) ContentFilter.RemoveResponseCookies(ref lines);
            var fwd = H2Lines.FieldsFromLines(lines, resp.WasSensitive);
            var out_ = new List<HpackField> { new(":status", status, false) };
            out_.AddRange(fwd);
            client.EnsureSendStream(streamId);
            await client.WriteHeadersAsync(streamId, out_, endStream, ct);
            if (endStream)
            {
                pair.RespEnded = true;
                up.NoteStream(streamId, Http2StreamState.HalfClosedLocal);
                client.NoteStream(streamId, Http2StreamState.HalfClosedLocal);
                MaybeRetire(pairs, up, client, streamId);
            }
            opt.Relay("MITM-H2");
        }

        // Best-effort clean failure when the ORIGIN leg never came up but the
        // client leg negotiated h2 (writing h1 bytes would corrupt framing).
        // Accepts the h2 session, answers the first request HEADERS with a
        // synthetic status, then GOAWAY. Any failure here just closes.
        public static async Task SendUpstreamFailureAsync(Stream clientT, string message, CancellationToken ct)
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
                var lct = linked.Token;
                var leg = await AcceptClientAsync(clientT, lct);
                try
                {
                    while (true)
                    {
                        lct.ThrowIfCancellationRequested();
                        var f = await Http2FrameCodec.ReadFrameAsync(clientT, lct, leg.PeerMaxFrameSize);
                        if (f.Type == Http2Const.SETTINGS && (f.Flags & Http2Const.FLAG_ACK) == 0)
                        {
                            leg.ApplyPeerSettings(f.Payload);
                            await leg.SendSettingsAckAsync(lct);
                            continue;
                        }
                        if (f.Type == Http2Const.PING && (f.Flags & Http2Const.FLAG_ACK) == 0)
                        {
                            if (f.Payload.Length == 8) await leg.SendPingAckAsync(f.Payload, lct);
                            continue;
                        }
                        if (f.Type == Http2Const.WINDOW_UPDATE && f.Payload.Length == 4)
                        {
                            try { leg.OnWindowUpdate(f.StreamId, (f.Payload[0] << 24) | (f.Payload[1] << 16) | (f.Payload[2] << 8) | f.Payload[3]); } catch { }
                            continue;
                        }
                        if (f.Type == Http2Const.GOAWAY) return;
                        if (f.Type != Http2Const.HEADERS || f.StreamId == 0 || f.StreamId % 2 == 0)
                            continue;
                        // Answer without decoding: the failure is ours, the
                        // request content is irrelevant (and stays unread).
                        leg.OpenStream(f.StreamId);
                        await SyntheticStatusAsync(leg, f.StreamId, "502", message, lct);
                        try { await leg.SendGoAwayAsync(f.StreamId, Http2Const.NO_ERROR, lct); } catch { }
                        return;
                    }
                }
                finally { leg.Dispose(); }
            }
            catch { }
        }

        static async Task SyntheticStatusAsync(Http2Leg client, int streamId, string status, string bodyText, CancellationToken ct)
        {
            var body = Encoding.ASCII.GetBytes("Blocked by PTor content policy: " + bodyText + "\n");
            var fields = new List<HpackField>
            {
                new(":status", status, false),
                new("content-type", "text/plain", false),
                new("content-length", body.Length.ToString(), false),
            };
            client.EnsureSendStream(streamId);
            await client.WriteHeadersAsync(streamId, fields, endStream: false, ct);
            await client.WriteDataAsync(streamId, body, 0, body.Length, endStream: true, ct);
            client.NoteStream(streamId, Http2StreamState.Closed);
        }

        static string StripPort(string host)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(host)) return "";
                var h = host.Trim();
                if (h.StartsWith("[", StringComparison.Ordinal))
                {
                    var close = h.IndexOf(']');
                    return close > 0 ? h.Substring(1, close - 1) : h.Trim('[', ']');
                }
                var colon = h.LastIndexOf(':');
                if (colon > 0 && h.IndexOf(':') == colon) return h.Substring(0, colon);
                return h;
            }
            catch { return host ?? ""; }
        }

        // ---- translators ----

        // H2 client -> per-request H1 origin connections (see file notes).
        public static async Task RunH2ToH1Async(Stream clientT, MitmSessionOptions opt, CancellationToken ct)
        {
            if (opt.SocksDial == null || opt.AuthenticateUpstream == null)
                throw new InvalidOperationException("H2→H1 translator needs SocksDial + AuthenticateUpstream.");
            var client = await AcceptClientAsync(clientT, ct);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var lct = cts.Token;
            var inboxes = new ConcurrentDictionary<int, StreamInbox>();
            var inFlight = new List<Task>();
            try
            {
                await DispatchH2ClientAsync(client, inboxes, inFlight, opt, lct);
            }
            catch (Http2Exception hex) { await SendGoAwayBothAsync(client, client, hex.ErrorCode); }
            catch (OperationCanceledException) { throw; }
            catch { await SendGoAwayBothAsync(client, client, Http2Const.INTERNAL_ERROR); }
            finally
            {
                try { cts.Cancel(); } catch { }
                foreach (var kv in inboxes) try { kv.Value.Aborted.Cancel(); } catch { }
                try { await Task.WhenAll(inFlight); } catch { }
                // All transactions finished: safe to release per-stream handles
                // (transaction finally already disposed its own; these cover
                // RST-aborted leftovers still in the dict).
                foreach (var kv in inboxes) try { kv.Value.Dispose(); } catch { }
                client.Dispose();
            }
        }

        readonly record struct InboxItem(byte[] Data, bool End, bool IsTrailers);

        sealed class StreamInbox
        {
            public readonly ConcurrentQueue<InboxItem> Queue = new();
            public readonly SemaphoreSlim DataAvail = new(0);
            public readonly CancellationTokenSource Aborted = new();
            public readonly object Gate = new();
            public int Queued;
            public TaskCompletionSource<bool> DrainGate = CompletedGate();

            static TaskCompletionSource<bool> CompletedGate()
            {
                var t = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                t.TrySetResult(true);
                return t;
            }

            // TCP-level backpressure: the dispatch task stops reading the
            // whole h2 connection while a transaction lags, so kernel
            // buffers stall the client cleanly (no unbounded buffering).
            public async Task WaitForRoomAsync(CancellationToken ct)
            {
                using var reg = ct.Register(() => PulseGate());
                while (true)
                {
                    Task<bool> gate;
                    lock (Gate)
                    {
                        ct.ThrowIfCancellationRequested();
                        if (Queued < 64) return;
                        gate = DrainGate.Task;
                    }
                    try { await gate; }
                    catch (OperationCanceledException) { ct.ThrowIfCancellationRequested(); }
                }
            }

            public void NotifyEnqueued()
            {
                lock (Gate) Queued++;
            }

            public void NotifyDrained()
            {
                TaskCompletionSource<bool>? wake = null;
                lock (Gate)
                {
                    if (Queued > 0) Queued--;
                    if (Queued < 32)
                    {
                        wake = DrainGate;
                        DrainGate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    }
                }
                try { wake?.TrySetResult(true); } catch { }
            }

            void PulseGate()
            {
                TaskCompletionSource<bool> old;
                lock (Gate)
                {
                    old = DrainGate;
                    DrainGate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                }
                try { old.TrySetResult(true); } catch { }
            }

            public void Dispose()
            {
                try { Aborted.Cancel(); } catch { }
                try { DataAvail.Dispose(); } catch { }
                try { Aborted.Dispose(); } catch { }
            }
        }

        static async Task DispatchH2ClientAsync(Http2Leg client,
            ConcurrentDictionary<int, StreamInbox> inboxes, List<Task> inFlight,
            MitmSessionOptions opt, CancellationToken ct)
        {
            var asm = new HeaderAssembly();
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var f = await Http2FrameCodec.ReadFrameAsync(client.Transport, ct, client.PeerMaxFrameSize);
                switch (f.Type)
                {
                    case Http2Const.SETTINGS:
                        if (f.StreamId != 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "SETTINGS on stream.");
                        if ((f.Flags & Http2Const.FLAG_ACK) == 0)
                        {
                            client.ApplyPeerSettings(f.Payload);
                            await client.SendSettingsAckAsync(ct);
                        }
                        break;
                    case Http2Const.PING:
                        if (f.StreamId != 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "PING on stream.");
                        if ((f.Flags & Http2Const.FLAG_ACK) == 0)
                        {
                            if (f.Payload.Length != 8) throw new Http2Exception(Http2Const.FRAME_SIZE_ERROR, "Bad PING.");
                            await client.SendPingAckAsync(f.Payload, ct);
                        }
                        break;
                    case Http2Const.WINDOW_UPDATE:
                        if (f.Payload.Length != 4) throw new Http2Exception(Http2Const.FRAME_SIZE_ERROR, "Bad WINDOW_UPDATE.");
                        ValidateStreamForWindowUpdate(client, f.StreamId);
                        client.OnWindowUpdate(f.StreamId, (f.Payload[0] << 24) | (f.Payload[1] << 16) | (f.Payload[2] << 8) | f.Payload[3]);
                        break;
                    case Http2Const.PRIORITY:
                        break;
                    case Http2Const.RST_STREAM:
                        if (f.Payload.Length != 4) throw new Http2Exception(Http2Const.FRAME_SIZE_ERROR, "Bad RST_STREAM.");
                        if (f.StreamId == 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "RST on stream 0.");
                        if (inboxes.TryRemove(f.StreamId, out var inbox))
                            try { inbox.Aborted.Cancel(); } catch { }
                        client.NoteStream(f.StreamId, Http2StreamState.Closed);
                        break;
                    case Http2Const.GOAWAY:
                        return;
                    case Http2Const.PUSH_PROMISE:
                        throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "PUSH_PROMISE from client.");
                    case Http2Const.DATA:
                        await DispatchDataAsync(client, inboxes, f, ct);
                        break;
                    case Http2Const.HEADERS:
                    case Http2Const.CONTINUATION:
                        await DispatchHeadersAsync(client, inboxes, inFlight, opt, f, asm, ct);
                        break;
                    default:
                        break;
                }
                try { await client.FlushWindowUpdatesAsync(ct); } catch { }
            }
        }

        static async Task DispatchDataAsync(Http2Leg client,
            ConcurrentDictionary<int, StreamInbox> inboxes, Http2Frame f, CancellationToken ct)
        {
            if (f.StreamId == 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "DATA on stream 0.");
            if (client.GetStreamState(f.StreamId) == Http2StreamState.Idle)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "DATA on idle stream.");
            if (!inboxes.TryGetValue(f.StreamId, out var inbox)) return; // refused/blocked: drop
            var (data, endStream) = Unpad(f);
            if (data.Length > 0) client.OnDataReceived(f.StreamId, data.Length);
            await inbox.WaitForRoomAsync(ct);
            inbox.Queue.Enqueue(new InboxItem(data, endStream, false));
            inbox.NotifyEnqueued();
            if (endStream) client.NoteStream(f.StreamId, Http2StreamState.HalfClosedRemote);
            try { inbox.DataAvail.Release(); } catch { }
        }

        static async Task DispatchHeadersAsync(Http2Leg client,
            ConcurrentDictionary<int, StreamInbox> inboxes, List<Task> inFlight,
            MitmSessionOptions opt, Http2Frame f, HeaderAssembly asm, CancellationToken ct)
        {
            // Assemble (HEADERS + CONTINUATIONs), then hand to a transaction.
            List<HpackField> fields;
            int streamId;
            bool endStream;
            if (f.Type == Http2Const.CONTINUATION)
            {
                if (asm.StreamId != f.StreamId)
                    throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Stray CONTINUATION.");
                asm.Buf.Write(f.Payload, 0, f.Payload.Length);
                if (asm.Buf.Length > MaxHeaderBlock)
                    throw new Http2Exception(Http2Const.COMPRESSION_ERROR, "Header block too large.");
                if ((f.Flags & Http2Const.FLAG_END_HEADERS) == 0) return;
                streamId = asm.StreamId;
                endStream = asm.PendingEndStream || (f.Flags & Http2Const.FLAG_END_STREAM) != 0;
                var block = asm.Buf.ToArray();
                asm.StreamId = -1;
                asm.Buf.SetLength(0);
                try { fields = client.Hpack.DecodeHeaderBlock(block, 0, block.Length); }
                catch (HpackException hex) { throw new Http2Exception(Http2Const.COMPRESSION_ERROR, hex.Message); }
            }
            else
            {
                if (f.StreamId == 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "HEADERS on stream 0.");
                var frag = StripH2Padding(f);
                if (asm.StreamId >= 0)
                    throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "HEADERS during CONTINUATION.");
                if ((f.Flags & Http2Const.FLAG_END_HEADERS) == 0)
                {
                    asm.StreamId = f.StreamId;
                    asm.Buf.SetLength(0);
                    asm.Buf.Write(frag, 0, frag.Length);
                    asm.PendingEndStream = (f.Flags & Http2Const.FLAG_END_STREAM) != 0;
                    return;
                }
                streamId = f.StreamId;
                endStream = (f.Flags & Http2Const.FLAG_END_STREAM) != 0;
                try { fields = client.Hpack.DecodeHeaderBlock(frag, 0, frag.Length); }
                catch (HpackException hex) { throw new Http2Exception(Http2Const.COMPRESSION_ERROR, hex.Message); }
            }

            // Existing stream => trailers for an in-flight transaction.
            if (inboxes.TryGetValue(streamId, out var existing))
            {
                if (!endStream) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Non-ending trailers.");
                var fwd = FilterTrailerFields(fields);
                existing.Queue.Enqueue(new InboxItem(HpackEncoder.EncodeFields(fwd), true, true));
                existing.NotifyEnqueued();
                try { existing.DataAvail.Release(); } catch { }
                client.NoteStream(streamId, Http2StreamState.HalfClosedRemote);
                return;
            }
            if (streamId % 2 == 0 || streamId <= client.MaxSeenStreamId)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad new stream id.");
            if (client.OpenStreamCount >= MaxStreams)
            {
                await client.SendRstAsync(streamId, Http2Const.REFUSED_STREAM, ct);
                return;
            }
            H2Pseudo.Request req;
            try { req = H2Pseudo.ParseRequest(fields); }
            catch (Http2Exception hex) when (hex.ErrorCode == Http2Const.REFUSED_STREAM)
            {
                // Unsupported extended-CONNECT protocol: clean stream error.
                await client.SendRstAsync(streamId, Http2Const.REFUSED_STREAM, ct);
                return;
            }
            var inbox = new StreamInbox();
            inboxes[streamId] = inbox;
            client.OpenStream(streamId);
            client.NoteStream(streamId, endStream ? Http2StreamState.HalfClosedRemote : Http2StreamState.Open);
            if (endStream)
            {
                inbox.Queue.Enqueue(new InboxItem(Array.Empty<byte>(), true, false));
                inbox.NotifyEnqueued();
                try { inbox.DataAvail.Release(); } catch { }
            }
            var task = H2ToH1TransactionAsync(client, streamId, req, endStream, inbox, inboxes, opt, ct);
            lock (inFlight)
            {
                inFlight.Add(task);
                inFlight.RemoveAll(t => t.IsCompleted);
            }
        }

        static byte[] StripH2Padding(Http2Frame f)
        {
            var frag = f.Payload;
            var off = 0;
            if ((f.Flags & Http2Const.FLAG_PADDED) != 0)
            {
                if (frag.Length == 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad HEADERS padding.");
                var padLen = frag[0];
                if (padLen >= frag.Length) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad HEADERS pad length.");
                off = 1;
                frag = frag[off..(frag.Length - padLen)];
            }
            if ((f.Flags & Http2Const.FLAG_PRIORITY) != 0)
            {
                if (frag.Length < 5) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad HEADERS priority.");
                frag = frag[5..];
            }
            return frag;
        }

        static async Task H2ToH1TransactionAsync(Http2Leg client, int streamId,
            H2Pseudo.Request req, bool requestEndStream, StreamInbox inbox,
            ConcurrentDictionary<int, StreamInbox> inboxes, MitmSessionOptions opt, CancellationToken ct)
        {
            async Task FailAsync(string status, string msg)
            {
                try
                {
                    inboxes.TryRemove(streamId, out _);
                    client.NoteStream(streamId, Http2StreamState.Closed);
                    await SyntheticStatusAsync(client, streamId, status, msg, ct);
                }
                catch { }
            }
            try
            {
                string path = PathOf(req.Path);
                var authority = string.IsNullOrWhiteSpace(req.Authority) ? opt.ConnectHost : req.Authority.Trim();
                if (opt.IsBlocked(StripPort(authority)) || opt.IsBlocked(opt.ConnectHost))
                {
                    try { inboxes.TryRemove(streamId, out _); } catch { }
                    client.NoteStream(streamId, Http2StreamState.HalfClosedRemote);
                    await SyntheticStatusAsync(client, streamId, "403", "Domain blocked by PTor (Blocked Domains)", ct);
                    opt.Relay("BLOCKED-DOMAIN");
                    return;
                }
                var lines = H2Lines.RequestToLines(req.Method, path, authority, req.Headers);
                if (opt.BlockWebRtc && ContentFilter.IsWebRtcTarget(StripPort(authority), opt.ConnectPort))
                {
                    try { inboxes.TryRemove(streamId, out _); } catch { }
                    client.NoteStream(streamId, Http2StreamState.HalfClosedRemote);
                    await SyntheticStatusAsync(client, streamId, "403", "WebRTC (STUN/TURN) blocked by PTor", ct);
                    opt.Relay("BLOCKED-RTC");
                    return;
                }
                if (req.Protocol == null && opt.BlockJs && ContentFilter.IsJsRequestPath(path))
                {
                    try { inboxes.TryRemove(streamId, out _); } catch { }
                    client.NoteStream(streamId, Http2StreamState.HalfClosedRemote);
                    await SyntheticStatusAsync(client, streamId, "403", "JavaScript file blocked by PTor (BlockJS)", ct);
                    opt.Relay("BLOCKED-JS");
                    return;
                }
                if (req.Protocol != null)
                {
                    // Extended-CONNECT websocket over a translator leg: no h1
                    // upgrade available — clean refusal (H2H2 path tunnels it).
                    await FailAsync("501", "WebSocket-over-HTTP/2 needs matching HTTP/2 upstream.");
                    return;
                }
                ContentFilter.RemoveProxyHopHeaders(ref lines);
                ContentFilter.RemoveHeadersByName(ref lines, "Expect");
                if (opt.BlockCookies) ContentFilter.RemoveRequestCookies(ref lines);
                if (!string.IsNullOrWhiteSpace(opt.SpoofHost))
                {
                    for (var i = 1; i < lines.Length; i++)
                        if (lines[i].StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                            lines[i] = "Host: " + opt.SpoofHost.Trim();
                }
                // Origin-form h1 request line. Bodies (when HEADERS did not
                // end the stream) are declared chunked UP FRONT, then streamed
                // from the inbox below.
                if (!requestEndStream)
                    ContentFilter.RemoveHeadersByName(ref lines, "Content-Length", "Transfer-Encoding");
                var h1list = new List<string> { $"{req.Method} {path} HTTP/1.1" };
                for (var i = 1; i < lines.Length; i++) h1list.Add(lines[i]);
                if (!requestEndStream)
                {
                    // Insert Transfer-Encoding before the terminating blank.
                    var blankAt = h1list.IndexOf("");
                    if (blankAt < 0) h1list.Add("");
                    blankAt = h1list.IndexOf("");
                    h1list.Insert(blankAt, "Transfer-Encoding: chunked");
                }
                var h1arr = h1list.ToArray();

                TcpClient? tcp = null;
                try { tcp = await opt.SocksDial!(opt.ConnectHost, opt.ConnectPort, ct); }
                catch (OperationCanceledException) { throw; }
                catch { tcp = null; }
                if (tcp == null) { await FailAsync("502", "Tor circuit unavailable."); return; }
                using (tcp)
                {
                    var net = tcp.GetStream();
                    using var upTls = new SslStream(net, false);
                    bool authed;
                    try { authed = await opt.AuthenticateUpstream!(upTls, opt.TlsTarget, ct); }
                    catch (OperationCanceledException) { throw; }
                    catch { authed = false; }
                    if (!authed) { await FailAsync("502", "Origin certificate invalid (fail-closed)."); return; }

                    // Send headers, then the body (if any) chunked from inbox.
                    var headBytes = Encoding.Latin1.GetBytes(string.Join("\r\n", h1arr));
                    try { await upTls.WriteAsync(headBytes, ct); }
                    catch { await FailAsync("502", "Origin write failed."); return; }
                    if (!requestEndStream)
                    {
                        if (!await ForwardInboxBodyChunkedAsync(upTls, inbox, ct)) return;
                    }
                    // Response.
                    var (respText, respExtra) = await Http1Plumbing.ReadHeadersAsync(upTls, ct);
                    if (respText.Length == 0) { await FailAsync("502", "Empty origin response."); return; }
                    var respLines = respText.Split("\r\n");
                    for (var guard = 0; guard < 5 && Http1Plumbing.IsInterim1xx(respLines); guard++)
                    {
                        var fwdI = H2Lines.FieldsFromLines(respLines, null);
                        var outI = new List<HpackField> { new(":status", ContentFilter.TryGetStatusCode(respLines).ToString(), false) };
                        outI.AddRange(fwdI);
                        client.EnsureSendStream(streamId);
                        await client.WriteHeadersAsync(streamId, outI, endStream: false, ct);
                        (respText, respExtra) = await Http1Plumbing.ReadHeadersAsync(upTls, ct);
                        if (respText.Length == 0) { await FailAsync("502", "Truncated origin response."); return; }
                        respLines = respText.Split("\r\n");
                    }
                    var status = ContentFilter.TryGetStatusCode(respLines);
                    if (status == 101)
                    {
                        await FailAsync("502", "Unexpected protocol switch from origin.");
                        return;
                    }
                    var respType = ContentFilter.GetHeaderValue(respLines, "Content-Type");
                    string? block = null;
                    if (opt.BlockWebRtc && ContentFilter.IsSdpContentType(respType)) block = "BLOCKED-RTC";
                    else if (opt.BlockJs && ContentFilter.IsJsContentType(respType)) block = "BLOCKED-JS";
                    if (block != null)
                    {
                        await SyntheticStatusAsync(client, streamId,
                            "403", block == "BLOCKED-JS" ? "JavaScript response blocked by PTor (BlockJS)" : "WebRTC signaling (SDP) blocked by PTor", ct);
                        opt.Relay(block);
                        return;
                    }
                    if (opt.BlockJs && ContentFilter.IsHtmlContentType(respType))
                        ContentFilter.TryInjectJsBlockCsp(ref respLines);
                    if (opt.BlockCookies) ContentFilter.RemoveResponseCookies(ref respLines);
                    var h2resp = H2Lines.FieldsFromLines(respLines, null);
                    var out_ = new List<HpackField> { new(":status", status.ToString(), false) };
                    out_.AddRange(h2resp);
                    var noBody = ContentFilter.IsNoBodyResponse(status, req.Method);
                    client.EnsureSendStream(streamId);
                    await client.WriteHeadersAsync(streamId, out_, endStream: noBody && respExtra.Length == 0, ct);
                    if (!noBody)
                        await ForwardH1BodyToH2Async(upTls, client, streamId, respLines, req.Method, status, respExtra, ct);
                    else if (respExtra.Length > 0)
                    {
                        // No-body response with stray bytes: protocol error
                        // upstream — close stream, keep connection.
                        try { await client.SendRstAsync(streamId, Http2Const.STREAM_CLOSED, ct); } catch { }
                    }
                    opt.Relay("MITM-TR");
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { try { await client.SendRstAsync(streamId, Http2Const.INTERNAL_ERROR, ct); } catch { } }
            finally
            {
                inboxes.TryRemove(streamId, out _);
                client.NoteStream(streamId, Http2StreamState.Closed);
                try { inbox.Aborted.Cancel(); } catch { }
                try { inbox.DataAvail.Release(); } catch { }
                // Handles are per-stream: dispose now that no waiter remains
                // (dispatch dropped the dict entry; the consumer is this task).
                try { inbox.Dispose(); } catch { }
            }
        }

        // Reads inbox items and writes them chunked to the h1 origin.
        // Item kinds are explicit (see StreamInbox): body bytes, body end,
        // or an HPACK-encoded trailer block. False = aborted/failed.
        static async Task<bool> ForwardInboxBodyChunkedAsync(
            SslStream upTls, StreamInbox inbox, CancellationToken ct)
        {
            while (true)
            {
                try { await inbox.DataAvail.WaitAsync(ct); }
                catch (OperationCanceledException)
                {
                    ct.ThrowIfCancellationRequested();
                    if (inbox.Aborted.IsCancellationRequested) return false;
                    continue;
                }
                if (inbox.Aborted.IsCancellationRequested) return false;
                if (!inbox.Queue.TryDequeue(out var item))
                    continue;
                inbox.NotifyDrained();
                if (item.IsTrailers)
                {
                    try
                    {
                        var tfields = new HpackDecoder(4096).DecodeHeaderBlock(
                            item.Data, 0, item.Data.Length);
                        var sb = new StringBuilder("0\r\n");
                        foreach (var tf in FilterTrailerFields(
                            tfields.Select(t => new HpackField(t.Name, t.Value, t.Sensitive)).ToList()))
                            sb.Append(tf.Name).Append(": ").Append(tf.Value).Append("\r\n");
                        sb.Append("\r\n");
                        await upTls.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), ct);
                    }
                    catch { return false; }
                    return true;
                }
                if (item.Data.Length > 0)
                {
                    try
                    {
                        await upTls.WriteAsync(Encoding.ASCII.GetBytes(item.Data.Length.ToString("X") + "\r\n"), ct);
                        await upTls.WriteAsync(item.Data, ct);
                        await upTls.WriteAsync(Encoding.ASCII.GetBytes("\r\n"), ct);
                    }
                    catch { return false; }
                }
                if (item.End)
                {
                    try { await upTls.WriteAsync(Encoding.ASCII.GetBytes("0\r\n\r\n"), ct); }
                    catch { return false; }
                    return true;
                }
            }
        }

        // h1 origin body -> h2 DATA (chunked or length-delimited or close).
        // Prefix bytes already read past the headers belong to the body.
        sealed class PrefixedBodyReader
        {
            readonly Stream _h1;
            readonly byte[] _prefix;
            int _prefixOffset;
            public PrefixedBodyReader(Stream h1, byte[] prefix) { _h1 = h1; _prefix = prefix; }
            public async Task<int> ReadAsync(byte[] buf, int offset, int count, CancellationToken ct)
            {
                if (_prefixOffset < _prefix.Length)
                {
                    var n = Math.Min(count, _prefix.Length - _prefixOffset);
                    Buffer.BlockCopy(_prefix, _prefixOffset, buf, offset, n);
                    _prefixOffset += n;
                    return n;
                }
                return await _h1.ReadAsync(buf.AsMemory(offset, count), ct);
            }
        }

        static async Task ForwardH1BodyToH2Async(Stream h1, Http2Leg client, int streamId,
            string[] respLines, string method, int status, byte[] prefix, CancellationToken ct)
        {
            if (ContentFilter.IsNoBodyResponse(status, method)) return;
            var reader = new PrefixedBodyReader(h1, prefix);
            var te = ContentFilter.GetHeaderValue(respLines, "Transfer-Encoding") ?? "";
            var chunked = te.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0;
            if (chunked)
            {
                await ForwardH1ChunkedToH2Async(reader, client, streamId, ct);
                return;
            }
            var cl = ContentFilter.GetHeaderValue(respLines, "Content-Length");
            if (cl != null && long.TryParse(cl.Trim(), out var len) && len > 0)
            {
                var buf = ArrayPool<byte>.Shared.Rent(81920);
                try
                {
                    var left = len;
                    while (left > 0)
                    {
                        var want = (int)Math.Min(buf.Length, left);
                        var n = await reader.ReadAsync(buf, 0, want, ct);
                        if (n <= 0) return; // truncated: fail closed (stream dies with tunnel)
                        left -= n;
                        var chunk = new byte[n];
                        Buffer.BlockCopy(buf, 0, chunk, 0, n);
                        client.EnsureSendStream(streamId);
                        await client.WriteDataAsync(streamId, chunk, 0, chunk.Length, left == 0, ct);
                    }
                }
                finally { ArrayPool<byte>.Shared.Return(buf); }
                return;
            }
            // Close-delimited: stream until origin EOF, then END_STREAM.
            var buf2 = ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                while (true)
                {
                    var n = await reader.ReadAsync(buf2, 0, buf2.Length, ct);
                    if (n <= 0)
                    {
                        await client.WriteDataAsync(streamId, Array.Empty<byte>(), 0, 0, endStream: true, ct);
                        return;
                    }
                    var chunk = new byte[n];
                    Buffer.BlockCopy(buf2, 0, chunk, 0, n);
                    client.EnsureSendStream(streamId);
                    await client.WriteDataAsync(streamId, chunk, 0, chunk.Length, endStream: false, ct);
                }
            }
            finally { ArrayPool<byte>.Shared.Return(buf2); }
        }

        static async Task ForwardH1ChunkedToH2Async(PrefixedBodyReader reader, Http2Leg client, int streamId,
            CancellationToken ct)
        {
            async Task<string?> ReadLine()
            {
                var ms = new MemoryStream();
                var one = new byte[1];
                while (ms.Length < 16384)
                {
                    int n;
                    try { n = await reader.ReadAsync(one, 0, 1, ct); }
                    catch (OperationCanceledException) { throw; }
                    catch { return null; }
                    if (n <= 0) return ms.Length == 0 ? null : Encoding.ASCII.GetString(ms.ToArray());
                    ms.WriteByte(one[0]);
                    var L = (int)ms.Length;
                    if (L >= 2)
                    {
                        var b = ms.GetBuffer();
                        if (b[L - 2] == '\r' && b[L - 1] == '\n')
                            return Encoding.ASCII.GetString(b, 0, L - 2);
                    }
                }
                return null;
            }
            async Task<bool> ReadExact(byte[] buf)
            {
                var off = 0;
                while (off < buf.Length)
                {
                    int n;
                    try { n = await reader.ReadAsync(buf, off, buf.Length - off, ct); }
                    catch (OperationCanceledException) { throw; }
                    catch { return false; }
                    if (n <= 0) return false;
                    off += n;
                }
                return true;
            }
            while (true)
            {
                var line = await ReadLine();
                if (line == null) return;
                var semi = line.IndexOf(';');
                if (!int.TryParse((semi >= 0 ? line.Substring(0, semi) : line).Trim(),
                        System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture, out var size) || size < 0)
                    return;
                if (size == 0)
                {
                    // Trailers: forward as h2 trailers.
                    var trailers = new List<HpackField>();
                    while (true)
                    {
                        var t = await ReadLine();
                        if (t == null) return;
                        if (t.Length == 0) break;
                        var c = t.IndexOf(':');
                        if (c <= 0) continue;
                        trailers.Add(new HpackField(t.Substring(0, c).Trim().ToLowerInvariant(),
                            t.Substring(c + 1).Trim(), false));
                    }
                    if (trailers.Count > 0)
                    {
                        client.EnsureSendStream(streamId);
                        await client.WriteHeadersAsync(streamId, trailers, endStream: true, ct);
                    }
                    else
                    {
                        await client.WriteDataAsync(streamId, Array.Empty<byte>(), 0, 0, endStream: true, ct);
                    }
                    return;
                }
                var chunk = new byte[size];
                if (!await ReadExact(chunk)) return;
                var crlf = new byte[2];
                if (!await ReadExact(crlf) || crlf[0] != '\r' || crlf[1] != '\n') return;
                client.EnsureSendStream(streamId);
                await client.WriteDataAsync(streamId, chunk, 0, chunk.Length, endStream: false, ct);
            }
        }

        // ---- H1 client -> shared H2 upstream session ----

        public static async Task RunH1ToH2Async(Stream clientT, MitmSessionOptions opt, CancellationToken ct)
        {
            if (opt.SocksDial == null || opt.AuthenticateUpstream == null)
                throw new InvalidOperationException("H1→H2 translator needs SocksDial + AuthenticateUpstream.");
            TcpClient? tcp;
            try { tcp = await opt.SocksDial(opt.ConnectHost, opt.ConnectPort, ct); }
            catch (OperationCanceledException) { throw; }
            catch { tcp = null; }
            if (tcp == null) return;
            using (tcp)
            {
                var net = tcp.GetStream();
                using var upTls = new SslStream(net, false);
                bool authed;
                try { authed = await opt.AuthenticateUpstream(upTls, opt.TlsTarget, ct); }
                catch (OperationCanceledException) { throw; }
                catch { authed = false; }
                if (!authed) return;
                var up = await OpenUpstreamAsync(upTls, ct);
                try
                {
                    await H1ToH2LoopAsync(clientT, up, opt, ct);
                }
                catch (Http2Exception hex) { await SendGoAwayBothAsync(up, up, hex.ErrorCode); }
                catch (OperationCanceledException) { throw; }
                catch { }
                finally { up.Dispose(); }
            }
        }

        static async Task H1ToH2LoopAsync(Stream clientT, Http2Leg up, MitmSessionOptions opt, CancellationToken ct)
        {
            var nextStream = 1;
            while (true)
            {
                string reqText;
                byte[] reqExtra;
                try { (reqText, reqExtra) = await Http1Plumbing.ReadHeadersAsync(clientT, ct); }
                catch (OperationCanceledException) { throw; }
                catch { return; }
                if (reqText.Length == 0) return;
                var reqLines = reqText.Split("\r\n");
                var rp = (reqLines[0] ?? "").Split(' ');
                if (rp.Length < 3) return;
                var method = rp[0];
                if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase)) return;
                Uri? uri = null;
                string path = rp[1];
                try
                {
                    if (path.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                        || path.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    {
                        uri = new Uri(path);
                        path = uri.PathAndQuery;
                    }
                }
                catch { }
                var host = ContentFilter.GetHeaderValue(reqLines, "Host") ?? opt.ConnectHost;
                if (opt.IsBlocked(StripPort(host)) || opt.IsBlocked(opt.ConnectHost))
                {
                    await WriteH1Async(clientT, ContentFilter.BuildBlockedResponse("Domain blocked by PTor (Blocked Domains)"), Array.Empty<byte>(), ct);
                    opt.Relay("BLOCKED-DOMAIN");
                    return;
                }
                if (opt.BlockWebRtc && ContentFilter.IsWebRtcTarget(StripPort(host), opt.ConnectPort))
                {
                    await WriteH1Async(clientT, ContentFilter.BuildBlockedResponse("WebRTC (STUN/TURN) blocked by PTor"), Array.Empty<byte>(), ct);
                    opt.Relay("BLOCKED-RTC");
                    return;
                }
                if (opt.BlockJs && ContentFilter.IsJsRequestPath(path))
                {
                    await WriteH1Async(clientT, ContentFilter.BuildBlockedResponse("JavaScript file blocked by PTor (BlockJS)"), Array.Empty<byte>(), ct);
                    opt.Relay("BLOCKED-JS");
                    return;
                }
                ContentFilter.RemoveProxyHopHeaders(ref reqLines);
                ContentFilter.RemoveHeadersByName(ref reqLines, "Expect");
                if (opt.BlockCookies) ContentFilter.RemoveRequestCookies(ref reqLines);
                if (!string.IsNullOrWhiteSpace(opt.SpoofHost))
                    HttpToSocksBridge.ApplyHostSpoof(ref reqLines, opt.SpoofHost);

                var h2req = H2Translator.RequestToH2(method, path, StripPort(host), reqLines);
                // Stream-ID exhaustion (client-initiated IDs cap at
                // 0x7FFFFFFF): close the translator leg instead of emitting
                // illegal IDs — the client opens a fresh connection.
                if (nextStream > Http2Const.MaxStreamId - 1) return;
                var sid = nextStream;
                nextStream += 2;
                // Request body: h1 framing -> h2 DATA.
                var hasBody = Http1Plumbing.RequestHasBody(reqLines);
                up.EnsureSendStream(sid);
                await up.WriteHeadersAsync(sid, h2req, endStream: !hasBody && reqExtra.Length == 0, ct);
                if (hasBody || reqExtra.Length > 0)
                    await ForwardH1BodyToH2StreamAsync(clientT, up, sid, reqLines, reqExtra, ct);

                // Response: h2 HEADERS (+interim) -> h1.
                var gotFinal = false;
                string[]? finalLines = null;
                string? finalStatus = null;
                while (!gotFinal)
                {
                    var f = await Http2FrameCodec.ReadFrameAsync(up.Transport, ct, up.PeerMaxFrameSize);
                    if (f.Type == Http2Const.SETTINGS && (f.Flags & Http2Const.FLAG_ACK) == 0)
                    {
                        up.ApplyPeerSettings(f.Payload);
                        await up.SendSettingsAckAsync(ct);
                        continue;
                    }
                    if (f.Type == Http2Const.PING && (f.Flags & Http2Const.FLAG_ACK) == 0)
                    {
                        if (f.Payload.Length == 8) await up.SendPingAckAsync(f.Payload, ct);
                        continue;
                    }
                    if (f.Type == Http2Const.WINDOW_UPDATE && f.Payload.Length == 4)
                    {
                        up.OnWindowUpdate(f.StreamId, (f.Payload[0] << 24) | (f.Payload[1] << 16) | (f.Payload[2] << 8) | f.Payload[3]);
                        continue;
                    }
                    if (f.Type != Http2Const.HEADERS || f.StreamId != sid)
                    {
                        if (f.Type == Http2Const.RST_STREAM && f.StreamId == sid)
                        {
                            await WriteH1Async(clientT, Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"), Array.Empty<byte>(), ct);
                            return;
                        }
                        if (f.Type == Http2Const.DATA && f.StreamId == sid)
                            up.OnDataReceived(sid, f.Payload.Length); // stray: account + drop
                        continue;
                    }
                    var (block, end) = await AssembleBlockAsync(up, f, ct);
                    List<HpackField> fields;
                    try { fields = up.Hpack.DecodeHeaderBlock(block, 0, block.Length); }
                    catch (HpackException hex) { throw new Http2Exception(Http2Const.COMPRESSION_ERROR, hex.Message); }
                    var resp = H2Pseudo.ParseResponse(fields);
                    if (resp.Status[0] == '1')
                    {
                        if (end)
                            throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "END_STREAM on 1xx.");
                        var il = H2Lines.ResponseToLines(resp.Status, resp.Headers);
                        await WriteH1Async(clientT, Encoding.Latin1.GetBytes(string.Join("\r\n", il)), Array.Empty<byte>(), ct);
                        continue;
                    }
                    finalLines = H2Lines.ResponseToLines(resp.Status, resp.Headers);
                    finalStatus = resp.Status;
                    gotFinal = true;
                    var noBodyEarly = ContentFilter.IsNoBodyResponse(int.Parse(finalStatus), method);
                    finalLines = ApplyH1ResponsePolicy(finalLines, resp, opt, noBodyEarly, out var blockedMode);
                    if (blockedMode != null)
                    {
                        await WriteH1Async(clientT, ContentFilter.BuildBlockedResponse(blockedMode == "BLOCKED-JS" ? "JavaScript response blocked by PTor (BlockJS)" : "WebRTC signaling (SDP) blocked by PTor"), Array.Empty<byte>(), ct);
                        opt.Relay(blockedMode);
                        try { await up.SendRstAsync(sid, Http2Const.CANCEL, ct); } catch { }
                        return;
                    }
                    var noBody = ContentFilter.IsNoBodyResponse(int.Parse(finalStatus), method);
                    await WriteH1Async(clientT, Encoding.Latin1.GetBytes(string.Join("\r\n", finalLines)), Array.Empty<byte>(), ct);
                    if (!noBody && !end)
                        await ForwardH2StreamToH1ChunkedAsync(up, clientT, sid, method, ct);
                    // (noBody || end): nothing more to read for this stream.
                    opt.Relay("MITM-TR");
                }
                if (ContentFilter.GetHeaderValue(finalLines!, "Connection")?.IndexOf("close", StringComparison.OrdinalIgnoreCase) >= 0)
                    return;
            }
        }

        static string[] ApplyH1ResponsePolicy(string[] lines, H2Pseudo.Response resp, MitmSessionOptions opt, bool noBody, out string? blockedMode)
        {
            blockedMode = null;
            var respType = ContentFilter.GetHeaderValue(lines, "Content-Type");
            if (opt.BlockWebRtc && ContentFilter.IsSdpContentType(respType)) { blockedMode = "BLOCKED-RTC"; return lines; }
            if (opt.BlockJs && ContentFilter.IsJsContentType(respType)) { blockedMode = "BLOCKED-JS"; return lines; }
            if (opt.BlockJs && ContentFilter.IsHtmlContentType(respType))
                ContentFilter.TryInjectJsBlockCsp(ref lines);
            if (opt.BlockCookies) ContentFilter.RemoveResponseCookies(ref lines);
            if (noBody) return lines; // 204/304/HEAD/1xx: no framing headers allowed
            // h1 framing for the translated response: force chunked bodies.
            // (Content-Length from origin is untrustworthy across translation;
            // chunked is universally supported by h1 clients.)
            ContentFilter.RemoveHeadersByName(ref lines, "Content-Length", "Transfer-Encoding");
            var end = Array.IndexOf(lines, "");
            if (end < 0) end = lines.Length;
            var grown = new string[lines.Length + 1];
            Array.Copy(lines, 0, grown, 0, end);
            grown[end] = "Transfer-Encoding: chunked";
            Array.Copy(lines, end, grown, end + 1, lines.Length - end);
            lines = grown;
            return lines;
        }

        static async Task<(byte[] Block, bool EndStream)> AssembleBlockAsync(Http2Leg leg, Http2Frame first, CancellationToken ct)
        {
            var frag = StripH2Padding(first);
            var end = (first.Flags & Http2Const.FLAG_END_STREAM) != 0;
            if ((first.Flags & Http2Const.FLAG_END_HEADERS) != 0) return (frag, end);
            var ms = new MemoryStream();
            ms.Write(frag, 0, frag.Length);
            while (true)
            {
                var c = await Http2FrameCodec.ReadFrameAsync(leg.Transport, ct, leg.PeerMaxFrameSize);
                if (c.Type != Http2Const.CONTINUATION || c.StreamId != first.StreamId)
                    throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Expected CONTINUATION.");
                ms.Write(c.Payload, 0, c.Payload.Length);
                if (ms.Length > MaxHeaderBlock)
                    throw new Http2Exception(Http2Const.COMPRESSION_ERROR, "Header block too large.");
                if ((c.Flags & Http2Const.FLAG_END_HEADERS) != 0)
                    return (ms.ToArray(), end || (c.Flags & Http2Const.FLAG_END_STREAM) != 0);
            }
        }

        static async Task WriteH1Async(Stream to, byte[] head, byte[] extra, CancellationToken ct)
        {
            await to.WriteAsync(head, ct);
            if (extra.Length > 0) await to.WriteAsync(extra, ct);
        }

        static async Task ForwardH1BodyToH2StreamAsync(Stream h1, Http2Leg up, int sid,
            string[] reqLines, byte[] prefix, CancellationToken ct)
        {
            var reader = new H1BodyReader(h1, prefix);
            var te = ContentFilter.GetHeaderValue(reqLines, "Transfer-Encoding") ?? "";
            var chunkedIn = te.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0;
            var cl = ContentFilter.GetHeaderValue(reqLines, "Content-Length");
            long remaining = -1;
            if (!chunkedIn && cl != null && long.TryParse(cl.Trim(), out var l)) remaining = l;
            if (chunkedIn)
            {
                // Re-frame into h2 DATA (parse to stay framed).
                while (true)
                {
                    var line = await reader.ReadLineAsync(ct);
                    if (line == null) { await up.SendRstAsync(sid, Http2Const.CANCEL, ct); return; }
                    var semi = line.IndexOf(';');
                    if (!int.TryParse((semi >= 0 ? line.Substring(0, semi) : line).Trim(),
                            System.Globalization.NumberStyles.HexNumber,
                            System.Globalization.CultureInfo.InvariantCulture, out var size) || size < 0)
                    { await up.SendRstAsync(sid, Http2Const.PROTOCOL_ERROR, ct); return; }
                    if (size == 0)
                    {
                        // Consume chunked trailers (h2 trailers would need a
                        // HEADERS frame here; the h2 stream simply ends —
                        // trailers from h1 uploads are dropped, bodies intact).
                        while (await reader.ReadLineAsync(ct) is string t && t.Length > 0) { }
                        up.EnsureSendStream(sid);
                        await up.WriteDataAsync(sid, Array.Empty<byte>(), 0, 0, endStream: true, ct);
                        return;
                    }
                    var chunk = new byte[size];
                    if (!await reader.ReadExactAsync(chunk, ct))
                    { await up.SendRstAsync(sid, Http2Const.CANCEL, ct); return; }
                    var crlf = new byte[2];
                    if (!await reader.ReadExactAsync(crlf, ct) || crlf[0] != '\r' || crlf[1] != '\n')
                    { await up.SendRstAsync(sid, Http2Const.PROTOCOL_ERROR, ct); return; }
                    up.EnsureSendStream(sid);
                    await up.WriteDataAsync(sid, chunk, 0, chunk.Length, endStream: false, ct);
                }
            }
            // Length-delimited (or prefix-only) body.
            var buf = ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                while (remaining < 0 || remaining > 0)
                {
                    int want = remaining < 0 ? buf.Length : (int)Math.Min(buf.Length, remaining);
                    int n;
                    try { n = await reader.ReadAsync(buf, 0, want, ct); }
                    catch (OperationCanceledException) { throw; }
                    catch { await up.SendRstAsync(sid, Http2Const.CANCEL, ct); return; }
                    if (n <= 0)
                    {
                        if (remaining < 0)
                        {
                            await up.WriteDataAsync(sid, Array.Empty<byte>(), 0, 0, endStream: true, ct);
                            return;
                        }
                        await up.SendRstAsync(sid, Http2Const.PROTOCOL_ERROR, ct);
                        return;
                    }
                    var chunk = new byte[n];
                    Buffer.BlockCopy(buf, 0, chunk, 0, n);
                    up.EnsureSendStream(sid);
                    if (remaining > 0) remaining -= n;
                    await up.WriteDataAsync(sid, chunk, 0, chunk.Length, endStream: remaining == 0, ct);
                    if (remaining == 0) return;
                }
                // remaining == 0 with no body bytes (e.g. Content-Length: 0).
                await up.WriteDataAsync(sid, Array.Empty<byte>(), 0, 0, endStream: true, ct);
            }
            finally { ArrayPool<byte>.Shared.Return(buf); }
        }

        // Sequential byte reader over (header-extra prefix + live stream)
        // for h1 request/response bodies in the translators.
        sealed class H1BodyReader
        {
            readonly Stream _h1;
            readonly byte[] _prefix;
            int _off;
            public H1BodyReader(Stream h1, byte[] prefix) { _h1 = h1; _prefix = prefix; }
            public async Task<int> ReadAsync(byte[] buf, int offset, int count, CancellationToken ct)
            {
                if (_off < _prefix.Length)
                {
                    var n = Math.Min(count, _prefix.Length - _off);
                    Buffer.BlockCopy(_prefix, _off, buf, offset, n);
                    _off += n;
                    return n;
                }
                return await _h1.ReadAsync(buf.AsMemory(offset, count), ct);
            }
            public async Task<string?> ReadLineAsync(CancellationToken ct)
            {
                var ms = new MemoryStream();
                var one = new byte[1];
                while (ms.Length < 16384)
                {
                    int n;
                    try { n = await ReadAsync(one, 0, 1, ct); }
                    catch (OperationCanceledException) { throw; }
                    catch { return null; }
                    if (n <= 0) return ms.Length == 0 ? null : Encoding.ASCII.GetString(ms.ToArray());
                    ms.WriteByte(one[0]);
                    var L = (int)ms.Length;
                    if (L >= 2)
                    {
                        var b = ms.GetBuffer();
                        if (b[L - 2] == '\r' && b[L - 1] == '\n')
                            return Encoding.ASCII.GetString(b, 0, L - 2);
                    }
                }
                return null;
            }
            public async Task<bool> ReadExactAsync(byte[] buf, CancellationToken ct)
            {
                var off = 0;
                while (off < buf.Length)
                {
                    int n;
                    try { n = await ReadAsync(buf, off, buf.Length - off, ct); }
                    catch (OperationCanceledException) { throw; }
                    catch { return false; }
                    if (n <= 0) return false;
                    off += n;
                }
                return true;
            }
        }

        static async Task ForwardH2StreamToH1ChunkedAsync(Http2Leg up, Stream h1out, int sid, string method, CancellationToken ct)
        {
            // h2 DATA for sid -> h1 chunked (headers already sent with TE: chunked).
            while (true)
            {
                var f = await Http2FrameCodec.ReadFrameAsync(up.Transport, ct, up.PeerMaxFrameSize);
                if (f.Type == Http2Const.SETTINGS && (f.Flags & Http2Const.FLAG_ACK) == 0)
                {
                    up.ApplyPeerSettings(f.Payload);
                    await up.SendSettingsAckAsync(ct);
                    continue;
                }
                if (f.Type == Http2Const.PING && (f.Flags & Http2Const.FLAG_ACK) == 0)
                {
                    if (f.Payload.Length == 8) await up.SendPingAckAsync(f.Payload, ct);
                    continue;
                }
                if (f.Type == Http2Const.WINDOW_UPDATE && f.Payload.Length == 4)
                {
                    up.OnWindowUpdate(f.StreamId, (f.Payload[0] << 24) | (f.Payload[1] << 16) | (f.Payload[2] << 8) | f.Payload[3]);
                    continue;
                }
                if (f.Type == Http2Const.RST_STREAM && f.StreamId == sid)
                {
                    // Truncated response: terminate chunked body abruptly (client
                    // detects truncation via missing zero-chunk — fail-closed).
                    return;
                }
                if (f.Type == Http2Const.GOAWAY) return;
                if (f.Type == Http2Const.HEADERS && f.StreamId == sid)
                {
                    // Response trailers: emit as chunked trailers, then done.
                    var (tblock, tend) = await AssembleBlockAsync(up, f, ct);
                    if (!tend) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Non-ending response trailers.");
                    List<HpackField> tfields;
                    try { tfields = up.Hpack.DecodeHeaderBlock(tblock, 0, tblock.Length); }
                    catch (HpackException hex) { throw new Http2Exception(Http2Const.COMPRESSION_ERROR, hex.Message); }
                    foreach (var tf in tfields)
                        if (tf.Name.Length == 0 || tf.Name[0] == ':')
                            throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Pseudo in trailers.");
                    var sb = new StringBuilder("0\r\n");
                    foreach (var tf in FilterTrailerFields(tfields))
                        sb.Append(tf.Name).Append(": ").Append(tf.Value).Append("\r\n");
                    sb.Append("\r\n");
                    await h1out.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), ct);
                    return;
                }
                if (f.Type != Http2Const.DATA || f.StreamId != sid) continue;
                var (data, end) = UnpadForTranslator(f);
                if (data.Length > 0) up.OnDataReceived(sid, data.Length);
                try { await up.FlushWindowUpdatesAsync(ct); } catch { }
                if (data.Length > 0)
                {
                    await h1out.WriteAsync(Encoding.ASCII.GetBytes(data.Length.ToString("X") + "\r\n"), ct);
                    await h1out.WriteAsync(data, ct);
                    await h1out.WriteAsync(Encoding.ASCII.GetBytes("\r\n"), ct);
                }
                if (end)
                {
                    await h1out.WriteAsync(Encoding.ASCII.GetBytes("0\r\n\r\n"), ct);
                    return;
                }
            }
        }

        static (byte[] Data, bool EndStream) UnpadForTranslator(Http2Frame f)
        {
            var payload = f.Payload;
            if ((f.Flags & Http2Const.FLAG_PADDED) != 0)
            {
                if (payload.Length == 0) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad padding.");
                var padLen = payload[0];
                if (padLen >= payload.Length) throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad padding length.");
                return (payload[1..(payload.Length - padLen)], (f.Flags & Http2Const.FLAG_END_STREAM) != 0);
            }
            return (payload, (f.Flags & Http2Const.FLAG_END_STREAM) != 0);
        }
    }

}
