using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{
    // Minimal HTTP/2 (RFC 9113) framing + session state for the inspection
    // relay. Deliberately NOT a general web server: it only implements what
    // a transparent filtering intermediary needs, and fails CLOSED
    // (connection error + teardown) on anything malformed or unhandled.
    //
    // Each CONNECT tunnel gets two independent sessions (client leg +
    // origin leg) with separate HPACK contexts, flow-control windows and
    // settings, bridged 1:1 by stream ID in MitmHttp2Relay.

    public sealed class Http2Exception : Exception
    {
        public readonly uint ErrorCode;
        public Http2Exception(uint errorCode, string message) : base(message)
        {
            ErrorCode = errorCode;
        }
    }

    public static class Http2Const
    {
        public static readonly byte[] Preface =
            System.Text.Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        public const byte DATA = 0x0;
        public const byte HEADERS = 0x1;
        public const byte PRIORITY = 0x2;
        public const byte RST_STREAM = 0x3;
        public const byte SETTINGS = 0x4;
        public const byte PUSH_PROMISE = 0x5;
        public const byte PING = 0x6;
        public const byte GOAWAY = 0x7;
        public const byte WINDOW_UPDATE = 0x8;
        public const byte CONTINUATION = 0x9;

        public const byte FLAG_END_STREAM = 0x1;
        public const byte FLAG_END_HEADERS = 0x4;
        public const byte FLAG_PADDED = 0x8;
        public const byte FLAG_PRIORITY = 0x20;
        public const byte FLAG_ACK = 0x1;

        public const ushort SETTINGS_HEADER_TABLE_SIZE = 0x1;
        public const ushort SETTINGS_ENABLE_PUSH = 0x2;
        public const ushort SETTINGS_MAX_CONCURRENT_STREAMS = 0x3;
        public const ushort SETTINGS_INITIAL_WINDOW_SIZE = 0x4;
        public const ushort SETTINGS_MAX_FRAME_SIZE = 0x5;
        public const ushort SETTINGS_MAX_HEADER_LIST_SIZE = 0x6;

        public const uint NO_ERROR = 0x0;
        public const uint PROTOCOL_ERROR = 0x1;
        public const uint INTERNAL_ERROR = 0x2;
        public const uint FLOW_CONTROL_ERROR = 0x3;
        public const uint STREAM_CLOSED = 0x5;
        public const uint FRAME_SIZE_ERROR = 0x6;
        public const uint REFUSED_STREAM = 0x7;
        public const uint CANCEL = 0x8;
        public const uint COMPRESSION_ERROR = 0x9;
        public const uint ENHANCE_YOUR_CALM = 0xB;

        public const int DefaultMaxFrame = 16384;
        public const int DefaultWindow = 65535;
        public const int MaxStreamId = 0x7FFFFFFF;
    }

    public readonly struct Http2Frame
    {
        public readonly byte Type;
        public readonly byte Flags;
        public readonly int StreamId;
        public readonly byte[] Payload;

        public Http2Frame(byte type, byte flags, int streamId, byte[] payload)
        {
            Type = type;
            Flags = flags;
            StreamId = streamId;
            Payload = payload;
        }
    }

    public static class Http2FrameCodec
    {
        public static async Task<Http2Frame> ReadFrameAsync(Stream s, CancellationToken ct, int peerMaxFrameSize = Http2Const.DefaultMaxFrame)
        {
            var hdr = new byte[9];
            if (!await TryReadExactAsync(s, hdr, ct))
                throw new Http2Exception(Http2Const.NO_ERROR, "EOF reading frame header.");
            var len = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2];
            var type = hdr[3];
            var flags = hdr[4];
            var sid = ((hdr[5] & 0x7F) << 24) | (hdr[6] << 16) | (hdr[7] << 8) | hdr[8];
            if ((hdr[5] & 0x80) != 0)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Reserved bit set on stream id.");
            // RFC 9113 §4.2: receiver MUST treat len > SETTINGS_MAX_FRAME_SIZE
            // as FRAME_SIZE_ERROR. Clamp the limit to the protocol range so a
            // corrupt peer setting cannot widen the alloc window.
            var limit = peerMaxFrameSize;
            if (limit < Http2Const.DefaultMaxFrame) limit = Http2Const.DefaultMaxFrame;
            if (limit > 16 * 1024 * 1024) limit = 16 * 1024 * 1024;
            if (len > limit)
                throw new Http2Exception(Http2Const.FRAME_SIZE_ERROR, "Frame exceeds SETTINGS_MAX_FRAME_SIZE.");
            if (len < 0 || len > 16 * 1024 * 1024)
                throw new Http2Exception(Http2Const.FRAME_SIZE_ERROR, "Absurd frame length.");
            var payload = new byte[len];
            if (!await TryReadExactAsync(s, payload, ct))
                throw new Http2Exception(Http2Const.NO_ERROR, "EOF reading frame payload.");
            return new Http2Frame(type, flags, sid, payload);
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

        public static byte[] Encode(byte type, byte flags, int streamId, byte[] payload)
        {
            var len = payload?.Length ?? 0;
            var out_ = new byte[9 + len];
            out_[0] = (byte)(len >> 16);
            out_[1] = (byte)(len >> 8);
            out_[2] = (byte)len;
            out_[3] = type;
            out_[4] = flags;
            out_[5] = (byte)((streamId >> 24) & 0x7F);
            out_[6] = (byte)(streamId >> 16);
            out_[7] = (byte)(streamId >> 8);
            out_[8] = (byte)streamId;
            if (len > 0) Buffer.BlockCopy(payload!, 0, out_, 9, len);
            return out_;
        }

        public static async Task WriteAsync(Stream s, byte type, byte flags, int streamId, byte[] payload, CancellationToken ct) =>
            await s.WriteAsync(Encode(type, flags, streamId, payload), ct);
    }

    public enum Http2StreamState
    {
        Idle,
        Open,
        HalfClosedRemote,
        HalfClosedLocal,
        Closed,
    }

    // One direction's session state for a single HTTP/2 connection leg.
    // The relay owns two of these (client leg, origin leg) and shuttles
    // frames between them in MitmHttp2Relay.
    public sealed class Http2Leg : IDisposable
    {
        public readonly Stream Transport;
        public readonly HpackDecoder Hpack;
        public readonly bool IsUpstream;

        // Written by ApplyPeerSettings (pump A), read by WriteData/WriteHeaders
        // (pump B): volatile so a peer-shrunk MAX_FRAME_SIZE is observed
        // promptly instead of oversizing frames on a stale read.
        public volatile int PeerMaxFrameSize = Http2Const.DefaultMaxFrame;
        public volatile int PeerMaxStreams = int.MaxValue;
        public volatile int PeerHeaderTableLimit = 4096;

        // Flow-control: S=self send budget (peer grants), R=self receive
        // budget (we grant peer via WINDOW_UPDATE as we consume).
        long _sendConnWindow = Http2Const.DefaultWindow;
        long _recvConnWindow = Http2Const.DefaultWindow;
        long _recvConnConsumed;
        readonly Dictionary<int, long> _sendStreamWindows = new();
        readonly Dictionary<int, long> _recvStreamWindows = new();
        readonly Dictionary<int, long> _recvStreamConsumed = new();
        readonly Dictionary<int, Http2StreamState> _streams = new();
        int _maxSeenStreamId;
        int _peerInitWindow = Http2Const.DefaultWindow;

        // Signalled whenever any send window grows (WINDOW_UPDATE).
        TaskCompletionSource<bool> _windowGate =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        readonly object _gate = new();

        public int OpenStreamCount
        {
            get
            {
                lock (_gate)
                {
                    var n = 0;
                    foreach (var kv in _streams)
                        if (kv.Value == Http2StreamState.Open
                            || kv.Value == Http2StreamState.HalfClosedRemote
                            || kv.Value == Http2StreamState.HalfClosedLocal)
                            n++;
                    return n;
                }
            }
        }

        const long WindowUpdateThreshold = 32768;
        bool _disposed;

        public Http2Leg(Stream transport, bool isUpstream)
        {
            Transport = transport;
            IsUpstream = isUpstream;
            Hpack = new HpackDecoder(4096);
        }

        // ---- stream bookkeeping ----

        public Http2StreamState GetStreamState(int id)
        {
            lock (_gate)
                return _streams.TryGetValue(id, out var st) ? st : Http2StreamState.Idle;
        }

        public void NoteStream(int id, Http2StreamState st)
        {
            lock (_gate) _streams[id] = st;
            if (id > _maxSeenStreamId && id % 2 == 1)
            {
                lock (_gate) { if (id > _maxSeenStreamId) _maxSeenStreamId = id; }
            }
        }

        public int MaxSeenStreamId
        {
            get { lock (_gate) return _maxSeenStreamId; }
        }

        // Marks a locally-initiated stream as open (call before its first
        // send). Keeps MaxSeen + concurrency accounting correct.
        public void OpenStream(int id)
        {
            EnsureSendStream(id);
            NoteStream(id, Http2StreamState.Open);
        }

        public void EnsureSendStream(int id)
        {
            lock (_gate)
            {
                if (!_sendStreamWindows.ContainsKey(id))
                    _sendStreamWindows[id] = _peerInitWindow;
                if (!_recvStreamWindows.ContainsKey(id))
                {
                    _recvStreamWindows[id] = Http2Const.DefaultWindow;
                    _recvStreamConsumed[id] = 0;
                }
            }
        }

        // ---- flow control ----

        public void OnDataReceived(int streamId, int len)
        {
            List<(int Stream, int Increment)> updates = new();
            lock (_gate)
            {
                _recvConnWindow -= len;
                _recvConnConsumed += len;
                if (_recvConnConsumed >= WindowUpdateThreshold)
                {
                    updates.Add((0, (int)_recvConnConsumed));
                    _recvConnWindow += _recvConnConsumed;
                    _recvConnConsumed = 0;
                }
                if (_recvStreamWindows.TryGetValue(streamId, out _))
                {
                    _recvStreamWindows[streamId] -= len;
                    var c = _recvStreamConsumed[streamId] + len;
                    _recvStreamConsumed[streamId] = c;
                    if (c >= WindowUpdateThreshold)
                    {
                        updates.Add((streamId, (int)c));
                        _recvStreamWindows[streamId] += c;
                        _recvStreamConsumed[streamId] = 0;
                    }
                }
                if (_recvConnWindow < 0 || (_recvStreamWindows.TryGetValue(streamId, out var w) && w < 0))
                    throw new Http2Exception(Http2Const.FLOW_CONTROL_ERROR, "Receive window exceeded.");
            }
            foreach (var (stream, inc) in updates)
            {
                var p = new byte[4];
                p[0] = (byte)(inc >> 24); p[1] = (byte)(inc >> 16);
                p[2] = (byte)(inc >> 8); p[3] = (byte)inc;
                // Fire-and-forget is wrong here (ordering vs DATA); the
                // caller awaits FlushWindowUpdatesAsync instead. Queued under
                // _gate: OnDataReceived can run on either relay pump, and an
                // unsynchronized List<> Add racing Flush's Clear corrupts.
                lock (_gate) PendingWindowUpdates.Add((stream, p));
            }
        }

        // WINDOW_UPDATE frames the relay must emit, in order, before its
        // next read on this leg. Protected by the relay's per-leg lock.
        public readonly List<(int Stream, byte[] Payload)> PendingWindowUpdates = new();

        // All Transport writes funnel through this gate: two relay tasks share
        // each leg (one forwards data into it, the other emits control
        // frames), and SslStream frames must never interleave.
        public readonly SemaphoreSlim SendGate = new(1, 1);

        public async Task WriteFrameAsync(byte type, byte flags, int streamId, byte[] payload, CancellationToken ct)
        {
            await SendGate.WaitAsync(ct);
            try { await Http2FrameCodec.WriteAsync(Transport, type, flags, streamId, payload, ct); }
            finally { try { SendGate.Release(); } catch { } }
        }

        public async Task FlushWindowUpdatesAsync(CancellationToken ct)
        {
            List<(int Stream, byte[] Payload)> batch;
            lock (_gate)
            {
                if (PendingWindowUpdates.Count == 0) return;
                batch = new List<(int, byte[])>(PendingWindowUpdates);
                PendingWindowUpdates.Clear();
            }
            foreach (var (stream, p) in batch)
                await WriteFrameAsync(Http2Const.WINDOW_UPDATE, 0, stream, p, ct);
        }

        void PulseWindowGate()
        {
            TaskCompletionSource<bool> old;
            lock (_gate)
            {
                old = _windowGate;
                _windowGate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            }
            try { old.TrySetResult(true); } catch { }
        }

        public void OnWindowUpdate(int streamId, int increment)
        {
            if (increment <= 0 || increment > Http2Const.MaxStreamId)
                throw new Http2Exception(Http2Const.FLOW_CONTROL_ERROR, "Bad WINDOW_UPDATE increment.");
            lock (_gate)
            {
                if (streamId == 0)
                {
                    _sendConnWindow += increment;
                    if (_sendConnWindow > (long)Http2Const.MaxStreamId * 2)
                        throw new Http2Exception(Http2Const.FLOW_CONTROL_ERROR, "Connection window overflow.");
                }
                else
                {
                    _sendStreamWindows.TryGetValue(streamId, out var w);
                    w += increment;
                    if (w > (long)Http2Const.MaxStreamId * 2)
                        throw new Http2Exception(Http2Const.FLOW_CONTROL_ERROR, "Stream window overflow.");
                    _sendStreamWindows[streamId] = w;
                }
            }
            PulseWindowGate();
        }

        // Waits until `len` bytes may be sent on (connection + stream).
        // Never holds SendGate (control frames must pass while bulk DATA
        // waits), and never cancels the shared gate (one waiter's
        // cancellation must not poison the others).
        public async Task ReserveSendWindowAsync(int streamId, int len, CancellationToken ct)
        {
            using var reg = ct.Register(() => PulseWindowGate());
            while (true)
            {
                Task<bool> wait;
                lock (_gate)
                {
                    ct.ThrowIfCancellationRequested();
                    _sendStreamWindows.TryGetValue(streamId, out var sw);
                    if (_sendConnWindow >= len && sw >= len)
                    {
                        _sendConnWindow -= len;
                        _sendStreamWindows[streamId] = sw - len;
                        return;
                    }
                    wait = _windowGate.Task;
                }
                try { await wait; }
                catch (OperationCanceledException)
                {
                    ct.ThrowIfCancellationRequested();
                    // Spurious pulse (another waiter's cancel): re-check.
                }
            }
        }

        // ---- sending helpers ----

        public async Task WriteDataAsync(int streamId, byte[] data, int offset, int count, bool endStream, CancellationToken ct)
        {
            var remaining = count;
            var pos = offset;
            var first = true;
            while (remaining > 0 || (first && count == 0 && endStream))
            {
                var chunk = Math.Min(remaining, PeerMaxFrameSize);
                if (remaining == 0) chunk = 0;
                await ReserveSendWindowAsync(streamId, chunk, ct);
                var flags = (byte)0;
                if (remaining - chunk == 0 && endStream) flags |= Http2Const.FLAG_END_STREAM;
                var payload = new byte[chunk];
                if (chunk > 0) Buffer.BlockCopy(data, pos, payload, 0, chunk);
                await WriteFrameAsync(Http2Const.DATA, flags, streamId, payload, ct);
                pos += chunk;
                remaining -= chunk;
                first = false;
                if (chunk == 0) break; // empty END_STREAM frame sent
            }
        }

        public async Task WriteHeadersAsync(int streamId, IList<HpackField> fields, bool endStream, CancellationToken ct)
        {
            var block = HpackEncoder.EncodeFields(fields);
            var flags = Http2Const.FLAG_END_HEADERS;
            if (endStream) flags |= Http2Const.FLAG_END_STREAM;
            if (block.Length <= PeerMaxFrameSize)
            {
                await WriteFrameAsync(Http2Const.HEADERS, (byte)flags, streamId, block, ct);
                return;
            }
            var off = 0;
            var firstFrag = true;
            while (off < block.Length)
            {
                var chunk = Math.Min(PeerMaxFrameSize, block.Length - off);
                var frag = new byte[chunk];
                Buffer.BlockCopy(block, off, frag, 0, chunk);
                off += chunk;
                byte f;
                if (firstFrag)
                {
                    f = (off >= block.Length && endStream)
                        ? (byte)(Http2Const.FLAG_END_HEADERS | Http2Const.FLAG_END_STREAM)
                        : (byte)0;
                    await WriteFrameAsync(Http2Const.HEADERS, f, streamId, frag, ct);
                    firstFrag = false;
                }
                else
                {
                    f = (off >= block.Length)
                        ? (endStream ? (byte)(Http2Const.FLAG_END_HEADERS | Http2Const.FLAG_END_STREAM) : Http2Const.FLAG_END_HEADERS)
                        : (byte)0;
                    await WriteFrameAsync(Http2Const.CONTINUATION, f, streamId, frag, ct);
                }
            }
        }

        public Task SendRstAsync(int streamId, uint code, CancellationToken ct)
        {
            var p = new byte[4];
            p[0] = (byte)(code >> 24); p[1] = (byte)(code >> 16);
            p[2] = (byte)(code >> 8); p[3] = (byte)code;
            NoteStream(streamId, Http2StreamState.Closed);
            return WriteFrameAsync(Http2Const.RST_STREAM, 0, streamId, p, ct);
        }

        public Task SendGoAwayAsync(int lastStreamId, uint code, CancellationToken ct)
        {
            var p = new byte[8];
            p[0] = (byte)(lastStreamId >> 24); p[1] = (byte)(lastStreamId >> 16);
            p[2] = (byte)(lastStreamId >> 8); p[3] = (byte)lastStreamId;
            p[4] = (byte)(code >> 24); p[5] = (byte)(code >> 16);
            p[6] = (byte)(code >> 8); p[7] = (byte)code;
            return WriteFrameAsync(Http2Const.GOAWAY, 0, 0, p, ct);
        }

        public Task SendSettingsAckAsync(CancellationToken ct) =>
            WriteFrameAsync(Http2Const.SETTINGS, Http2Const.FLAG_ACK, 0, Array.Empty<byte>(), ct);

        public Task SendPingAckAsync(byte[] payload, CancellationToken ct) =>
            WriteFrameAsync(Http2Const.PING, Http2Const.FLAG_ACK, 0, payload, ct);

        public void ApplyPeerSettings(byte[] payload)
        {
            if (payload.Length % 6 != 0)
                throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad SETTINGS length.");
            for (var i = 0; i < payload.Length; i += 6)
            {
                var id = (payload[i] << 8) | payload[i + 1];
                var val = (uint)((payload[i + 2] << 24) | (payload[i + 3] << 16) | (payload[i + 4] << 8) | payload[i + 5]);
                switch (id)
                {
                    case Http2Const.SETTINGS_HEADER_TABLE_SIZE:
                        PeerHeaderTableLimit = (int)Math.Min(val, 65536);
                        Hpack.SetProtocolLimit(PeerHeaderTableLimit);
                        break;
                    case Http2Const.SETTINGS_ENABLE_PUSH:
                        if (val != 0 && val != 1)
                            throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad ENABLE_PUSH.");
                        break;
                    case Http2Const.SETTINGS_MAX_CONCURRENT_STREAMS:
                        PeerMaxStreams = val >= int.MaxValue ? int.MaxValue : (int)val;
                        break;
                    case Http2Const.SETTINGS_INITIAL_WINDOW_SIZE:
                        if (val > Http2Const.MaxStreamId)
                            throw new Http2Exception(Http2Const.FLOW_CONTROL_ERROR, "Bad INITIAL_WINDOW_SIZE.");
                        lock (_gate)
                        {
                            var delta = (long)val - _peerInitWindow;
                            _peerInitWindow = (int)val;
                            foreach (var k in new List<int>(_sendStreamWindows.Keys))
                                _sendStreamWindows[k] += delta;
                        }
                        PulseWindowGate();
                        break;
                    case Http2Const.SETTINGS_MAX_FRAME_SIZE:
                        if (val < Http2Const.DefaultMaxFrame || val > 16777215)
                            throw new Http2Exception(Http2Const.PROTOCOL_ERROR, "Bad MAX_FRAME_SIZE.");
                        PeerMaxFrameSize = (int)val;
                        break;
                    case Http2Const.SETTINGS_MAX_HEADER_LIST_SIZE:
                        break; // advisory; our HPACK list cap stands
                    default:
                        break; // unknown settings are ignored per RFC
                }
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try { PulseWindowGate(); } catch { }
            try { SendGate.Dispose(); } catch { }
        }
    }
}
