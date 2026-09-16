using System;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{

    public class TorMaintenance : IDisposable
    {
        readonly TorControlClient _control;
        Timer? _keepAliveTimer;
        Timer? _rotateTimer;
        int _rotateGen;

        // Exact-interval NEWNYM bursts are stopwatch-regular: ±20% per cycle. (Loopback keep-alive stays fixed.)
        internal static TimeSpan NextRotationDelay(int intervalSec, Random? rng = null)
        {
            rng ??= Random.Shared;
            var baseMs = Math.Max(60_000L, (long)intervalSec * 1000);
            var factor = 0.8 + rng.NextDouble() * 0.4;
            // Floor AFTER jitter: otherwise the 0.8x pull drags tiny
            // intervals below the intended 60s minimum.
            return TimeSpan.FromMilliseconds(Math.Max(60_000, baseMs * factor));
        }
        volatile bool _disposed;

        public int KeepAliveIntervalSec { get; set; } = 45;
        public int RotateIntervalSec { get; set; } = 0;

        public event EventHandler? Died;
        public event EventHandler<string>? RotationRequested;
        public event EventHandler<bool>? RotationCompleted;

        public TorMaintenance(TorControlClient control)
        {
            _control = control;
        }

        public void Start()
        {
            if (_disposed) return;
            try { _keepAliveTimer?.Dispose(); } catch { }
            _keepAliveTimer = new Timer(async _ => await KeepAliveTick(), null,
                TimeSpan.FromSeconds(KeepAliveIntervalSec), TimeSpan.FromSeconds(KeepAliveIntervalSec));

            RestartRotationTimer();
        }

        public void RestartRotationTimer()
        {
            if (_disposed) return;
            var gen = Interlocked.Increment(ref _rotateGen);
            try { _rotateTimer?.Dispose(); } catch { }
            _rotateTimer = null;

            if (RotateIntervalSec <= 0) return;

            ScheduleNextRotation(gen);
        }

        void ScheduleNextRotation(int gen)
        {
            Timer? timer = null;
            try
            {
                if (_disposed) return;
                if (gen != Volatile.Read(ref _rotateGen)) return;
                // Drop the previous one-shot handle first (see engine link ticks).
                try { _rotateTimer?.Dispose(); } catch { }
                timer = _rotateTimer = new Timer(async _ =>
                {
                    try { await RotateTick(); }
                    finally { if (gen == Volatile.Read(ref _rotateGen)) ScheduleNextRotation(gen); }
                }, null, NextRotationDelay(RotateIntervalSec), Timeout.InfiniteTimeSpan);
            }
            catch { try { timer?.Dispose(); } catch { } }
        }

        // Test seam: the timer calls this; tests drive it directly against
        // a fake control server.
        internal async Task KeepAliveTick()
        {
            if (_disposed) return;
            try
            {
                if (_disposed) return;
                if (_control.IsConnected)
                {
                    try { if (await _control.HeartbeatAsync()) return; }
                    catch { }
                    if (_disposed) return;
                    // Heartbeat failed on a supposedly-live channel: usually
                    // a stale loopback socket (sleep, flap), not a dead tor.
                    // Fall through to resurrect instead of killing circuits.
                }
                await TryResurrectOrDie();
            }
            catch
            {
                if (!_disposed) Died?.Invoke(this, EventArgs.Empty);
            }
        }

        // Control channel died — tor itself is usually FINE (only its
        // loopback control TCP broke). Re-auth the channel (zero impact on
        // circuits: apps never notice) and only escalate to Died — which
        // restarts the whole daemon and drops every app connection — when
        // tor itself is unreachable. Previously ANY blip (sleep, flap, one
        // slow command) caused a full restart: long-running apps suddenly
        // lost everything and took minutes to recover.
        async Task TryResurrectOrDie()
        {
            try
            {
                for (var i = 0; i < 2 && !_disposed; i++)
                {
                    bool ok;
                    try { ok = await _control.ConnectAsync(3000); }
                    catch { ok = false; }
                    if (ok) return;
                    if (_disposed) return;
                    try { await Task.Delay(1000); } catch { return; }
                }
            }
            catch { }
            if (!_disposed) Died?.Invoke(this, EventArgs.Empty);
        }

        async Task RotateTick()
        {
            if (_disposed) return;
            try { RotationRequested?.Invoke(this, "Rotating circuit (scheduled)..."); }
            catch { return; }
            bool ok;
            try { ok = await _control.NewIdentityAsync(); }
            catch { ok = false; }
            if (_disposed) return;
            try { RotationCompleted?.Invoke(this, ok); } catch { }
        }

        public async Task<bool> RotateNowAsync()
        {
            if (_disposed) return false;
            try { RotationRequested?.Invoke(this, "Rotating circuit (manual)..."); }
            catch { return false; }
            bool ok;
            try { ok = await _control.NewIdentityAsync(); }
            catch { ok = false; }
            if (_disposed) return false;
            try { RotationCompleted?.Invoke(this, ok); } catch { }
            return ok;
        }

        public void Dispose()
        {
            _disposed = true;
            try { _keepAliveTimer?.Dispose(); } catch { }
            _keepAliveTimer = null;
            try { _rotateTimer?.Dispose(); } catch { }
            _rotateTimer = null;
        }
    }
}
