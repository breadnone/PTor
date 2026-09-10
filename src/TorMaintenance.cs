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

        async Task KeepAliveTick()
        {
            if (_disposed) return;
            try
            {
                if (_disposed || !_control.IsConnected)
                {
                    if (!_disposed) Died?.Invoke(this, EventArgs.Empty);
                    return;
                }
                var ok = await _control.HeartbeatAsync();
                if (_disposed) return;
                if (!ok) Died?.Invoke(this, EventArgs.Empty);
            }
            catch
            {
                if (!_disposed) Died?.Invoke(this, EventArgs.Empty);
            }
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
