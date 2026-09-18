using System;
using System.Collections.Generic;

namespace PTor
{

    public class DirectStreakTracker
    {
        readonly Dictionary<int, int> _streak = new();

        public void Clear()
        {
            try { _streak.Clear(); } catch { }
        }

        public List<int> Update(IEnumerable<(int pid, bool direct)> rows, int threshold = 5)
        {
            var newly = new List<int>();
            try
            {
                var seen = new HashSet<int>();
                foreach (var (pid, direct) in rows)
                {
                    seen.Add(pid);
                    if (direct)
                    {
                        var n = _streak.TryGetValue(pid, out var c) ? c + 1 : 1;
                        _streak[pid] = n;
                        if (n == threshold) newly.Add(pid);
                    }
                    else
                    {
                        _streak.Remove(pid);
                    }
                }
                foreach (var k in new List<int>(_streak.Keys))
                    if (!seen.Contains(k)) _streak.Remove(k);
            }
            catch { }
            return newly;
        }
    }
}
