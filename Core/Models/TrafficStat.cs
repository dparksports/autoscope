using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;

namespace AutoScope.Models
{
    /// <summary>
    /// One aggregated (process → destination IP) row for the Traffic Patterns
    /// tab: lifetime byte/flow totals plus a 24-hour ring of 5-minute buckets
    /// that turns totals into a pattern — windowed rates, a sparkline, and a
    /// conservative beaconing hint. Mutated by the TrafficAggregationService
    /// (background thread, under Sync); display properties are recomputed by
    /// the view on the UI thread via SetWindow, which is also the only place
    /// that fires PropertyChanged.
    /// </summary>
    public class TrafficStat : INotifyPropertyChanged, IResolvableHost
    {
        public const int BucketCount = 288;                             // 24h of 5-min buckets
        public static readonly TimeSpan BucketSpan = TimeSpan.FromMinutes(5);

        public string ProcessName { get; }
        public string DestIp { get; }
        public string Key => $"{ProcessName}|{DestIp}";

        public string RemoteIp => DestIp;

        // Lifetime totals (guard with Sync)
        public long TxBytes { get; private set; }
        public long RxBytes { get; private set; }
        public long Flows { get; private set; }
        public DateTime FirstSeenUtc { get; private set; }
        public DateTime LastSeenUtc { get; private set; }

        // Day-over-day history (UTC date "yyyy-MM-dd" → totals), for exports
        public Dictionary<string, DayTotals> Daily { get; } = new();

        /// <summary>Pids this process name was seen connecting from (capped).</summary>
        public IReadOnlyCollection<int> Pids => _pids;
        private readonly HashSet<int> _pids = new();

        /// <summary>Destination ports seen on flows to this IP (capped).</summary>
        public IReadOnlyCollection<int> Ports => _ports;
        private readonly HashSet<int> _ports = new();

        internal readonly object Sync = new();
        internal readonly Bucket[] Buckets = new Bucket[BucketCount];

        /// <summary>One 5-minute slot of the 24h ring; Abs is the absolute bucket
        /// index so a reused slot can be told apart from a fresh one.</summary>
        internal struct Bucket
        {
            public long Abs;
            public long Tx, Rx, Flows;
        }

        public TrafficStat(string processName, string destIp)
        {
            ProcessName = processName;
            DestIp = destIp;
        }

        // -----------------------------------------------------------------------
        // Aggregation (TrafficAggregationService, background thread)
        // -----------------------------------------------------------------------

        internal void Add(long tx, long rx, int port, int pid, DateTime endedUtc)
        {
            lock (Sync)
            {
                TxBytes += tx;
                RxBytes += rx;
                Flows++;
                if (FirstSeenUtc == default || endedUtc < FirstSeenUtc) FirstSeenUtc = endedUtc;
                if (endedUtc > LastSeenUtc) LastSeenUtc = endedUtc;
                if (_pids.Count < 32) _pids.Add(pid);
                if (_ports.Count < 16) _ports.Add(port);

                long abs = endedUtc.Ticks / BucketSpan.Ticks;
                int slot = (int)(abs % BucketCount);
                var b = Buckets[slot];
                if (b.Abs != abs) b = default;
                b.Abs = abs;
                b.Tx += tx;
                b.Rx += rx;
                b.Flows++;
                Buckets[slot] = b;

                string day = endedUtc.ToString("yyyy-MM-dd");
                var dayTotals = Daily.TryGetValue(day, out var d) ? d : new DayTotals();
                dayTotals.Tx += tx;
                dayTotals.Rx += rx;
                dayTotals.Flows++;
                Daily[day] = dayTotals;
            }
        }

        /// <summary>Rebuilds a stat from persisted state (TrafficAggregationService.LoadState).</summary>
        internal void RestoreFrom(long tx, long rx, long flows, DateTime firstUtc, DateTime lastUtc,
            IEnumerable<int> pids, IEnumerable<int> ports,
            IEnumerable<KeyValuePair<string, DayTotals>> daily,
            IEnumerable<(long Abs, long Tx, long Rx, long Flows)> buckets)
        {
            lock (Sync)
            {
                TxBytes = tx;
                RxBytes = rx;
                Flows = flows;
                FirstSeenUtc = firstUtc;
                LastSeenUtc = lastUtc;
                foreach (int pid in pids) if (_pids.Count < 32) _pids.Add(pid);
                foreach (int port in ports) if (_ports.Count < 16) _ports.Add(port);
                foreach (var kv in daily) Daily[kv.Key] = kv.Value;
                foreach (var b in buckets)
                {
                    if (b.Tx <= 0 && b.Rx <= 0 && b.Flows <= 0) continue;
                    int slot = (int)(b.Abs % BucketCount);
                    if (slot < 0) slot += BucketCount;
                    Buckets[slot] = new Bucket { Abs = b.Abs, Tx = b.Tx, Rx = b.Rx, Flows = b.Flows };
                }
            }
        }

        /// <summary>Sums the buckets strictly after <paramref name="sinceUtc"/> (inclusive window start).</summary>
        internal (long Tx, long Rx, long Flows) SumSince(DateTime sinceUtc)
        {
            long minAbs = sinceUtc.Ticks / BucketSpan.Ticks;
            long tx = 0, rx = 0, flows = 0;
            lock (Sync)
            {
                foreach (var b in Buckets)
                {
                    if (b.Abs < minAbs) continue;
                    tx += b.Tx; rx += b.Rx; flows += b.Flows;
                }
            }
            return (tx, rx, flows);
        }

        // -----------------------------------------------------------------------
        // Display window (view, UI thread)
        // -----------------------------------------------------------------------

        private string _hostname;
        private bool _windowIsAllTime = true;
        private long _windowTx, _windowRx, _windowFlows;
        private string _patternDisplay, _patternHint;
        private string _rateDisplay = "—", _lastSeenDisplay;
        private TimeSpan _windowSpan = TimeSpan.Zero;

        /// <summary>Recomputes everything the grid shows. windowStartUtc == null → lifetime.</summary>
        public void SetWindow(DateTime? windowStartUtc)
        {
            long tx, rx, flows;
            if (windowStartUtc == null)
            {
                lock (Sync) { tx = TxBytes; rx = RxBytes; flows = Flows; }
                _windowIsAllTime = true;
                _windowSpan = TimeSpan.Zero;
            }
            else
            {
                (tx, rx, flows) = SumSince(windowStartUtc.Value);
                _windowIsAllTime = false;
                _windowSpan = DateTime.UtcNow - windowStartUtc.Value;
                if (_windowSpan <= TimeSpan.Zero) _windowSpan = BucketSpan;
            }

            // Fire only what actually changed: the grid live-sorts and live-
            // filters on WindowTotal, so every event costs a reshape pass.
            if (_windowTx != tx)
            {
                _windowTx = tx;
                Fire(nameof(WindowTx)); Fire(nameof(TxDisplay));
                Fire(nameof(WindowTotal)); Fire(nameof(TotalDisplay));
            }
            if (_windowRx != rx)
            {
                _windowRx = rx;
                Fire(nameof(WindowRx)); Fire(nameof(RxDisplay));
                Fire(nameof(WindowTotal)); Fire(nameof(TotalDisplay));
            }
            if (_windowFlows != flows)
            {
                _windowFlows = flows;
                Fire(nameof(WindowFlows)); Fire(nameof(FlowsDisplay));
            }

            ComputePattern();

            string rate = _windowIsAllTime || _windowSpan <= TimeSpan.Zero
                ? "—"
                : FormatBytes((long)(_windowTx / _windowSpan.TotalSeconds)) + "/s ↑";
            if (_rateDisplay != rate)
            {
                _rateDisplay = rate;
                Fire(nameof(RateDisplay));
            }

            string lastSeen = LastSeenUtc == default ? "—" : LastSeenUtc.ToLocalTime().ToString("HH:mm:ss");
            if (_lastSeenDisplay != lastSeen)
            {
                _lastSeenDisplay = lastSeen;
                Fire(nameof(LastSeenDisplay));
            }
        }

        private void Fire(string name) => OnPropertyChanged(name);

        public long WindowTx => _windowTx;
        public long WindowRx => _windowRx;
        public long WindowTotal => _windowTx + _windowRx;
        public long WindowFlows => _windowFlows;
        public bool WindowIsAllTime => _windowIsAllTime;

        public string TxDisplay => FormatBytes(_windowTx) + " ↑";
        public string RxDisplay => FormatBytes(_windowRx) + " ↓";
        public string TotalDisplay => FormatBytes(_windowTx + _windowRx);
        public string FlowsDisplay => _windowFlows.ToString("N0");
        public string PidsDisplay => JoinCapped(_pids);
        public string PortsDisplay => JoinCapped(_ports);
        public string LastSeenDisplay => _lastSeenDisplay ?? "—";

        /// <summary>Average outbound rate across the selected window (blank for all-time).</summary>
        public string RateDisplay => _rateDisplay;

        /// <summary>Compact 24-hour sparkline of outbound bytes, one glyph per hour.</summary>
        public string PatternDisplay => _patternDisplay;

        /// <summary>Non-empty when the last hours look beacon-like (regular cadence, similar sizes).</summary>
        public string PatternHint => _patternHint;

        // -----------------------------------------------------------------------
        // Hostname (DnsResolutionService updates this; grid restyles via IsResolved)
        // -----------------------------------------------------------------------

        public string Hostname
        {
            get => _hostname;
            set
            {
                if (_hostname != value)
                {
                    _hostname = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(IsResolved));
                }
            }
        }

        public bool IsResolved =>
            !string.IsNullOrEmpty(_hostname) && _hostname != DestIp && _hostname != "0.0.0.0" && _hostname != "::";

        // -----------------------------------------------------------------------
        // Pattern analysis
        // -----------------------------------------------------------------------

        private const string Glyphs = "▁▂▃▄▅▆▇█";

        private void ComputePattern()
        {
            // 24 hourly sums from the tx ring, oldest → newest
            long absNow = DateTime.UtcNow.Ticks / BucketSpan.Ticks;
            var hours = new long[24];
            lock (Sync)
            {
                foreach (var b in Buckets)
                {
                    if (b.Tx <= 0) continue;
                    long hoursAgo = (absNow - b.Abs) / 12;   // 12 buckets per hour
                    if (hoursAgo is >= 0 and < 24) hours[23 - (int)hoursAgo] += b.Tx;
                }
            }

            long max = hours.Max();
            var sb = new StringBuilder(24);
            foreach (long h in hours)
                sb.Append(h <= 0 ? '·' : Glyphs[Math.Min(Glyphs.Length - 1, (int)(h * Glyphs.Length / max))]);
            if (_patternDisplay != sb.ToString())
            {
                _patternDisplay = sb.ToString();
                OnPropertyChanged(nameof(PatternDisplay));
            }

            // Beaconing hint, evaluated on the last 2 hours of buckets: needs
            // ≥6 active buckets whose inter-bucket gaps are all equal (±1) and
            // whose per-bucket tx stays within ±60% of the mean. Deliberately
            // conservative — it suggests a look, never an accusation.
            var active = new List<(long Abs, long Tx)>();
            lock (Sync)
            {
                foreach (var b in Buckets)
                {
                    if (b.Tx > 0 && absNow - b.Abs < 24) active.Add((b.Abs, b.Tx));
                }
            }
            active.Sort((a, b) => a.Abs.CompareTo(b.Abs));

            string hint = "";
            if (active.Count >= 6)
            {
                var gaps = new long[active.Count - 1];
                for (int i = 1; i < active.Count; i++) gaps[i - 1] = active[i].Abs - active[i - 1].Abs;
                bool regular = gaps.All(g => Math.Abs(g - gaps[0]) <= 1) && gaps[0] is >= 1 and <= 12;

                double mean = active.Average(a => (double)a.Tx);
                double spread = active.Max(a => (double)a.Tx) - active.Min(a => (double)a.Tx);
                bool similar = mean > 0 && spread / mean <= 1.2;

                if (regular && similar)
                    hint = $"⚠ beacon-like: every {gaps[0] * 5} min, ~{FormatBytes((long)mean)}";
            }
            if (_patternHint != hint)
            {
                _patternHint = hint;
                OnPropertyChanged(nameof(PatternHint));
            }
        }

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        private static string JoinCapped(IEnumerable<int> values) =>
            values == null ? "—" : string.Join(",", values.Take(8));

        internal static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes}B";
            if (bytes < 1048576) return $"{bytes / 1024.0:F0}KB";
            if (bytes < 1073741824) return $"{bytes / 1048576.0:F1}MB";
            return $"{bytes / 1073741824.0:F2}GB";
        }

        public event PropertyChangedEventHandler PropertyChanged;
        private void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        public struct DayTotals
        {
            public long Tx { get; set; }
            public long Rx { get; set; }
            public long Flows { get; set; }
        }
    }
}
