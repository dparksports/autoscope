using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Threading;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// Folds every finalized TCP flow from the app-level TcpStreamCaptureService
    /// into (process name → destination IP) TrafficStat rows with byte totals,
    /// a 24h bucket ring, and day-over-day history. Attached once at app start
    /// (MainWindow), so patterns accumulate whenever ANY tab runs the capture —
    /// the Traffic Patterns tab is just a viewer for this state.
    ///
    /// Direction rule: whichever flow endpoint is on this machine is "us"; the
    /// other endpoint is the destination, and Tx is the local→remote direction
    /// (normally the client direction, inverted for inbound connections).
    /// Flows Sysmon never attributed land under "(unattributed)".
    /// </summary>
    public sealed class TrafficAggregationService
    {
        public static readonly TrafficAggregationService Shared = new();

        private readonly ConcurrentDictionary<string, TrafficStat> _stats = new(StringComparer.Ordinal);
        private readonly object _persistLock = new();
        private HashSet<string> _localIps = new(0, StringComparer.Ordinal);
        private Timer _timer;
        private int _running;
        private bool _dirty;
        private long _flowsAggregated;

        private const int MaxKeys = 5000;        // eviction guard for the persisted state
        private const int MaxDailyDays = 30;

        public static string DataDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoScope", "traffic");

        private static string StatePath => Path.Combine(DataDir, "patterns.json");

        public long FlowsAggregated => Interlocked.Read(ref _flowsAggregated);
        public int KeyCount => _stats.Count;

        private TrafficAggregationService() { }

        /// <summary>Subscribes to the shared capture. Call once, before Start.</summary>
        public void Attach(TcpStreamCaptureService capture)
        {
            capture.OnFlowFinalized += OnFlowFinalized;
        }

        public void Start()
        {
            if (Interlocked.Exchange(ref _running, 1) == 1) return;
            RefreshLocalIps();
            LoadState();
            _timer = new Timer(_ =>
            {
                RefreshLocalIps();
                PersistIfDirty();
            }, null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
        }

        public void Shutdown()
        {
            if (Interlocked.Exchange(ref _running, 0) == 0) return;
            _timer?.Dispose();
            _timer = null;
            Persist();
        }

        // -----------------------------------------------------------------------
        // Aggregation
        // -----------------------------------------------------------------------

        private void OnFlowFinalized(TcpFlowRecord flow)
        {
            try
            {
                // Split "ip:port" endpoints (IPv4 capture, but LastIndexOf is
                // IPv6-safe anyway)
                (string clientIp, int clientPort) = SplitEndpoint(flow.ClientEndpoint);
                (string serverIp, int serverPort) = SplitEndpoint(flow.ServerEndpoint);
                if (clientIp == null || serverIp == null) return;

                bool outbound = !_localIps.Contains(serverIp);   // client remote → inbound to us
                string destIp = outbound ? serverIp : clientIp;
                int destPort = outbound ? serverPort : clientPort;
                long tx = outbound ? flow.ClientBytes : flow.ServerBytes;
                long rx = outbound ? flow.ServerBytes : flow.ClientBytes;

                string process = flow.Pid > 0 && !string.IsNullOrEmpty(flow.Image)
                    ? Path.GetFileName(flow.Image)
                    : "(unattributed)";

                // Honor Process Monitor's ignore list: a process the user told
                // the app to stop listing stays out of the pattern table too.
                if (process != "(unattributed)" && SysmonWatcherService.IsIgnoredByFile(process))
                    return;

                var stat = _stats.GetOrAdd($"{process}|{destIp}", _ => new TrafficStat(process, destIp));
                stat.Add(tx, rx, destPort, flow.Pid, flow.EndedUtc);
                Interlocked.Increment(ref _flowsAggregated);
                _dirty = true;
            }
            catch { /* one bad flow never stops aggregation */ }
        }

        private static (string Ip, int Port) SplitEndpoint(string endpoint)
        {
            if (string.IsNullOrEmpty(endpoint)) return (null, 0);
            int colon = endpoint.LastIndexOf(':');
            if (colon <= 0 || colon == endpoint.Length - 1) return (null, 0);
            return int.TryParse(endpoint[(colon + 1)..], out int port)
                ? (endpoint[..colon], port)
                : (null, 0);
        }

        private void RefreshLocalIps()
        {
            try
            {
                var ips = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                    .Select(a => a.Address.ToString())
                    .ToHashSet(StringComparer.Ordinal);
                if (ips.Count > 0) _localIps = ips;
            }
            catch { /* keep the last known set */ }
        }

        // -----------------------------------------------------------------------
        // View API
        // -----------------------------------------------------------------------

        /// <summary>
        /// All rows, biggest lifetime totals first. Rows for processes on the
        /// Process Monitor ignore list are hidden (their aggregation resumes
        /// if the process is ever un-ignored; the history stays intact).
        /// </summary>
        public IReadOnlyList<TrafficStat> Snapshot() =>
            _stats.Values
                .Where(s => s.ProcessName == "(unattributed)" ||
                            !SysmonWatcherService.IsIgnoredByFile(s.ProcessName))
                .OrderByDescending(s => s.TxBytes + s.RxBytes)
                .ToList();

        /// <summary>Clears everything and removes the persisted state.</summary>
        public void Reset()
        {
            _stats.Clear();
            Interlocked.Exchange(ref _flowsAggregated, 0);
            lock (_persistLock)
            {
                try { File.Delete(StatePath); } catch { }
            }
        }

        // -----------------------------------------------------------------------
        // Persistence
        // -----------------------------------------------------------------------

        private void PersistIfDirty()
        {
            if (!_dirty) return;
            Persist();
        }

        private void Persist()
        {
            try
            {
                Directory.CreateDirectory(DataDir);

                // Evict the smallest rows when over budget so the file stays bounded
                var rows = _stats.Values.OrderByDescending(s => s.TxBytes + s.RxBytes).Take(MaxKeys).ToList();

                var state = new PersistedState { SavedUtc = DateTime.UtcNow };
                foreach (var stat in rows)
                {
                    lock (stat.Sync)
                    {
                        long absNow = DateTime.UtcNow.Ticks / TrafficStat.BucketSpan.Ticks;
                        long minAbs = absNow - TrafficStat.BucketCount;   // keep the last 24h only

                        var entry = new PersistedStat
                        {
                            Process = stat.ProcessName,
                            Ip = stat.DestIp,
                            Tx = stat.TxBytes,
                            Rx = stat.RxBytes,
                            Flows = stat.Flows,
                            FirstUtc = stat.FirstSeenUtc,
                            LastUtc = stat.LastSeenUtc,
                            Pids = stat.Pids.ToArray(),
                            Ports = stat.Ports.ToArray(),
                            Daily = stat.Daily
                                .Where(kv => IsRecentDay(kv.Key))
                                .ToDictionary(kv => kv.Key, kv => kv.Value)
                        };
                        foreach (var b in stat.Buckets)
                        {
                            if (b.Abs < minAbs || (b.Tx | b.Rx | b.Flows) == 0) continue;
                            entry.Buckets.Add(new PersistedBucket { A = b.Abs, T = b.Tx, R = b.Rx, F = b.Flows });
                        }
                        state.Keys.Add(entry);
                    }
                }

                lock (_persistLock)
                {
                    File.WriteAllText(StatePath,
                        JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = false }));
                }
                _dirty = false;
            }
            catch { /* persistence is best-effort; aggregation itself already succeeded */ }
        }

        private static bool IsRecentDay(string day)
        {
            if (DateTime.TryParse(day, out var date))
                return (DateTime.UtcNow - date.ToUniversalTime()).TotalDays <= MaxDailyDays;
            return false;
        }

        private void LoadState()
        {
            try
            {
                if (!File.Exists(StatePath)) return;
                var state = JsonSerializer.Deserialize<PersistedState>(File.ReadAllText(StatePath));
                if (state?.Keys == null) return;

                foreach (var entry in state.Keys)
                {
                    if (string.IsNullOrEmpty(entry.Process) || string.IsNullOrEmpty(entry.Ip)) continue;
                    var stat = new TrafficStat(entry.Process, entry.Ip);
                    stat.RestoreFrom(entry.Tx, entry.Rx, entry.Flows, entry.FirstUtc, entry.LastUtc,
                        entry.Pids, entry.Ports, entry.Daily,
                        entry.Buckets.Select(b => (b.A, b.T, b.R, b.F)));
                    _stats[stat.Key] = stat;
                }
            }
            catch { /* unreadable state — start fresh rather than fail */ }
        }

        // -----------------------------------------------------------------------
        // JSON DTOs (short keys; the file is rewritten whole on every save)
        // -----------------------------------------------------------------------

        private sealed class PersistedState
        {
            public DateTime SavedUtc { get; set; }
            public List<PersistedStat> Keys { get; set; } = new();
        }

        private sealed class PersistedStat
        {
            public string Process { get; set; }
            public string Ip { get; set; }
            public long Tx { get; set; }
            public long Rx { get; set; }
            public long Flows { get; set; }
            public DateTime FirstUtc { get; set; }
            public DateTime LastUtc { get; set; }
            public int[] Pids { get; set; } = Array.Empty<int>();
            public int[] Ports { get; set; } = Array.Empty<int>();
            public Dictionary<string, TrafficStat.DayTotals> Daily { get; set; } = new();
            public List<PersistedBucket> Buckets { get; set; } = new();
        }

        private sealed class PersistedBucket
        {
            public long A { get; set; }
            public long T { get; set; }
            public long R { get; set; }
            public long F { get; set; }
        }
    }
}
