using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using System.Threading;

namespace AutoScope.Services
{
    /// <summary>
    /// Live monitoring half of the Windows Defender tab:
    ///   • MsMpEng resource sampling every 2s via WMI formatted perf data —
    ///     CPU as % of total machine capacity (PerfProc's PercentProcessorTime
    ///     sums cores, so it divides by core count) plus private working set —
    ///     kept in a 5-minute ring for the sparkline.
    ///   • Defender's own operational event log as a live activity feed:
    ///     scans (1000 started / 1001 finished / 1002 stopped — pairable by
    ///     Scan ID into durations), detections (1116/1117), definition updates
    ///     (2000), cloud-protection activity (2010/2050/2051) and configuration
    ///     changes (5007). Chatty health-report IDs (1150/1151) are skipped.
    /// </summary>
    public sealed class DefenderMonitoringService : IDisposable
    {
        public sealed class ResourceSample
        {
            public DateTime TimeUtc;
            public double ProcCpu;        // % of total machine capacity
            public double MachineCpu;     // % across all cores
            public long WorkingSetPrivate;
        }

        private readonly object _sync = new();
        private readonly Queue<ResourceSample> _history = new();
        private readonly List<DefenderActivityItem> _feed = new();
        private readonly Dictionary<string, DefenderScanItem> _openScans = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<DefenderScanItem> _scans = new();
        private ResourceSample _latest;
        private Timer _sampleTimer;
        private EventLogWatcher _watcher;
        private bool _disposed;

        private const int HistorySeconds = 300;   // 5 minutes of 2s samples
        private const int FeedCap = 200;
        private const int ScanCap = 20;

        private static readonly HashSet<int> FeedIdSet = new() { 1000, 1001, 1002, 1116, 1117, 2000, 2010, 2050, 2051, 5007 };

        public event Action<DefenderActivityItem> OnActivity;
        public event Action<string> OnError;

        public void Start()
        {
            lock (_sync)
            {
                _feed.Clear();
                _scans.Clear();
                _openScans.Clear();
            }

            // Backfill oldest→newest so scan starts pair with their finishes
            // (the reader returns newest-first)
            foreach (var item in ReadRecentActivity(60).AsEnumerable().Reverse())
                AppendActivity(item, raise: false);

            try
            {
                var query = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational",
                    PathType.LogName, "*[System[(EventID=1000 or EventID=1001 or EventID=1002 or EventID=1116 or EventID=1117 or EventID=2000 or EventID=2010 or EventID=2050 or EventID=2051 or EventID=5007)]]");
                _watcher = new EventLogWatcher(query);
                _watcher.EventRecordWritten += Watcher_EventRecordWritten;
                _watcher.Enabled = true;
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Defender activity feed unavailable: {ex.Message}");
            }

            _sampleTimer = new Timer(_ => Sample(), null, TimeSpan.Zero, TimeSpan.FromSeconds(2));
        }

        public void Stop()
        {
            _sampleTimer?.Dispose();
            _sampleTimer = null;
            _watcher?.Dispose();
            _watcher = null;
        }

        // -----------------------------------------------------------------------
        // Resource sampling
        // -----------------------------------------------------------------------

        public ResourceSample Latest
        {
            get { lock (_sync) return _latest; }
        }

        public List<ResourceSample> HistorySnapshot()
        {
            lock (_sync) return _history.ToList();
        }

        private void Sample()
        {
            try
            {
                double procCpu = 0;
                long workingSet = 0;
                bool running = false;

                using (var searcher = new ManagementObjectSearcher(
                    "SELECT Name, PercentProcessorTime, WorkingSetPrivate FROM Win32_PerfFormattedData_PerfProc_Process WHERE Name LIKE 'MsMpEng%'"))
                using (var results = searcher.Get())
                {
                    foreach (ManagementObject o in results)
                    {
                        running = true;
                        procCpu += Convert.ToDouble(o["PercentProcessorTime"], CultureInfo.InvariantCulture);
                        workingSet += Convert.ToInt64(o["WorkingSetPrivate"], CultureInfo.InvariantCulture);
                    }
                }

                double machineCpu = 0;
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name = '_Total'"))
                using (var results = searcher.Get())
                {
                    foreach (ManagementObject o in results)
                        machineCpu = Convert.ToDouble(o["PercentProcessorTime"], CultureInfo.InvariantCulture);
                }

                int cores = Math.Max(1, Environment.ProcessorCount);
                var sample = new ResourceSample
                {
                    TimeUtc = DateTime.UtcNow,
                    // WMI percent = 100 per core; scale to whole-machine share
                    ProcCpu = running ? Math.Max(0, procCpu / cores) : 0,
                    MachineCpu = machineCpu,
                    WorkingSetPrivate = workingSet
                };

                lock (_sync)
                {
                    _latest = sample;
                    _history.Enqueue(sample);
                    while (_history.Count > HistorySeconds / 2)
                        _history.Dequeue();
                }
            }
            catch
            {
                // One failed WMI poll (WMI restart, perf data rebuild) never
                // stops the sampler; the ring just shows a gap.
            }
        }

        // -----------------------------------------------------------------------
        // Activity feed + scan pairing
        // -----------------------------------------------------------------------

        public IReadOnlyList<DefenderActivityItem> FeedSnapshot()
        {
            lock (_sync) return _feed.ToList();
        }

        public IReadOnlyList<DefenderScanItem> ScanSnapshot()
        {
            lock (_sync) return _scans.OrderByDescending(s => s.StartedUtc).ToList();
        }

        /// <summary>Reads the newest <paramref name="max"/> relevant events, newest first.</summary>
        public List<DefenderActivityItem> ReadRecentActivity(int max)
        {
            var items = new List<DefenderActivityItem>();
            try
            {
                var query = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational",
                    PathType.LogName, "*[System[(EventID=1000 or EventID=1001 or EventID=1002 or EventID=1116 or EventID=1117 or EventID=2000 or EventID=2010 or EventID=2050 or EventID=2051 or EventID=5007)]]");
                using var reader = new EventLogReader(query);
                for (int i = 0; i < max; i++)
                {
                    var record = reader.ReadEvent();
                    if (record == null) break;
                    var item = ParseRecord(record);
                    if (item != null) items.Add(item);
                }
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Could not read Defender event history: {ex.Message}");
            }
            return items;   // newest first
        }

        private void Watcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;
            var item = ParseRecord(e.EventRecord);
            if (item == null) return;
            AppendActivity(item, raise: true);
        }

        private static DefenderActivityItem ParseRecord(EventRecord record)
        {
            int id = record.Id;
            if (!FeedIdSet.Contains(id)) return null;

            string message = (record.FormatDescription() ?? "").Trim();
            if (message.Length > 4000) message = message[..4000] + "…";
            if (message.Length == 0) message = $"(event {id})";

            var item = new DefenderActivityItem
            {
                TimeUtc = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
                EventId = id,
                Summary = message
            };

            // Scan records pair on Scan ID; carry both on the item so the
            // aggregator can open/close scans whichever record arrives first.
            string description = record.FormatDescription() ?? "";
            var m = Regex.Match(description, @"Scan ID:\s*\{?([0-9A-Fa-f\-]{36})\}?");
            if (m.Success) item.ScanId = m.Groups[1].Value;
            m = Regex.Match(description, @"Scan Type:\s*(\w+)");
            if (m.Success) item.ScanType = m.Groups[1].Value;

            return item;
        }

        /// <summary>Adds to feed/scans. Pass oldest→newest for backfill (raise=false).</summary>
        private void AppendActivity(DefenderActivityItem item, bool raise)
        {
            lock (_sync)
            {
                _feed.Insert(0, item);
                while (_feed.Count > FeedCap) _feed.RemoveAt(_feed.Count - 1);

                if (item.ScanId != null)
                {
                    switch (item.EventId)
                    {
                        case 1000:
                            _openScans[item.ScanId] = new DefenderScanItem
                            {
                                ScanType = item.ScanType ?? "Scan",
                                StartedUtc = item.TimeUtc
                            };
                            break;
                        case 1001 or 1002 when _openScans.Remove(item.ScanId, out var scan):
                            scan.EndedUtc = item.TimeUtc;
                            scan.Completed = item.EventId == 1001;
                            _scans.Add(scan);
                            while (_scans.Count > ScanCap) _scans.RemoveAt(0);
                            break;
                    }
                }
            }
            if (raise) OnActivity?.Invoke(item);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
        }
    }

    /// <summary>One Defender operational-log event for the activity feed.
    /// Summary carries the FULL event description (tooltip); the grid cell
    /// shows SummaryFirstLine so rows stay single-height.</summary>
    public class DefenderActivityItem
    {
        public DateTime TimeUtc { get; set; }
        public int EventId { get; set; }
        public string Summary { get; set; }

        /// <summary>First line of the description, for the grid cell.</summary>
        public string SummaryFirstLine
        {
            get
            {
                string s = Summary ?? "";
                int nl = s.IndexOf('\n');
                string line = (nl > 0 ? s[..nl] : s).Trim();
                return line.Length > 160 ? line[..160] + "…" : line;
            }
        }

        public string ScanId { get; set; }   // scan events only
        public string ScanType { get; set; }

        public string TimeDisplay => TimeUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");

        public string Kind => EventId switch
        {
            1000 => "▶ scan started",
            1001 => "✓ scan finished",
            1002 => "⏹ scan stopped",
            1116 => "⚠ malware detected",
            1117 => "⚠ malware remediated",
            2000 => "⤓ definitions updated",
            2010 => "☁ cloud intelligence",
            2050 => "⤒ file uploaded",
            2051 => "⤒ upload failed",
            5007 => "⚙ configuration changed",
            _ => $"event {EventId}"
        };

        /// <summary>Detections and failures tint amber in the feed.</summary>
        public bool IsWarning => EventId is 1116 or 1117 or 2051 or 1002;
    }

    /// <summary>A paired scan: EID 1000 start closed by 1001 (finished) or 1002 (stopped).</summary>
    public class DefenderScanItem
    {
        public string ScanType { get; set; }
        public DateTime StartedUtc { get; set; }
        public DateTime? EndedUtc { get; set; }
        public bool Completed { get; set; }

        public string Display =>
            $"{ScanType} · {StartedUtc.ToLocalTime():MM-dd HH:mm:ss}" +
            (EndedUtc == null ? " · running…" : $" → {EndedUtc.Value.ToLocalTime():HH:mm:ss}" +
             $" · {(EndedUtc.Value - StartedUtc).TotalSeconds:0}s" +
             (Completed ? "" : " · stopped early"));
    }
}
