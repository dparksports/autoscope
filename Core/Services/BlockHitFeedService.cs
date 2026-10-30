using System;
using AutoCommand.Engines.Bridge;
using AutoCommand.Engines.Watch;
using AutoCommand.Engines.Firewall;
using AutoCommand.Engines.Core;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AutoScope.Services
{
    /// <summary>
    /// Joins live Sysmon EID 3 connect attempts (every process, full 4-tuple)
    /// against AutoScope's blocked-target inventory. Windows Firewall blocks
    /// silently in the kernel — an AS-BLOCK hit fails the connect() with
    /// WSAEACCES and emits nothing the app could subscribe to — so this service
    /// synthesizes the missing signal: "process X just tried to reach blocked
    /// IP Y". It is the real-time feed behind the Blocks tab's live section
    /// and the list_recent_block_hits bridge tool. pfirewall.log stays the
    /// secondary source: default-off, per-IP only, no process attribution.
    ///
    /// Hits persist across restarts (JSONL beside the transmissions archive),
    /// so a block that broke a user's browsing an hour ago is still explainable
    /// when they open the tab or ask the AI.
    /// </summary>
    public sealed class BlockHitFeedService
    {
        public static BlockHitFeedService Instance => _instance ??= new BlockHitFeedService();
        private static BlockHitFeedService _instance;

        private const int MaxHits = 2000;
        private static readonly TimeSpan Retain = TimeSpan.FromHours(24);
        private static readonly TimeSpan InventoryRefresh = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan SaveInterval = TimeSpan.FromSeconds(30);

        /// <summary>Inventory snapshot entry for one blocked IP (≤30s stale).</summary>
        public sealed class BlockedInfo
        {
            public string Ip;
            public int Rules;
            public int EnabledRules;
            public string Class;
            public DateTime? Created;   // from v2 provenance; null for legacy rules
        }

        /// <summary>One blocked connect attempt as synthesized from Sysmon EID 3.</summary>
        public sealed class BlockHit
        {
            public DateTime TimeUtc { get; set; }
            public string Image { get; set; }
            public int Pid { get; set; }
            public string DestIp { get; set; }
            public int DestPort { get; set; }
            public string Protocol { get; set; }
            public string MatchKind { get; set; }   // "ip" | "app"
        }

        /// <summary>Per (process, destination) rollup for the tab and the bridge.</summary>
        public sealed class HitAggregate
        {
            public string Image, Process, DestIp, MatchKind;
            public int Pid, DestPort, Count;
            public DateTime FirstUtc, LastUtc;
        }

        private readonly object _gate = new();
        private readonly List<BlockHit> _hits = new();
        private Dictionary<string, BlockedInfo> _blockedIps = new(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _blockedApps = new(StringComparer.OrdinalIgnoreCase);
        private SysmonConnectWatcherService _watcher;
        private Timer _refreshTimer, _saveTimer;
        private bool _running, _dirty;

        public DateTime LastRefreshUtc { get; private set; }
        public string LastInventoryError { get; private set; }
        public string WatcherError { get; private set; }
        public bool IsRunning { get { lock (_gate) return _running; } }

        /// <summary>Persistence root; settable for offline self-tests (house pattern).</summary>
        public static string StoreDirectory { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoScope");

        private static string StorePath => Path.Combine(StoreDirectory, "block-hits.jsonl");

        private BlockHitFeedService() { }

        /// <summary>Idempotent: safe to call from the Blocks tab, bridge handlers, startup.</summary>
        public void Start()
        {
            lock (_gate)
            {
                if (_running) return;
                _running = true;
            }
            Load();
            _watcher = new SysmonConnectWatcherService();
            _watcher.OnError += msg => WatcherError = msg;   // e.g. Sysmon not installed
            _watcher.OnConnect += HandleConnect;
            _watcher.Start();
            _ = RefreshInventoryAsync();
            _refreshTimer = new Timer(_ => _ = RefreshInventoryAsync(), null,
                InventoryRefresh, InventoryRefresh);
            _saveTimer = new Timer(_ => SaveIfDirty(), null, SaveInterval, SaveInterval);
        }

        public void Stop()
        {
            lock (_gate)
            {
                if (!_running) return;
                _running = false;
                _refreshTimer?.Dispose(); _refreshTimer = null;
                _saveTimer?.Dispose(); _saveTimer = null;
            }
            _watcher?.Stop();
            _watcher = null;
            SaveIfDirty();
        }

        private async Task RefreshInventoryAsync()
        {
            try
            {
                var inv = await AutoScope.Services.Fw.Service.GetBlockedInventoryAsync();
                var ips = new Dictionary<string, BlockedInfo>(StringComparer.OrdinalIgnoreCase);
                var apps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var t in inv)
                {
                    if (t.EnabledRules == 0) continue;   // fully disabled blocks never fire
                    if (t.Kind == "ip")
                        ips[t.Ip] = new BlockedInfo { Ip = t.Ip, Rules = t.Rules, EnabledRules = t.EnabledRules, Class = t.Class, Created = t.Created };
                    else if (!string.IsNullOrEmpty(t.AppPath))
                        apps.Add(t.AppPath.ToLowerInvariant());
                }
                lock (_gate)
                {
                    _blockedIps = ips;
                    _blockedApps = apps;
                    LastRefreshUtc = DateTime.UtcNow;
                    LastInventoryError = null;
                }
            }
            catch (Exception ex)
            {
                lock (_gate) LastInventoryError = ex.Message;
            }
        }

        private void HandleConnect(SysmonConnectEvent e)
        {
            try
            {
                if (string.IsNullOrEmpty(e.DestIp) || string.IsNullOrEmpty(e.Image)) return;
                string kind;
                lock (_gate)
                {
                    if (_blockedIps.ContainsKey(e.DestIp)) kind = "ip";
                    else if (_blockedApps.Contains(e.Image.ToLowerInvariant())) kind = "app";
                    else return;
                }
                lock (_gate)
                {
                    _hits.Add(new BlockHit
                    {
                        TimeUtc = e.TimeUtc,
                        Image = e.Image,
                        Pid = e.Pid,
                        DestIp = e.DestIp,
                        DestPort = e.DestPort,
                        Protocol = e.Protocol,
                        MatchKind = kind,
                    });
                    _dirty = true;
                    PruneLocked();
                }
            }
            catch { /* a malformed event never takes the feed down */ }
        }

        private void PruneLocked()
        {
            var cutoff = DateTime.UtcNow - Retain;
            int stale = _hits.FindLastIndex(h => h.TimeUtc < cutoff) + 1;
            if (stale > 0) _hits.RemoveRange(0, stale);
            if (_hits.Count > MaxHits) _hits.RemoveRange(0, _hits.Count - MaxHits);
        }

        // ── queries (thread-safe; Blocks tab + AI bridge) ────────────────

        public List<BlockHit> Recent(int minutes, int max = 200)
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-Math.Max(1, minutes));
            lock (_gate)
                return _hits.Where(h => h.TimeUtc >= cutoff)
                            .OrderByDescending(h => h.TimeUtc)
                            .Take(max).ToList();
        }

        public List<HitAggregate> Aggregates(int minutes, int max = 100)
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-Math.Max(1, minutes));
            lock (_gate)
            {
                return _hits.Where(h => h.TimeUtc >= cutoff)
                    .GroupBy(h => new { h.Image, h.Pid, h.DestIp, h.DestPort, h.MatchKind })
                    .Select(g => new HitAggregate
                    {
                        Image = g.Key.Image,
                        Process = Path.GetFileName(g.Key.Image),
                        Pid = g.Key.Pid,
                        DestIp = g.Key.DestIp,
                        DestPort = g.Key.DestPort,
                        MatchKind = g.Key.MatchKind,
                        Count = g.Count(),
                        FirstUtc = g.Min(h => h.TimeUtc),
                        LastUtc = g.Max(h => h.TimeUtc),
                    })
                    .OrderByDescending(a => a.LastUtc)
                    .Take(max).ToList();
            }
        }

        /// <summary>Fast blocked-IP lookup against the ≤30s-stale inventory cache; null = not blocked.</summary>
        public BlockedInfo BlockedIp(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return null;
            lock (_gate) return _blockedIps.TryGetValue(ip, out var b) ? b : null;
        }

        /// <summary>Recent per-IP hit counts from this feed (Sysmon ground truth, not pfirewall.log).</summary>
        public Dictionary<string, int> FeedHitsByIp(int minutes)
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-Math.Max(1, minutes));
            lock (_gate)
                return _hits.Where(h => h.TimeUtc >= cutoff && h.MatchKind == "ip")
                            .GroupBy(h => h.DestIp)
                            .ToDictionary(g => g.Key, g => g.Count());
        }

        // ── persistence: plain JSONL, house pattern ──────────────────────

        private void Load()
        {
            try
            {
                if (!File.Exists(StorePath)) return;
                var loaded = new List<BlockHit>();
                foreach (var line in File.ReadLines(StorePath))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var h = JsonSerializer.Deserialize<BlockHit>(line);
                    if (h?.TimeUtc != null && h.TimeUtc > DateTime.UtcNow - Retain) loaded.Add(h);
                }
                lock (_gate)
                {
                    _hits.Clear();
                    _hits.AddRange(loaded.OrderByDescending(h => h.TimeUtc).Take(MaxHits));
                }
            }
            catch { /* a corrupt store starts fresh, never blocks startup */ }
        }

        private void SaveIfDirty()
        {
            List<BlockHit> snapshot;
            lock (_gate)
            {
                if (!_dirty) return;
                _dirty = false;
                snapshot = _hits.ToList();
            }
            try
            {
                Directory.CreateDirectory(StoreDirectory);
                string tmp = StorePath + ".tmp";
                using (var w = new StreamWriter(tmp))
                    foreach (var h in snapshot)
                        w.WriteLine(JsonSerializer.Serialize(h));
                File.Delete(StorePath);
                File.Move(tmp, StorePath);
            }
            catch { /* offline disk is survivable — the feed stays in memory */ }
        }
    }
}
