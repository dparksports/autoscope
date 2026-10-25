using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// Real-time tracing of process creations for a chosen image family
    /// (python.exe, taskhostw.exe, …) from the Sysmon operational channel:
    /// EID 1 (create, with full parentage), EID 5 (terminate, flips Exited)
    /// and EID 3 (network connect, used to attribute captured TCP flows to
    /// the spawning pid). EID 1 fires for every process creation on the
    /// machine, so records are pre-filtered by a cheap substring scan and
    /// discarded early unless the image passes the caller's filter.
    /// <see cref="Backfill"/> replays the same channel's recent records so a
    /// tab opened after the fact still shows what ran.
    /// </summary>
    public class ImageSpawnWatcherService : IDisposable
    {
        private const string ChannelName = "Microsoft-Windows-Sysmon/Operational";

        private EventLogWatcher _spawnWatcher;
        private EventLogWatcher _exitWatcher;
        private EventLogWatcher _netWatcher;
        private bool _disposed;

        private readonly Func<string, bool> _imageFilter;
        private readonly string _xmlKeyword;
        private readonly bool _venvPairing;

        /// <param name="imageFilter">Client-side image filter (full path in).</param>
        /// <param name="xmlKeyword">Cheap substring pre-filter applied to the raw event XML
        /// before parsing — must match everything imageFilter accepts.</param>
        /// <param name="venvPairing">Enable the python venv launcher/interpreter pairing.</param>
        public ImageSpawnWatcherService(Func<string, bool> imageFilter, string xmlKeyword, bool venvPairing = false)
        {
            _imageFilter = imageFilter;
            _xmlKeyword = xmlKeyword;
            _venvPairing = venvPairing;
        }

        /// <summary>Python family filter: any path containing "python".</summary>
        public static bool IsPythonImage(string image) =>
            !string.IsNullOrEmpty(image) &&
            image.IndexOf("python", StringComparison.OrdinalIgnoreCase) >= 0;

        /// <summary>taskhostw filter: the scheduled-task host binary exactly.</summary>
        public static bool IsTaskhostwImage(string image) =>
            !string.IsNullOrEmpty(image) &&
            image.EndsWith("taskhostw.exe", StringComparison.OrdinalIgnoreCase);

        // Tracked spawns by pid — drives venv pairing and EID 5 lookup. A pid
        // reuse replaces the entry (old rows keep their own copy of the data).
        private readonly Dictionary<int, SpawnItem> _tracked = new();
        private readonly object _trackedLock = new();

        // EID 5 can beat its own EID 1 through the independent watchers;
        // exits with no spawn yet wait here and stamp the item on arrival.
        private readonly Dictionary<int, DateTime> _earlyExits = new();

        // Memory guard for the pid maps on long sessions
        private const int TrackedCap = 20000;

        public event Action<string> OnError;
        public event Action<SpawnItem> OnSpawn;
        public event Action<SpawnItem> OnExited;
        public event Action<SpawnNetworkEvent> OnNetworkConnect;

        public int TrackedCount { get { lock (_trackedLock) return _tracked.Count; } }

        /// <summary>
        /// Distinct python image paths seen spawning — the passive discovery
        /// feed for the instrumentation dialog (every python that actually
        /// ran on this machine, wherever it lives).
        /// </summary>
        public List<string> GetSeenImages()
        {
            lock (_trackedLock)
                return _tracked.Values
                    .Select(i => i.Image)
                    .Where(img => !string.IsNullOrEmpty(img))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
        }

        public void Start()
        {
            try
            {
                _spawnWatcher = Watch("*[System[(EventID=1)]]", Spawn_EventRecordWritten);
                _exitWatcher = Watch("*[System[(EventID=5)]]", Exit_EventRecordWritten);
                _netWatcher = Watch("*[System[(EventID=3)]]", Net_EventRecordWritten);
            }
            catch (EventLogNotFoundException)
            {
                OnError?.Invoke("Sysmon is not installed. Install it from the Sysmon Audit tab — spawn tracing needs it.");
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Failed to start python spawn watcher: {ex.Message}");
            }
        }

        public void Stop()
        {
            _spawnWatcher?.Dispose();
            _spawnWatcher = null;
            _exitWatcher?.Dispose();
            _exitWatcher = null;
            _netWatcher?.Dispose();
            _netWatcher = null;
        }

        private static EventLogWatcher Watch(string xpath, EventHandler<EventRecordWrittenEventArgs> handler)
        {
            var watcher = new EventLogWatcher(
                new EventLogQuery(ChannelName, PathType.LogName, xpath));
            watcher.EventRecordWritten += handler;
            watcher.Enabled = true;
            return watcher;
        }

        // ── Historical replay ────────────────────────────────────────────────

        /// <summary>
        /// Replays the last <paramref name="window"/> of EID 1 / EID 5 records
        /// from the Sysmon channel through the same handlers the live watchers
        /// use — so a tab opened after the fact shows what already ran, with
        /// parentage, venv pairing and Exited stamps intact. Spawns the live
        /// watcher already delivered are skipped (pid-keyed), so racing the
        /// live feed never double-adds a row. Returns the number of spawn rows
        /// replayed.
        /// </summary>
        public int Backfill(TimeSpan window, int maxRows = 400)
        {
            int replayed = 0;
            try
            {
                string xpath =
                    "*[System[(EventID=1 or EventID=5) and TimeCreated[timediff(@SystemTime) <= " +
                    Math.Max(0, (int)window.TotalMilliseconds) + "]]]";

                var records = new List<(DateTime time, EventRecord rec)>();
                using (var reader = new EventLogReader(new EventLogQuery(ChannelName, PathType.LogName, xpath)))
                {
                    EventRecord rec;
                    while ((rec = reader.ReadEvent()) != null)
                        records.Add((rec.TimeCreated?.ToUniversalTime() ?? DateTime.MinValue, rec));
                }

                // Newest-first for the cap, oldest-first for the replay
                var spawns = records.Where(r => r.rec.Id == 1).OrderByDescending(r => r.time).Take(maxRows)
                                    .OrderBy(r => r.time).ToList();
                var exits = records.Where(r => r.rec.Id == 5).Select(r => r.rec);
                var replay = spawns.Select(r => r.rec)
                    .Concat(exits)
                    .OrderBy(r => r.TimeCreated?.ToUniversalTime() ?? DateTime.MinValue)
                    .ToList();

                foreach (var rec in replay)
                {
                    if (rec.Id == 1)
                    {
                        if (HandleSpawnRecord(rec, isReplay: true)) replayed++;
                    }
                    else
                    {
                        HandleExitRecord(rec);
                    }
                }
                foreach (var (_, rec) in records) rec.Dispose();
            }
            catch (EventLogNotFoundException)
            {
                OnError?.Invoke("Sysmon is not installed. Install it from the Sysmon Audit tab — spawn tracing needs it.");
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Spawn history replay failed: {ex.Message}");
            }
            return replayed;
        }

        // ── EID 1: process create ────────────────────────────────────────────

        private void Spawn_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;
            HandleSpawnRecord(e.EventRecord, isReplay: false);
        }

        /// <summary>Returns true when the record produced a spawn.</summary>
        private bool HandleSpawnRecord(EventRecord record, bool isReplay)
        {
            try
            {
                var item = ParseSpawnRecord(record, _imageFilter, _xmlKeyword);
                if (item == null) return false;

                lock (_trackedLock)
                {
                    // Live watcher won the race for this pid — never double-add
                    if (isReplay && _tracked.ContainsKey(item.Pid)) return false;

                    PairWithLauncher(item);

                    // Terminate event already observed for this pid — the
                    // process was shorter than the watcher round-trip.
                    if (_earlyExits.Remove(item.Pid)) item.Exited = true;

                    PruneIfNeeded();
                    _tracked[item.Pid] = item;
                }
                OnSpawn?.Invoke(item);
                return true;
            }
            catch { /* a malformed record never takes the watcher down */ }
            return false;
        }

        /// <summary>
        /// Parse a Sysmon EID 1 record into a SpawnItem — null when the record
        /// is not a process-create, fails the image filter, or has no parseable
        /// pid. Shared by the live watcher and the taskhostw tab's historical
        /// backfill (TaskAttributionService.Backfill) so both paths build
        /// identical rows from the same field parsing.
        /// </summary>
        public static SpawnItem ParseSpawnRecord(EventRecord record, Func<string, bool> imageFilter, string xmlKeyword)
        {
            try
            {
                if (record == null || record.Id != 1) return null;
                string xml = record.ToXml();
                if (xmlKeyword != null && xml.IndexOf(xmlKeyword, StringComparison.OrdinalIgnoreCase) < 0) return null;

                var fields = ParseFields(xml);
                if (fields == null || !imageFilter(GetValue(fields, "Image"))) return null;

                int pid = ParsePid(GetValue(fields, "ProcessId"));
                if (pid <= 0) return null;

                return new SpawnItem
                {
                    TimeUtc = ParseUtcTime(GetValue(fields, "UtcTime"), record.TimeCreated),
                    Pid = pid,
                    ProcessGuid = GetValue(fields, "ProcessGuid")?.Trim('{', '}'),
                    Image = GetValue(fields, "Image"),
                    CommandLine = GetValue(fields, "CommandLine"),
                    ParentPid = ParsePid(GetValue(fields, "ParentProcessId")),
                    ParentImage = GetValue(fields, "ParentImage"),
                    ParentCommandLine = GetValue(fields, "ParentCommandLine"),
                    User = GetValue(fields, "User"),
                    IntegrityLevel = GetValue(fields, "IntegrityLevel"),
                    Hashes = GetValue(fields, "Hashes"),
                    Source = "sysmon"
                };
            }
            catch { return null; }
        }

        /// <summary>
        /// Venv pairing: a venv command spawns two processes — the launcher
        /// (venv\Scripts\python.exe) and the real base interpreter as its
        /// child. When the new spawn's parent is a tracked, still-running
        /// python spawn with a different image in a \Scripts\ folder, the
        /// child is the real interpreter: it carries the pair and the launcher
        /// row is absorbed into the detail pane. Correlation is purely
        /// ParentProcessId-based — nothing inside the venv is ever read.
        /// </summary>
        private void PairWithLauncher(SpawnItem item)
        {
            if (!_venvPairing) return;
            if (item.ParentPid <= 0) return;
            if (!_tracked.TryGetValue(item.ParentPid, out var parent)) return;
            if (parent.Exited || parent.Pid == item.Pid) return;

            if (IsVenvLauncherImage(parent.Image) &&
                !string.Equals(parent.Image, item.Image, StringComparison.OrdinalIgnoreCase))
            {
                item.SetVenvLauncher(parent);
                parent.MarkAbsorbedLauncher();
            }
            else
            {
                // python spawning python without a venv layout (multiprocessing,
                // subprocess.run([...python...])) — keep both rows, badge the child.
                item.SetPythonParent();
            }
        }

        private static bool IsVenvLauncherImage(string image) =>
            !string.IsNullOrEmpty(image) &&
            image.IndexOf("\\Scripts\\", StringComparison.OrdinalIgnoreCase) >= 0 &&
            IsPythonImage(image);

        private void PruneIfNeeded()
        {
            if (_tracked.Count < TrackedCap) return;
            // Drop the oldest tenth by spawn time; view rows keep their own data.
            foreach (int pid in _tracked
                .OrderBy(kv => kv.Value.TimeUtc)
                .Take(Math.Max(1, _tracked.Count / 10))
                .Select(kv => kv.Key)
                .ToList())
            {
                _tracked.Remove(pid);
            }
        }

        // ── EID 5: process terminate ─────────────────────────────────────────

        private void Exit_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;
            try { HandleExitRecord(e.EventRecord); } catch { }
        }

        private void HandleExitRecord(EventRecord record)
        {
            try
            {
                var fields = ParseIfMatchedRecord(record, _xmlKeyword);
                if (fields == null) return;

                int pid = ParsePid(GetValue(fields, "ProcessId"));
                if (pid <= 0) return;

                SpawnItem item;
                lock (_trackedLock)
                {
                    if (!_tracked.TryGetValue(pid, out item))
                    {
                        // EID 1 not processed yet — hold the exit for the spawn handler.
                        _earlyExits[pid] = DateTime.UtcNow;
                        if (_earlyExits.Count > 1024)
                            foreach (var stale in _earlyExits.Where(kv =>
                                     (DateTime.UtcNow - kv.Value).TotalMinutes > 10).ToList())
                                _earlyExits.Remove(stale.Key);
                        return;
                    }
                    item.Exited = true;
                }
                OnExited?.Invoke(item);
            }
            catch { }
        }

        // ── EID 3: network connect (python images only) ─────────────────────

        private void Net_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                var fields = ParseIfMatched(e, _xmlKeyword);
                if (fields == null) return;

                string proto = GetValue(fields, "Protocol");
                if (!string.Equals(proto, "tcp", StringComparison.OrdinalIgnoreCase)) return;

                int pid = ParsePid(GetValue(fields, "ProcessId"));
                if (pid <= 0) return;

                OnNetworkConnect?.Invoke(new SpawnNetworkEvent
                {
                    TimeUtc = ParseUtcTime(GetValue(fields, "UtcTime"), e.EventRecord?.TimeCreated),
                    Pid = pid,
                    Image = GetValue(fields, "Image"),
                    SourceIp = GetValue(fields, "SourceIp"),
                    SourcePort = ParsePort(GetValue(fields, "SourcePort")),
                    DestIp = GetValue(fields, "DestinationIp"),
                    DestPort = ParsePort(GetValue(fields, "DestinationPort"))
                });
            }
            catch { }
        }

        // ── EventData helpers ────────────────────────────────────────────────
        //
        // EventData is parsed BY NAME, never by property index — the field
        // order varies across Sysmon versions. EID 1 fires for every process
        // creation on the machine, so the XML gets a cheap substring scan
        // before anything is parsed into a DOM (a cmdline/parent mentioning
        // python only costs one wasted parse; a real python image never
        // escapes the scan).

        private Dictionary<string, string> ParseIfMatched(EventRecordWrittenEventArgs e, string keyword)
        {
            if (e.EventRecord == null) return null;
            return ParseIfMatchedRecord(e.EventRecord, keyword);
        }

        private Dictionary<string, string> ParseIfMatchedRecord(EventRecord record, string keyword)
        {
            if (record == null) return null;
            string xml = record.ToXml();
            if (xml.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) < 0) return null;

            var fields = ParseFields(xml);
            return fields != null && _imageFilter(GetValue(fields, "Image")) ? fields : null;
        }

        private static Dictionary<string, string> ParseFields(string xml)
        {
            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var eventData = doc.Root?.Element(ns + "EventData");
            if (eventData == null) return null;

            var fields = new Dictionary<string, string>(16, StringComparer.Ordinal);
            foreach (var data in eventData.Elements(ns + "Data"))
            {
                string name = data.Attribute("Name")?.Value;
                if (name != null && !fields.ContainsKey(name)) fields[name] = data.Value;
            }

            return fields;
        }

        private static string GetValue(Dictionary<string, string> fields, string name) =>
            fields.TryGetValue(name, out string value) ? value : string.Empty;

        /// <summary>Sysmon PIDs are decimal in EID 1/5 but hex (0x…) in some EID 3 versions.</summary>
        private static int ParsePid(string value)
        {
            if (string.IsNullOrEmpty(value)) return 0;
            if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int dec)) return dec;
            if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(value.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int hex))
                return hex;
            return 0;
        }

        private static int ParsePort(string value) =>
            int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int port) ? port : 0;

        /// <summary>Sysmon UtcTime is "yyyy-MM-dd HH:mm:ss.fff" UTC; fall back to the record stamp.</summary>
        private static DateTime ParseUtcTime(string value, DateTime? fallback)
        {
            if (DateTime.TryParse(value, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime parsed))
                return parsed;
            return fallback?.ToUniversalTime() ?? DateTime.UtcNow;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
        }
    }

    /// <summary>A python TCP connect as seen by Sysmon EID 3 — the pid↔flow attribution source.</summary>
    public class SpawnNetworkEvent
    {
        public DateTime TimeUtc { get; set; }
        public int Pid { get; set; }
        public string Image { get; set; }
        public string SourceIp { get; set; }
        public int SourcePort { get; set; }
        public string DestIp { get; set; }
        public int DestPort { get; set; }

        /// <summary>Canonical endpoint pair, orientation as the initiator saw it.</summary>
        public string Endpoints => $"{SourceIp}:{SourcePort} → {DestIp}:{DestPort}";
    }
}
