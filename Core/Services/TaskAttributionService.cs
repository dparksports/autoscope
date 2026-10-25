using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// Attribution for a taskhostw.exe instance: the Task Scheduler events
    /// narrating the launch (129 names the task and the PID directly; 100/102
    /// carry the instance GUID and user context; 107/108/119 say why it
    /// fired; 201 carries the action's return code), plus what code the task
    /// actually runs.
    /// </summary>
    public class TaskLaunchInfo
    {
        public string InstanceGuid;
        public string TaskPath;       // e.g. "\Microsoft\Windows\Foo\Bar"
        public string UserContext;    // account the task ran as
        public int ProcessId;         // taskhostw PID (from Sysmon EID 1 or scheduler EID 129)
        public string ProcessGuid;    // Sysmon's per-boot unique process identity (braces stripped)
        public string CommandLine;
        public DateTime? StartedAt;   // scheduler EID 100 (or 129 launch time)
        public DateTime? CompletedAt; // scheduler EID 102

        // Why it fired — scheduler EID 107 (timer), 108 (event), 119 (logon).
        public string TriggerReason;

        // How it ended — scheduler EID 201 carries the action's return code
        // (0 = nothing to do / success); 203 is the engine's failure record.
        public int? ReturnCode;
        public bool? CompletedSuccessfully;
        public string ActionName;     // scheduler EID 200/201 friendly action name

        // COM-handler evidence: what code the task actually runs. A task with
        // a ClassId whose DLL is missing is an orphan (its software is gone).
        public string HandlerClassId;
        public string HandlerDll;
        public string HandlerDllCompany;
        public string HandlerDllVersion;
        public bool? HandlerDllExists;

        // Inbox / Third-party / Orphaned; null while the task is unresolved.
        public string Verdict;

        public DateTime FirstSeenUtc = DateTime.UtcNow;   // prune ordering

        public double? DurationSeconds => StartedAt != null && CompletedAt != null
            ? Math.Max(0, (CompletedAt.Value - StartedAt.Value).TotalSeconds)
            : null;
    }

    /// <summary>
    /// Answers "who/what/why" for taskhostw processes by stitching two logs
    /// together per launch:
    ///
    ///   Sysmon EID 1        the spawn itself (pid, command line, parentage)
    ///   Task Scheduler      107/108/119 why it fired · 129 task name + pid ·
    ///                      100/102 instance GUID + user context, start/finish ·
    ///                      200/201/203 action launched / completed (return
    ///                      code) / failed
    ///
    /// The join has two keys and both are needed: the instance GUID on the
    /// command line ("taskhostw.exe {222A245B-…}") and the PID in EID 129.
    /// Many ComHandler tasks pass only their handler data —
    /// "taskhostw.exe Install $(arg0)" carries no GUID at all — so EID 129 is
    /// the only attribution path for them.
    ///
    /// The Task Scheduler operational channel is disabled on many systems; it
    /// is enabled here once (requires admin) so future launches can be
    /// attributed. Launches before that are unrecoverable live, but Backfill
    /// replays whatever the channel retained. Disabling a task for good is
    /// handled by TaskSchedulerService.SetTaskEnabledAsync.
    /// </summary>
    public class TaskAttributionService
    {
        private const string TaskSchedulerLog = "Microsoft-Windows-TaskScheduler/Operational";
        private const string SysmonLog = "Microsoft-Windows-Sysmon/Operational";

        private const string SchedulerXPath =
            "*[System[(EventID=100 or EventID=102 or EventID=107 or EventID=108 or " +
            "EventID=119 or EventID=129 or EventID=200 or EventID=201 or EventID=203)]]";

        private static readonly Regex InstanceGuidRegex = new Regex(@"\{([0-9A-Fa-f\-]{36})\}", RegexOptions.Compiled);
        private static readonly Regex MessagePidRegex = new Regex(@"process ID (\d+)", RegexOptions.Compiled);
        private static readonly Regex MessageReturnCodeRegex = new Regex(@"return code (-?\d+)", RegexOptions.Compiled);

        private EventLogWatcher _sysmonProcessWatcher;   // Sysmon EID1 — taskhostw spawns
        private EventLogWatcher _sysmonExitWatcher;      // Sysmon EID5 — dead pids get evicted
        private EventLogWatcher _taskInstanceWatcher;    // Task Scheduler launch narrative

        // Both maps hold the same objects once a launch is fully stitched
        // together; until then LinkGuid folds the halves together. The cap
        // bounds a long session — pruned entries only cost late attribution
        // for pids whose rows are long gone from the views anyway.
        private readonly ConcurrentDictionary<int, TaskLaunchInfo> _byPid = new();
        private readonly ConcurrentDictionary<string, TaskLaunchInfo> _byGuid = new(StringComparer.OrdinalIgnoreCase);

        // Sysmon's ProcessGuid (kernel-assigned, unique for the whole boot)
        // → launch. A DIFFERENT guid namespace from _byGuid's scheduler
        // instance GUIDs; this is the one key PID recycling can never
        // collide on, and its entries are evicted by Sysmon EID 5.
        private readonly ConcurrentDictionary<string, TaskLaunchInfo> _byProcGuid = new(StringComparer.OrdinalIgnoreCase);
        private const int TrackedCap = 20000;
        private const double StitchWindowSeconds = 30;

        public event Action<string> OnError;

        /// <summary>Raised (on a watcher thread) whenever an instance gained an
        /// attribution fact. ProcessId > 0 is guaranteed.</summary>
        public event Action<TaskLaunchInfo> OnAttributionUpdated;

        /// <summary>False when the history channel could not be enabled (attribution then degrades to GUID-only).</summary>
        public bool HistoryChannelEnabled { get; private set; }

        public void Start()
        {
            EnableHistoryChannel();

            try
            {
                var query = new EventLogQuery(SysmonLog, PathType.LogName, "*[System[(EventID=1)]]");
                _sysmonProcessWatcher = new EventLogWatcher(query);
                _sysmonProcessWatcher.EventRecordWritten += Sysmon_ProcessCreate;
                _sysmonProcessWatcher.Enabled = true;
            }
            catch (EventLogNotFoundException)
            {
                OnError?.Invoke("Sysmon is not installed — taskhostw instances cannot be detected.");
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Failed to watch Sysmon process events: {ex.Message}");
            }

            try
            {
                var query = new EventLogQuery(SysmonLog, PathType.LogName, "*[System[(EventID=5)]]");
                _sysmonExitWatcher = new EventLogWatcher(query);
                _sysmonExitWatcher.EventRecordWritten += Sysmon_ProcessStopped;
                _sysmonExitWatcher.Enabled = true;
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Failed to watch Sysmon exit events: {ex.Message}");
            }

            try
            {
                var query = new EventLogQuery(TaskSchedulerLog, PathType.LogName, SchedulerXPath);
                _taskInstanceWatcher = new EventLogWatcher(query);
                _taskInstanceWatcher.EventRecordWritten += TaskScheduler_InstanceRecorded;
                _taskInstanceWatcher.Enabled = true;
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Failed to watch the Task Scheduler log: {ex.Message}");
            }
        }

        public void Stop()
        {
            if (_sysmonProcessWatcher != null)
            {
                _sysmonProcessWatcher.Enabled = false;
                _sysmonProcessWatcher.Dispose();
                _sysmonProcessWatcher = null;
            }
            if (_sysmonExitWatcher != null)
            {
                _sysmonExitWatcher.Enabled = false;
                _sysmonExitWatcher.Dispose();
                _sysmonExitWatcher = null;
            }
            if (_taskInstanceWatcher != null)
            {
                _taskInstanceWatcher.Enabled = false;
                _taskInstanceWatcher.Dispose();
                _taskInstanceWatcher = null;
            }
        }

        /// <summary>Attribution for a taskhostw PID, or null when unknown/not a task host.</summary>
        public TaskLaunchInfo GetTaskForPid(int pid) =>
            _byPid.TryGetValue(pid, out var info) ? info : null;

        /// <summary>
        /// Attribution for a taskhostw PID, checked against the asking
        /// process's own start time. Attribution is a fact about ONE tenant
        /// of a PID; once Windows recycles the number onto an unrelated
        /// process, handing that task over would blame an innocent process.
        /// Returns null when the start times don't line up (±5s) or nothing
        /// is known for the PID.
        /// </summary>
        public TaskLaunchInfo GetTaskForPid(int pid, DateTime? subjectStartedUtc)
        {
            if (!_byPid.TryGetValue(pid, out var info)) return null;
            if (subjectStartedUtc.HasValue && info.StartedAt.HasValue &&
                (subjectStartedUtc.Value.ToUniversalTime() - info.StartedAt.Value).Duration() > TimeSpan.FromSeconds(5))
                return null;   // attribution belongs to an earlier tenant of this PID
            return info;
        }

        /// <summary>
        /// Attribution for a spawn row: the Sysmon ProcessGuid first — the one
        /// key immune to PID recycling, no time heuristic needed — falling
        /// back to the time-guarded pid lookup when the guid is unavailable.
        /// </summary>
        public TaskLaunchInfo GetTaskFor(SpawnItem item)
        {
            if (item == null) return null;
            if (!string.IsNullOrEmpty(item.ProcessGuid) &&
                _byProcGuid.TryGetValue(item.ProcessGuid, out var byGuid))
                return byGuid;
            return GetTaskForPid(item.Pid, item.TimeUtc);
        }

        /// <summary>
        /// Replay the recent past so a freshly opened tab shows spawns that
        /// happened before it: Sysmon EID 1 taskhostw records become rows,
        /// and the scheduler events for the same window are stitched onto
        /// them by the same merge logic the live watchers use. Rows come
        /// back oldest-first; attribution keeps refining afterwards through
        /// the normal live paths.
        /// </summary>
        public List<SpawnItem> Backfill(TimeSpan window, int maxRows = 400)
        {
            var cutoff = DateTime.UtcNow - window;
            var spawns = new List<SpawnItem>();

            try
            {
                // Newest-first: stop at the window edge. EID 1 fires for every
                // process on the machine, so the substring pre-filter inside
                // ParseSpawnRecord keeps the DOM parses to the taskhostw few.
                var query = new EventLogQuery(SysmonLog, PathType.LogName, "*[System[(EventID=1)]]") { ReverseDirection = true };
                using var reader = new EventLogReader(query);
                EventRecord rec;
                while ((rec = reader.ReadEvent()) != null && spawns.Count < maxRows)
                {
                    using (rec)
                    {
                        if (rec.TimeCreated is DateTime t && t.ToUniversalTime() < cutoff) break;
                        var item = ImageSpawnWatcherService.ParseSpawnRecord(
                            rec, ImageSpawnWatcherService.IsTaskhostwImage, "taskhostw");
                        if (item != null) spawns.Add(item);
                    }
                }
            }
            catch { /* history is a bonus; a missing log just yields nothing */ }

            ReplayScheduler(cutoff);

            spawns.Sort((a, b) => a.TimeUtc.CompareTo(b.TimeUtc));
            foreach (var item in spawns)
                FeedSysmonItem(item);

            // Exits inside the window evict their pid mappings too — a
            // backfilled launch that already exited must not stay
            // attributable through its (possibly since-recycled) pid.
            ReplayExits(cutoff);
            return spawns;
        }

        /// <summary>
        /// Scheduler-only replay: fills the attribution map without Sysmon
        /// (whose log denies reads to non-elevated callers). EID 129 carries
        /// the taskhostw PID, so launches still attribute — only the grid
        /// rows are missing. Returns the number of records processed.
        /// </summary>
        public int BackfillSchedulerOnly(TimeSpan window) =>
            ReplayScheduler(DateTime.UtcNow - window);

        /// <summary>Fully or partially attributed launches seen (live or backfilled), newest first — diagnostic enumeration.</summary>
        public List<TaskLaunchInfo> GetRecentLaunches(int max = 50) =>
            _byPid.Values
                  .Where(i => !string.IsNullOrEmpty(i.TaskPath))
                  .OrderByDescending(i => i.StartedAt ?? i.FirstSeenUtc)
                  .Take(max)
                  .ToList();

        private int ReplayScheduler(DateTime cutoff)
        {
            int processed = 0;
            try
            {
                // Oldest-first so timestamps fill in chronological order; skip
                // what predates the window, guard against unbounded logs.
                var query = new EventLogQuery(TaskSchedulerLog, PathType.LogName, SchedulerXPath);
                using var reader = new EventLogReader(query);
                EventRecord rec; int guard = 20000;
                while ((rec = reader.ReadEvent()) != null && guard-- > 0)
                {
                    using (rec)
                    {
                        if (!(rec.TimeCreated is DateTime t) || t.ToUniversalTime() < cutoff) continue;
                        HandleTaskSchedulerRecord(rec);
                        processed++;
                    }
                }
            }
            catch { }
            return processed;
        }

        // ── merge helpers ─────────────────────────────────────────────────

        private TaskLaunchInfo ForPid(int pid) =>
            _byPid.GetOrAdd(pid, _ =>
            {
                PruneIfNeeded();
                return new TaskLaunchInfo { ProcessId = pid, FirstSeenUtc = DateTime.UtcNow };
            });

        private TaskLaunchInfo ForGuid(string guid) =>
            _byGuid.GetOrAdd(guid.Trim('{', '}'), key =>
            {
                PruneIfNeeded();
                return new TaskLaunchInfo { InstanceGuid = key, FirstSeenUtc = DateTime.UtcNow };
            });

        /// <summary>
        /// Fold the pid-keyed object into the guid-keyed one (or register it
        /// as the canonical object). The two maps can hold different objects
        /// for the same launch — Sysmon's create event and the scheduler's
        /// GUID-bearing events each discover the instance independently — and
        /// every later fact must land on the one object the row reads through
        /// GetTaskForPid.
        /// </summary>
        private void LinkGuid(TaskLaunchInfo info, string guid)
        {
            info.InstanceGuid ??= guid.Trim('{', '}');
            var canonical = _byGuid.GetOrAdd(info.InstanceGuid, info);
            if (ReferenceEquals(canonical, info)) return;

            canonical.ProcessId = info.ProcessId;
            canonical.CommandLine ??= info.CommandLine;
            if (info.ProcessId > 0) _byPid[info.ProcessId] = canonical;
        }

        private void Notify(TaskLaunchInfo info)
        {
            if (info != null && info.ProcessId > 0)
                OnAttributionUpdated?.Invoke(info);
        }

        /// <summary>
        /// Target object for a GUID-bearing scheduler event. EID 129 carries
        /// the taskhostw PID but no InstanceId, so a launch whose command line
        /// had no GUID ("taskhostw.exe Install $(arg0)") splits in two: a
        /// PID-keyed half (task path, handler) and a GUID-keyed half (trigger,
        /// user context, result). Resolution order: already stitched → EnginePID
        /// exact join (200/201 carry the taskhostw PID) → task-path + time
        /// proximity (the scheduler writes a whole launch sequence within a
        /// second or two) → plain GUID side. Null when the event offers no
        /// handle at all.
        /// </summary>
        private TaskLaunchInfo ResolveTarget(Dictionary<string, string> fields, string taskName, string instanceId, EventRecord record)
        {
            if (string.IsNullOrEmpty(instanceId))
            {
                int enginePid = ParseInt(Get(fields, "EnginePID")) ?? 0;
                return enginePid > 0 && _byPid.TryGetValue(enginePid, out var tracked) ? tracked : null;
            }

            string key = instanceId.Trim('{', '}');
            if (_byGuid.TryGetValue(key, out var guidSide) && guidSide.ProcessId > 0)
                return guidSide;   // already stitched to a pid

            // Exact join first: 200/201's EnginePID is the taskhostw process.
            // Only adopt an already-tracked pid — untracked engine pids belong
            // to non-taskhostw task actions (cmd.exe…) and must not pollute.
            int ep = ParseInt(Get(fields, "EnginePID")) ?? 0;
            if (ep > 0 && _byPid.TryGetValue(ep, out var byPid) && byPid.InstanceGuid == null)
            {
                FoldInto(byPid, guidSide);
                byPid.InstanceGuid = key;
                _byGuid[key] = byPid;
                return byPid;
            }

            // Proximity join: same task, launch sequence in flight, pid half
            // not yet GUID-linked.
            if (!string.IsNullOrEmpty(taskName) && record.TimeCreated is DateTime t)
            {
                TaskLaunchInfo best = null;
                double bestDelta = StitchWindowSeconds;
                foreach (var candidate in _byPid.Values)
                {
                    if (candidate.InstanceGuid != null ||
                        !string.Equals(candidate.TaskPath, taskName, StringComparison.OrdinalIgnoreCase)) continue;
                    var stamp = candidate.StartedAt ?? candidate.FirstSeenUtc;
                    double delta = Math.Abs((t.ToUniversalTime() - stamp).TotalSeconds);
                    if (delta <= bestDelta) { best = candidate; bestDelta = delta; }
                }
                if (best != null)
                {
                    FoldInto(best, guidSide);
                    best.InstanceGuid = key;
                    _byGuid[key] = best;
                    return best;
                }
            }

            return guidSide ?? ForGuid(key);
        }

        /// <summary>Copies the GUID-side half's facts onto the PID-side half before the two are linked.</summary>
        private static void FoldInto(TaskLaunchInfo target, TaskLaunchInfo source)
        {
            if (source == null || ReferenceEquals(target, source)) return;
            target.TriggerReason ??= source.TriggerReason;
            target.UserContext ??= source.UserContext;
            target.StartedAt ??= source.StartedAt;
            target.CompletedAt ??= source.CompletedAt;
            target.ReturnCode ??= source.ReturnCode;
            target.ActionName ??= source.ActionName;
        }

        private void PruneIfNeeded()
        {
            if (_byPid.Count >= TrackedCap)
                foreach (int key in _byPid.OrderBy(kv => kv.Value.FirstSeenUtc)
                                          .Take(Math.Max(1, _byPid.Count / 10))
                                          .Select(kv => kv.Key).ToList())
                    _byPid.TryRemove(key, out _);
            if (_byGuid.Count >= TrackedCap)
                foreach (string key in _byGuid.OrderBy(kv => kv.Value.FirstSeenUtc)
                                              .Take(Math.Max(1, _byGuid.Count / 10))
                                              .Select(kv => kv.Key).ToList())
                    _byGuid.TryRemove(key, out _);
            if (_byProcGuid.Count >= TrackedCap)
                foreach (string key in _byProcGuid.OrderBy(kv => kv.Value.FirstSeenUtc)
                                                  .Take(Math.Max(1, _byProcGuid.Count / 10))
                                                  .Select(kv => kv.Key).ToList())
                    _byProcGuid.TryRemove(key, out _);
        }

        // ── live event handling ───────────────────────────────────────────

        private void Sysmon_ProcessCreate(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                var item = ImageSpawnWatcherService.ParseSpawnRecord(
                    e.EventRecord, ImageSpawnWatcherService.IsTaskhostwImage, "taskhostw");
                if (item == null) return;

                FeedSysmonItem(item);
                Notify(_byPid.TryGetValue(item.Pid, out var info) ? info : null);
            }
            catch { }
        }

        private void Sysmon_ProcessStopped(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                if (e.EventRecord == null) return;
                HandleProcessStopped(ParseFields(e.EventRecord.ToXml()));
            }
            catch { }
        }

        /// <summary>
        /// A tracked taskhostw exited (Sysmon EID 5): drop its PID-keyed
        /// attribution so the number cannot hand this task to whatever
        /// process inherits it next. The scheduler-GUID and ProcessGuid maps
        /// keep their entries — those keys are unique and rows already
        /// holding the object keep enriching until the last completion
        /// events land. Eviction happens in the live watcher and in the
        /// backfill replay, so even a freshly opened tab never attributes
        /// through an exited pid.
        /// </summary>
        private void HandleProcessStopped(Dictionary<string, string> fields)
        {
            if (fields == null) return;
            string key = (Get(fields, "ProcessGuid") ?? string.Empty).Trim('{', '}');
            if (key.Length == 0) return;

            if (!_byProcGuid.TryRemove(key, out var info)) return;

            if (Get(fields, "UtcTime") is string raw &&
                DateTime.TryParse(raw, null,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out DateTime exited))
                info.CompletedAt ??= exited;

            // Only evict the pid mapping while it still points at THIS
            // tenant — if the number was already recycled onto a newer
            // launch, that launch owns the mapping now.
            if (info.ProcessId > 0 && _byPid.TryGetValue(info.ProcessId, out var current) &&
                ReferenceEquals(current, info))
                _byPid.TryRemove(info.ProcessId, out _);
        }

        /// <summary>Backfill half of EID 5: evicts pid mappings for launches that exited within the replayed window.</summary>
        private void ReplayExits(DateTime cutoff)
        {
            try
            {
                var query = new EventLogQuery(SysmonLog, PathType.LogName, "*[System[(EventID=5)]]");
                using var reader = new EventLogReader(query);
                EventRecord rec; int guard = 20000;
                while ((rec = reader.ReadEvent()) != null && guard-- > 0)
                {
                    using (rec)
                    {
                        if (_byProcGuid.IsEmpty) break;   // nothing tracked left to evict
                        if (!(rec.TimeCreated is DateTime t) || t.ToUniversalTime() < cutoff) continue;
                        HandleProcessStopped(ParseFields(rec.ToXml()));
                    }
                }
            }
            catch { /* exit replay is a bonus — scheduler events still bound CompletedAt */ }
        }

        /// <summary>Sysmon-side half of a launch: registers/updates the pid entry and links the command-line GUID when present.</summary>
        private void FeedSysmonItem(SpawnItem item)
        {
            var info = ForPid(item.Pid);
            info.CommandLine ??= item.CommandLine;
            // The spawn time binds this attribution to THIS tenant of the
            // PID — GetTaskForPid's time guard depends on it once the
            // number gets recycled onto a later process.
            info.StartedAt ??= item.TimeUtc;
            if (!string.IsNullOrEmpty(item.ProcessGuid)) LinkProcGuid(info, item.ProcessGuid);

            var guidMatch = InstanceGuidRegex.Match(item.CommandLine ?? string.Empty);
            if (guidMatch.Success) LinkGuid(info, guidMatch.Groups[1].Value);
        }

        /// <summary>
        /// Registers the Sysmon ProcessGuid side of a launch. Live watching
        /// and Backfill can discover the same launch twice; both fold onto
        /// the canonical object and the pid map is re-pointed at it.
        /// </summary>
        private void LinkProcGuid(TaskLaunchInfo info, string procGuid)
        {
            info.ProcessGuid ??= procGuid.Trim('{', '}');
            var canonical = _byProcGuid.GetOrAdd(info.ProcessGuid, info);
            if (ReferenceEquals(canonical, info)) return;

            canonical.ProcessId = info.ProcessId;
            canonical.CommandLine ??= info.CommandLine;
            canonical.StartedAt ??= info.StartedAt;
            if (info.ProcessId > 0) _byPid[info.ProcessId] = canonical;
        }

        private void TaskScheduler_InstanceRecorded(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;
            HandleTaskSchedulerRecord(e.EventRecord);
        }

        private void HandleTaskSchedulerRecord(EventRecord record)
        {
            try
            {
                var fields = ParseFields(record.ToXml());
                if (fields == null) return;

                string taskName = Get(fields, "TaskName");
                // 100-series events call it InstanceId; 200/201 say TaskInstanceId
                string instanceId = (Get(fields, "InstanceId") ?? Get(fields, "TaskInstanceId"))?.Trim('{', '}');

                TaskLaunchInfo info;
                switch (record.Id)
                {
                    case 107: // triggered by its schedule
                    case 108: // triggered by an event
                    case 119: // triggered by a user logon
                        info = ResolveTarget(fields, taskName, instanceId, record);
                        if (info == null) return;
                        info.TriggerReason = record.Id switch { 107 => "timer (schedule)", 108 => "event", _ => "user logon" };
                        break;

                    case 129: // "launch task X, instance taskhostw.exe, with process ID N"
                    {
                        // 129 fires for every task action — cmd.exe, powershell.exe…
                        // Only taskhostw instances belong on this tab.
                        string instanceName = Get(fields, "Path") ?? Get(fields, "InstanceName");
                        if (instanceName != null &&
                            instanceName.IndexOf("taskhostw", StringComparison.OrdinalIgnoreCase) < 0)
                            return;

                        int pid = ParseInt(Get(fields, "ProcessId")) ?? MatchInt(record.FormatDescription(), MessagePidRegex) ?? 0;
                        if (pid <= 0) return;

                        info = ForPid(pid);
                        if (record.TimeCreated is DateTime launched) info.StartedAt ??= launched.ToUniversalTime();
                        break;
                    }

                    case 100:
                        info = ResolveTarget(fields, taskName, instanceId, record);
                        if (info == null) return;
                        if (record.TimeCreated is DateTime started) info.StartedAt ??= started.ToUniversalTime();
                        break;

                    case 102:
                        info = ResolveTarget(fields, taskName, instanceId, record);
                        if (info == null) return;
                        if (record.TimeCreated is DateTime finished) info.CompletedAt = finished.ToUniversalTime();
                        break;

                    case 200:
                        info = ResolveTarget(fields, taskName, instanceId, record);
                        if (info == null) return;
                        info.ActionName ??= Get(fields, "ActionName");
                        break;

                    case 201: // action completed — "with return code 0"
                    case 203: // action failed
                        info = ResolveTarget(fields, taskName, instanceId, record);
                        if (info == null) return;
                        info.ActionName ??= Get(fields, "ActionName");
                        string code = Get(fields, "ResultCode") ?? Get(fields, "ErrorCode");
                        info.ReturnCode = ParseInt(code)
                                          ?? MatchInt(record.FormatDescription(), MessageReturnCodeRegex)
                                          ?? info.ReturnCode;
                        if (record.Id == 201)
                        {
                            info.CompletedSuccessfully = true;
                            if (record.TimeCreated is DateTime done) info.CompletedAt ??= done.ToUniversalTime();
                        }
                        else if (info.CompletedSuccessfully != true)
                        {
                            info.CompletedSuccessfully = false;
                        }
                        break;

                    default:
                        return;
                }

                if (!string.IsNullOrEmpty(taskName) && string.IsNullOrEmpty(info.TaskPath)) info.TaskPath = taskName;
                if (string.IsNullOrEmpty(info.UserContext))
                {
                    string user = Get(fields, "UserContext") ?? Get(fields, "UserName");
                    if (!string.IsNullOrEmpty(user)) info.UserContext = user;
                }

                // Knowing the task path, resolve what code a COM-handler task
                // runs: the task XML carries the ClassId, and the registry maps
                // ClassId → DLL. This is the "what does taskhostw actually
                // execute" answer for DLL tasks, which have no command line.
                if (!string.IsNullOrEmpty(info.TaskPath) &&
                    info.HandlerDll == null && info.HandlerDllExists == null)
                    ResolveHandler(info);

                UpdateVerdict(info);
                Notify(info);
            }
            catch { /* attribution is best-effort; one bad record never stops the watcher */ }
        }

        // ── handler resolution + verdict ──────────────────────────────────

        /// <summary>
        /// Fills HandlerClassId/HandlerDll for a task whose path is known.
        /// Scheduled-task files live under %WINDIR%\System32\Tasks\<path>; a
        /// ComHandler action's XML contains the ClassId, which resolves to the
        /// DLL through HKCR\CLSID\{...}\InprocServer32. Exec/spawn tasks have
        /// no ClassId and are left null — their command line already says
        /// what they run.
        /// </summary>
        private static void ResolveHandler(TaskLaunchInfo info)
        {
            try
            {
                string tasksRoot = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
                string taskFile = tasksRoot + info.TaskPath;
                if (!File.Exists(taskFile)) return;

                string xml = File.ReadAllText(taskFile);
                int open = xml.IndexOf("<ClassId>", StringComparison.OrdinalIgnoreCase);
                int close = xml.IndexOf("</ClassId>", StringComparison.OrdinalIgnoreCase);
                if (open < 0 || close <= open) return;

                string classId = xml.Substring(open + 9, close - open - 9).Trim();
                if (!classId.StartsWith("{")) return;
                info.HandlerClassId = classId;

                // HKCR merges HKLM\Software\Classes and HKCU\Software\Classes;
                // check the 64-bit view first, then WOW6432Node for 32-bit DLLs
                foreach (string hive in new[]
                         {
                             @"Software\Classes\CLSID\" + classId + @"\InprocServer32",
                             @"Software\Classes\WOW6432Node\CLSID\" + classId + @"\InprocServer32"
                         })
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(hive);
                    string dll = key?.GetValue(null)?.ToString();
                    if (string.IsNullOrEmpty(dll)) continue;

                    info.HandlerDll = Environment.ExpandEnvironmentVariables(dll);
                    info.HandlerDllExists = File.Exists(info.HandlerDll);
                    if (info.HandlerDllExists == true)
                    {
                        try
                        {
                            // .NET 10 renamed the factory: GetFileVersionInfo → GetVersionInfo
                            var fv = System.Diagnostics.FileVersionInfo.GetVersionInfo(info.HandlerDll);
                            info.HandlerDllCompany = fv.CompanyName;
                            info.HandlerDllVersion = fv.FileVersion;
                        }
                        catch { }
                    }
                    return;
                }

                // Registered nowhere: the task fires but its DLL is gone —
                // classic leftover of uninstalled software
                info.HandlerDllExists = false;
            }
            catch { /* attribution extras are best-effort */ }
        }

        /// <summary>
        /// Inbox: Microsoft-shipped task path running code from the system
        /// directories. Third-party: task outside \Microsoft\, or an inbox
        /// task whose handler DLL lives elsewhere. Orphaned: the handler DLL
        /// is gone — leftover of uninstalled software. Null while the task is
        /// still unresolved.
        /// </summary>
        private static void UpdateVerdict(TaskLaunchInfo info)
        {
            if (string.IsNullOrEmpty(info.TaskPath)) { info.Verdict = null; return; }

            bool inboxPath = info.TaskPath.StartsWith("\\Microsoft\\", StringComparison.OrdinalIgnoreCase);

            // A classic-COM miss (handler DLL not registered) is the "leftover
            // of uninstalled software" signature for third-party tasks. Inbox
            // tasks also resolve handlers through stores the classic lookup
            // doesn't cover (packaged COM et al.) — they run fine unregistered
            // in HKCR — so they stay Inbox with an unresolved handler.
            if (info.HandlerDllExists == false)
            {
                info.Verdict = inboxPath ? "Inbox" : "Orphaned";
                return;
            }

            bool systemCode = true;
            if (!string.IsNullOrEmpty(info.HandlerDll))
            {
                systemCode = info.HandlerDll.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase) ||
                             info.HandlerDll.StartsWith(
                                 Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
                                 StringComparison.OrdinalIgnoreCase);
            }
            info.Verdict = inboxPath && systemCode ? "Inbox" : "Third-party";
        }

        // ── plumbing ──────────────────────────────────────────────────────

        private void EnableHistoryChannel()
        {
            try
            {
                using var config = new EventLogConfiguration(TaskSchedulerLog);
                if (!config.IsEnabled)
                {
                    config.IsEnabled = true;
                    config.SaveChanges();
                }
                HistoryChannelEnabled = true;
            }
            catch (Exception ex)
            {
                HistoryChannelEnabled = false;
                OnError?.Invoke($"Task Scheduler history could not be enabled: {ex.Message}");
            }
        }

        private static Dictionary<string, string> ParseFields(string xml)
        {
            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var eventData = doc.Root?.Element(ns + "EventData");
            if (eventData == null) return null;

            // Case-insensitive on purpose: scheduler events mix spellings
            // (EID 129 says "ProcessID", 100/102 say "ProcessId")
            var fields = new Dictionary<string, string>(16, StringComparer.OrdinalIgnoreCase);
            foreach (var data in eventData.Elements(ns + "Data"))
            {
                string name = data.Attribute("Name")?.Value;
                if (name != null && !fields.ContainsKey(name)) fields[name] = data.Value;
            }
            return fields;
        }

        private static string Get(Dictionary<string, string> fields, string name) =>
            fields.TryGetValue(name, out string value) ? value : null;

        private static int? ParseInt(string value) =>
            int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int v) ? v : null;

        /// <summary>Field-name fallback for events whose EventData names vary by build: dig the number out of the formatted message.</summary>
        private static int? MatchInt(string message, Regex regex)
        {
            try
            {
                var m = regex.Match(message ?? string.Empty);
                return m.Success && int.TryParse(m.Groups[1].Value, out int v) ? v : null;
            }
            catch { return null; }
        }
    }
}
