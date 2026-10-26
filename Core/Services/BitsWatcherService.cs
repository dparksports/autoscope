using System;
using AutoScope.Engines.Firewall;
using AutoScope.Engines.Core;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AutoScope.Models;

namespace AutoScope.Services
{
    // ─────────────────────────────────────────────────────────────────────
    // BITS COM interop — read-only vtable declarations, slot order per the
    // SDK bits.idl (verified against wine-mirror's copy and validated live
    // on-box: CoCreateInstance(CLSCTX_LOCAL_SERVER) + full enumeration).
    // The manager coclass is the versioned "Background Intelligent Transfer
    // Control Class"; the 1.0 CLSID is the canonical one, 10.3 the newest.
    // ─────────────────────────────────────────────────────────────────────

    internal enum BG_JOB_TYPE { DOWNLOAD = 0, UPLOAD = 1, UPLOAD_REPLY = 2 }
    internal enum BG_JOB_STATE { QUEUED = 0, CONNECTING = 1, TRANSFERRING = 2, SUSPENDED = 3, ERROR = 4, TRANSIENT_ERROR = 5, TRANSFERRED = 6, ACKNOWLEDGED = 7, CANCELLED = 8 }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BG_JOB_PROGRESS { public ulong BytesTotal; public ulong BytesTransferred; public uint FilesTotal; public uint FilesTransferred; }

    [ComImport, Guid("5CE34C0D-0DC9-4C1F-897C-DAA1B78CEE7C"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IBackgroundCopyManager
    {
        void CreateJob([MarshalAs(UnmanagedType.LPWStr)] string displayName, BG_JOB_TYPE type, out Guid jobId, out IBackgroundCopyJob job);
        void GetJob(ref Guid jobId, out IBackgroundCopyJob job);
        void EnumJobs(uint flags, out IEnumBackgroundCopyJobs jobs);
        void GetErrorDescription(int hResult, uint languageId, [MarshalAs(UnmanagedType.LPWStr)] out string description);
    }

    [ComImport, Guid("37668D37-507E-4160-9316-26306D150B12"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IBackgroundCopyJob
    {
        void AddFileSet(uint count, IntPtr fileSet);
        void AddFile([MarshalAs(UnmanagedType.LPWStr)] string remoteUrl, [MarshalAs(UnmanagedType.LPWStr)] string localName);
        void EnumFiles(out IEnumBackgroundCopyFiles files);
        void Suspend();
        void Resume();
        void Cancel();
        void Complete();
        void GetId(out Guid id);
        void GetType(out BG_JOB_TYPE type);
        void GetProgress(out BG_JOB_PROGRESS progress);
        void GetTimes(out long creationFileTime, out long modificationFileTime, out long transferCompletionFileTime);
        void GetState(out BG_JOB_STATE state);
        void GetError(out IntPtr error);
        void GetOwner([MarshalAs(UnmanagedType.LPWStr)] out string owner);
        void SetDisplayName([MarshalAs(UnmanagedType.LPWStr)] string name);
        void GetDisplayName([MarshalAs(UnmanagedType.LPWStr)] out string name);
        // slots after GetDisplayName (SetDescription…TakeOwnership) are never called by the tracer
    }

    [ComImport, Guid("1AF4F612-3B71-466F-8F58-7B6F73AC57AD"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IEnumBackgroundCopyJobs
    {
        void Next(uint celt, out IBackgroundCopyJob elt, out uint fetched);
        void Skip(uint celt);
        void Reset();
        void Clone(out IEnumBackgroundCopyJobs penum);
        void GetCount(out uint count);
    }

    [ComImport, Guid("01B7BD23-FB88-4A77-8490-5891D3E4653A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IBackgroundCopyFile
    {
        void GetRemoteName([MarshalAs(UnmanagedType.LPWStr)] out string remoteName);
        void GetLocalName([MarshalAs(UnmanagedType.LPWStr)] out string localName);
        void GetProgress(out BG_JOB_PROGRESS progress);
    }

    [ComImport, Guid("CA51E165-C365-424C-8D41-24AAA4FF3C40"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IEnumBackgroundCopyFiles
    {
        void Next(uint celt, out IBackgroundCopyFile elt, out uint fetched);
        void Skip(uint celt);
        void Reset();
        void Clone(out IEnumBackgroundCopyFiles penum);
        void GetCount(out uint count);
    }

    /// <summary>
    /// The BITS Transfers tab's engine. Two read-only sources stitched by
    /// job GUID:
    ///   • Microsoft-Windows-Bits-Client/Operational — EID 3 (job created:
    ///     name, owner, creating process + PID), 59/60 (transfer start/stop
    ///     with the URL + status code), 4 (complete with file count).
    ///     This is the history: it survives restarts to the log's wrap.
    ///   • The BITS COM queue (all users, needs the elevation the app
    ///     already has) — direction (download/upload), live state and
    ///     progress, and per-file remote + LOCAL names, none of which the
    ///     event log carries.
    /// Plus enrichment (forward DNS, IP→owner via IpClassifier/RDAP,
    /// Authenticode on the creator, reason-catalog verdict), completion
    /// hashing (size + SHA-256 of delivered files; content itself is only
    /// ever touched by the explicit per-file preview action), per-(creator,
    /// host) frequency stats, and JSONL/JSON persistence under
    /// %LOCALAPPDATA%\AutoScope\bits\. Nothing here creates, cancels or
    /// modifies jobs — BITS delivers Windows Update.
    /// </summary>
    public sealed class BitsWatcherService : IDisposable
    {
        // coclass BackgroundCopyManager (canonical 1.0, then newest 10.3)
        private static readonly Guid ClsidBitsManager10 = new("4991d34b-80a1-4291-83b6-3328366b9097");
        private static readonly Guid ClsidBitsManager103 = new("5FD42AD5-C04E-4D36-ADC7-E08FF15737AD");
        private static readonly Guid IidBackgroundCopyManager = new("5CE34C0D-0DC9-4C1F-897C-DAA1B78CEE7C");

        private const string LogName = "Microsoft-Windows-Bits-Client/Operational";
        private const string XPath = "*[System[(EventID=3 or EventID=4 or EventID=59 or EventID=60 or EventID=209 or EventID=310 or EventID=313)]]";
        private const int JobCap = 20000;         // stitch map (GUIDs), pruned oldest-first
        private const int BackfillCap = 5000;     // records replayed from the log

        /// <summary>Rows are exposed newest-first; the view caps at its own RowCap.</summary>
        public event Action<BitsJobItem> OnJobUpserted;
        /// <summary>Fires once per UPLOAD-type job (T1197 exfiltration vector) — the view forwards it to the app's threat status bar.</summary>
        public event Action<BitsJobItem> OnUploadJob;
        public event Action<string> OnError;

        private readonly ConcurrentDictionary<string, BitsJobItem> _jobs = new();
        private readonly ConcurrentDictionary<string, byte> _uploadAlerted = new();
        private readonly ConcurrentDictionary<string, byte> _persisted = new();
        private readonly ConcurrentDictionary<string, byte> _enrichDone = new();   // jobId → which enrichment stages have run
        private readonly object _applySync = new();

        private readonly Dictionary<string, BitsJobStat> _stats = new();
        private readonly object _statsSync = new();
        private bool _statsDirty;
        private DateTime _statsFirstKey = DateTime.MaxValue;   // oldest LastSeenUtc seen, for pruning

        private static string _bitsDirOverride;
        /// <summary>Self-test isolation: redirect jobs.jsonl/bits-stats.json away from real user data.</summary>
        internal static void UseBitsDirForTest(string dir) => _bitsDirOverride = dir;

        private static string BitsDir =>
            _bitsDirOverride ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AutoScope", "bits");
        private static string JobsLogPath => Path.Combine(BitsDir, "jobs.jsonl");
        private static string StatsPath => Path.Combine(BitsDir, "bits-stats.json");

        private EventLogWatcher _watcher;
        private Timer _comTimer;
        private Timer _statsTimer;
        private DnsResolutionService _dns;
        private int _comFailureCount;
        private int _running;

        /// <summary>Self-test switch: disables DNS/RDAP/signer/reason lookups so Apply() is fully offline.</summary>
        internal bool EnrichmentEnabled { get; set; } = true;

        // -----------------------------------------------------------------------
        // Lifecycle
        // -----------------------------------------------------------------------

        public void Start()
        {
            if (Interlocked.Exchange(ref _running, 1) == 1) return;

            try { Directory.CreateDirectory(BitsDir); } catch { /* read-only media etc. — tracing still works in memory */ }
            LoadStats();
            Backfill();

            try
            {
                var query = new EventLogQuery(LogName, PathType.LogName, XPath);
                _watcher = new EventLogWatcher(query);
                _watcher.EventRecordWritten += Watcher_EventRecordWritten;
                _watcher.Enabled = true;
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"BITS activity feed unavailable: {ex.Message}");
            }

            _dns = new DnsResolutionService();
            _dns.Start();

            _comTimer = new Timer(_ => PollCom(), null, TimeSpan.Zero, TimeSpan.FromSeconds(2));
            _statsTimer = new Timer(_ => PersistStatsIfDirty(), null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
        }

        public void Stop()
        {
            if (Interlocked.Exchange(ref _running, 0) == 0) return;
            _watcher?.Dispose();
            _watcher = null;
            _comTimer?.Dispose();
            _comTimer = null;
            _statsTimer?.Dispose();
            _statsTimer = null;
            _dns?.Dispose();
            _dns = null;
            PersistStatsIfDirty();
        }

        public void Dispose() { Stop(); }

        // -----------------------------------------------------------------------
        // Event-log ingestion + stitching
        // -----------------------------------------------------------------------

        private void Watcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;
            try
            {
                var ev = ParseRecord(e.EventRecord);
                if (ev != null) Apply(ev);
            }
            catch { /* one malformed record never stops the watcher */ }
        }

        /// <summary>Replays the whole channel (bounded) oldest→newest once at Start.</summary>
        private void Backfill()
        {
            Task.Run(() =>
            {
                try
                {
                    var records = new List<EventRecord>();
                    var query = new EventLogQuery(LogName, PathType.LogName, XPath);
                    using (var reader = new EventLogReader(query))
                    {
                        for (int i = 0; i < BackfillCap; i++)
                        {
                            var r = reader.ReadEvent();
                            if (r == null) break;
                            records.Add(r);
                        }
                    }
                    // The reader's direction depends on the channel; normalize oldest→newest.
                    if (records.Count > 1 && records[0].TimeCreated > records[^1].TimeCreated) records.Reverse();
                    foreach (var r in records)
                    {
                        var ev = ParseRecord(r);
                        if (ev != null) Apply(ev);
                        r.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    OnError?.Invoke($"BITS history backfill failed: {ex.Message}");
                }
            });
        }

        /// <summary>
        /// Structured parse of one Bits-Client record. Message-regex based
        /// (the Defender-tab precedent — the same shapes validated against
        /// this machine's live log on 2026-10-15). Static + pure for the
        /// offline self-test.
        /// </summary>
        internal sealed class ParsedBitsEvent
        {
            public int EventId;
            public DateTime TimeUtc;
            public string JobId;          // braceless lowercase GUID
            public string JobName;
            public string Owner;
            public string CreatorImage;
            public int CreatorPid;
            public string Url;
            public string StatusCode;     // "0x0" style
            public int FileCount = -1;
        }

        internal static ParsedBitsEvent ParseRecord(EventRecord record)
        {
            int id = record.Id;
            string message = (record.FormatDescription() ?? "").Trim();
            if (message.Length == 0) message = $"(event {id})";
            return ParseMessage(id, record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow, message);
        }

        private static readonly Regex RxJobId = new(@"Job ID:\s*\{?([0-9A-Fa-f\-]{36})\}?", RegexOptions.Compiled);
        private static readonly Regex RxJobName = new(@"Transfer job:\s*(.+)", RegexOptions.Compiled);
        private static readonly Regex RxOwner = new(@"(?:^|\n)\s*(?:Owner|User):\s*(.+)", RegexOptions.Compiled);
        private static readonly Regex RxProcessPath = new(@"Process Path:\s*(.+)", RegexOptions.Compiled);
        private static readonly Regex RxProcessId = new(@"Process ID:\s*(\d+)", RegexOptions.Compiled);
        private static readonly Regex RxUrl = new(@"associated with the\s*(\S+?)\s*URL", RegexOptions.Compiled);
        private static readonly Regex RxStatus = new(@"status code is\s*(0x[0-9A-Fa-f]+)", RegexOptions.Compiled);
        private static readonly Regex RxFileCount = new(@"File count:\s*(\d+)", RegexOptions.Compiled);

        internal static ParsedBitsEvent ParseMessage(int eventId, DateTime timeUtc, string message)
        {
            var ev = new ParsedBitsEvent { EventId = eventId, TimeUtc = timeUtc };

            var m = RxJobId.Match(message);
            if (m.Success) ev.JobId = m.Groups[1].Value.Trim('{', '}').ToLowerInvariant();
            m = RxJobName.Match(message);
            if (m.Success) ev.JobName = m.Groups[1].Value.Trim();
            m = RxOwner.Match(message);
            if (m.Success) ev.Owner = m.Groups[1].Value.Trim();
            m = RxProcessPath.Match(message);
            if (m.Success) ev.CreatorImage = m.Groups[1].Value.Trim();
            m = RxProcessId.Match(message);
            if (m.Success && int.TryParse(m.Groups[1].Value, out int pid)) ev.CreatorPid = pid;
            m = RxUrl.Match(message);
            if (m.Success) ev.Url = m.Groups[1].Value.Trim();
            m = RxStatus.Match(message);
            if (m.Success) ev.StatusCode = m.Groups[1].Value;
            m = RxFileCount.Match(message);
            if (m.Success && int.TryParse(m.Groups[1].Value, out int fc)) ev.FileCount = fc;

            // 59/60 embed the job name in prose ("the X transfer job that is…")
            if (ev.JobName == null && (eventId == 59 || eventId == 60))
            {
                var byProse = Regex.Match(message, @"BITS \w+ the (.+?) transfer job", RegexOptions.IgnoreCase);
                if (byProse.Success) ev.JobName = byProse.Groups[1].Value.Trim();
            }

            return ev.JobId != null || ev.JobName != null || ev.Url != null ? ev : null;
        }

        /// <summary>Applies one parsed event to the stitch map. Thread-safe; raises OnJobUpserted.</summary>
        internal void Apply(ParsedBitsEvent ev)
        {
            if (ev == null) return;
            BitsJobItem item;
            lock (_applySync)
            {
                item = GetOrCreate(ev);
                if (item == null) return;   // nothing keyable and nothing nameable

                if (ev.JobName != null && (item.Name == null || ev.EventId == 3)) item.Name = ev.JobName;
                if (ev.Owner != null && ev.EventId == 3) item.OwnerAccount = ev.Owner;
                if (ev.CreatorImage != null) item.CreatorImage = ev.CreatorImage;
                if (ev.CreatorPid > 0) item.CreatorPid = ev.CreatorPid;
                if (item.FirstSeenUtc == default || ev.TimeUtc < item.FirstSeenUtc) item.FirstSeenUtc = ev.TimeUtc;
                item.LastSeenUtc = ev.TimeUtc;

                if (ev.Url != null && !string.Equals(item.Url, ev.Url, StringComparison.OrdinalIgnoreCase))
                {
                    item.Url = ev.Url;
                    var (host, port) = SplitUrl(ev.Url);
                    item.Host = host;
                    item.Port = port;
                }

                switch (ev.EventId)
                {
                    case 59:   // transfer started — the "connection event" for frequency stats
                        AddStat(item);
                        break;
                    case 60:   // transfer stopped — status code tells success/failure
                        item.StatusText = DecodeStatus(ev.StatusCode);
                        break;
                    case 4:    // complete — hash what we can, persist once
                        Complete(item, ev.FileCount);
                        break;
                }

                item.Timeline.Add(new BitsEventRecord { TimeUtc = ev.TimeUtc, EventId = ev.EventId, Text = SummarizeEvent(ev) });
                if (item.Timeline.Count > 200) item.Timeline.RemoveRange(0, item.Timeline.Count - 200);

                PruneJobs();
            }

            OnJobUpserted?.Invoke(item);

            if (EnrichmentEnabled && ev.Url != null) TriggerEnrichment(item.JobId ?? $"name:{item.Name?.ToLowerInvariant()}");
        }

        private BitsJobItem GetOrCreate(ParsedBitsEvent ev)
        {
            // Identity ladder:
            //  • Event carries the GUID (EID 3/4) → authoritative row key.
            //  • Name-only events (EID 59/60 — the URL prose carries no Job
            //    ID) → adopt the OLDEST same-name row that still has no URL
            //    (BITS creates then starts each job; today's real log has
            //    three same-name Chrome jobs disambiguated exactly this
            //    way), else a row already bound to this exact URL, else a
            //    name|url keyed row.
            if (ev.JobId != null)
                return _jobs.GetOrAdd(ev.JobId, _ => new BitsJobItem { JobId = ev.JobId, Name = ev.JobName });

            string name = ev.JobName;
            if (name == null && ev.Url == null) return null;

            if (ev.Url != null)
            {
                var byUrl = _jobs.Values.FirstOrDefault(j =>
                    string.Equals(j.Url, ev.Url, StringComparison.OrdinalIgnoreCase));
                if (byUrl != null) return byUrl;
            }

            if (name != null)
            {
                var candidates = _jobs.Values
                    .Where(j => string.Equals(j.Name, name, StringComparison.OrdinalIgnoreCase)
                                && (ev.Url == null || j.Url == null))
                    .OrderBy(j => j.FirstSeenUtc == default ? DateTime.MaxValue : j.FirstSeenUtc)
                    .ToList();
                if (candidates.Count > 0) return candidates[0];
            }

            string fallbackKey = name != null && ev.Url != null
                ? $"name:{name.ToLowerInvariant()}|{ev.Url.ToLowerInvariant()}"
                : name != null ? $"name:{name.ToLowerInvariant()}" : $"url:{ev.Url.ToLowerInvariant()}";
            return _jobs.GetOrAdd(fallbackKey, _ => new BitsJobItem { Name = name });
        }

        private void PruneJobs()
        {
            if (_jobs.Count <= JobCap) return;
            foreach (var oldest in _jobs.OrderBy(kv => kv.Value.LastSeenUtc).Take(_jobs.Count - JobCap).ToList())
                _jobs.TryRemove(oldest.Key, out _);
        }

        internal static (string host, int port) SplitUrl(string url)
        {
            if (Uri.TryCreate(url, UriKind.Absolute, out var u))
                return (u.Host, u.Port > 0 ? u.Port : (u.Scheme == Uri.UriSchemeHttps ? 443 : 80));
            return (url, 0);
        }

        internal static string DecodeStatus(string statusCode)
        {
            if (string.IsNullOrEmpty(statusCode)) return null;
            return statusCode.ToLowerInvariant() switch
            {
                "0x0" => "completed ok",
                "0x80190194" => "failed: HTTP 404 not found",
                "0x80190191" => "failed: HTTP 401 unauthorized",
                "0x8019019f" => "failed: HTTP 415",
                "0x80190194 " => "failed: HTTP 404",
                "0x80072ee2" => "failed: timeout",
                "0x80072ee7" => "failed: host not resolved",
                "0x80070005" => "failed: access denied",
                "0x80190190" => "failed: HTTP 400",
                _ => $"status {statusCode}"
            };
        }

        private static string SummarizeEvent(ParsedBitsEvent ev) => ev.EventId switch
        {
            3 => "job created" + (ev.CreatorImage != null ? $" by {System.IO.Path.GetFileName(ev.CreatorImage)} (PID {ev.CreatorPid})" : ""),
            4 => "transfer job complete" + (ev.FileCount >= 0 ? $" ({ev.FileCount} file(s))" : ""),
            59 => "transfer started" + (ev.Url != null ? $" → {ev.Url}" : ""),
            60 => "transfer stopped" + (ev.StatusCode != null ? $" ({ev.StatusCode})" : ""),
            209 => "high-performance property enabled",
            310 => "peer helper init failed (peer caching off)",
            313 => "no connectivity reported (idle poll)",
            _ => $"event {ev.EventId}"
        };

        // -----------------------------------------------------------------------
        // COM live queue (read-only): direction, state, progress, file paths
        // -----------------------------------------------------------------------

        [DllImport("ole32.dll")]
        private static extern int CoCreateInstance(ref Guid clsid, IntPtr pUnkOuter, uint dwClsContext, ref Guid riid, out IntPtr ppv);

        private static IBackgroundCopyManager CreateManager()
        {
            foreach (var clsid in new[] { ClsidBitsManager10, ClsidBitsManager103 })
            {
                Guid c = clsid, iid = IidBackgroundCopyManager;
                int hr = CoCreateInstance(ref c, IntPtr.Zero, 4 /*CLSCTX_LOCAL_SERVER*/, ref iid, out IntPtr ppv);
                if (hr == 0)
                {
                    var mgr = (IBackgroundCopyManager)Marshal.GetObjectForIUnknown(ppv);
                    Marshal.Release(ppv);
                    return mgr;
                }
            }
            return null;   // BITS service unreachable (stopped/disabled) — retry next tick
        }

        private void PollCom()
        {
            IBackgroundCopyManager mgr = null;
            try
            {
                mgr = CreateManager();
                if (mgr == null)
                {
                    if (Interlocked.Increment(ref _comFailureCount) == 5)
                        OnError?.Invoke("BITS COM queue unreachable (service stopped?) — live direction/progress paused; event-log tracing continues.");
                    return;
                }
                Interlocked.Exchange(ref _comFailureCount, 0);

                // All-users first (app is elevated); fall back to current user.
                IEnumBackgroundCopyJobs jobs;
                try { mgr.EnumJobs(1, out jobs); }
                catch (UnauthorizedAccessException) { mgr.EnumJobs(0, out jobs); }

                jobs.GetCount(out uint count);
                for (uint i = 0; i < Math.Min(count, 500); i++)
                {
                    jobs.Next(1, out IBackgroundCopyJob job, out uint fetched);
                    if (fetched == 0) break;
                    MergeComJob(job);
                }
            }
            catch (Exception ex)
            {
                if (Interlocked.Increment(ref _comFailureCount) == 5)
                    OnError?.Invoke($"BITS COM poll error: {ex.Message}");
            }
        }

        private void MergeComJob(IBackgroundCopyJob job)
        {
            job.GetId(out Guid id);
            string key = id.ToString("D");
            var item = _jobs.GetOrAdd(key, _ => new BitsJobItem { JobId = key });

            job.GetDisplayName(out string name);
            if (!string.IsNullOrEmpty(name)) item.Name = name;
            job.GetOwner(out string owner);
            if (!string.IsNullOrEmpty(owner)) item.OwnerAccount = owner;

            job.GetType(out BG_JOB_TYPE type);
            string direction = type switch
            {
                BG_JOB_TYPE.DOWNLOAD => "Download",
                BG_JOB_TYPE.UPLOAD => "Upload",
                BG_JOB_TYPE.UPLOAD_REPLY => "Upload-reply",
                _ => null
            };
            if (direction != null && item.Direction != direction)
            {
                item.Direction = direction;
                if (item.IsUpload && _uploadAlerted.TryAdd(key, 0))
                {
                    var explained = BitsReasonCatalog.Explain(item);
                    item.Verdict = explained?.Verdict ?? "Review";
                    item.ReasonText = explained == null ? null : $"{explained.Title} — {explained.Text}";
                    OnUploadJob?.Invoke(item);
                }
            }

            job.GetState(out BG_JOB_STATE state);
            item.State = state switch
            {
                BG_JOB_STATE.QUEUED => "queued",
                BG_JOB_STATE.CONNECTING => "connecting",
                BG_JOB_STATE.TRANSFERRING => "transferring",
                BG_JOB_STATE.SUSPENDED => "suspended",
                BG_JOB_STATE.ERROR => "error",
                BG_JOB_STATE.TRANSIENT_ERROR => "transient error",
                BG_JOB_STATE.TRANSFERRED => "transferred",
                BG_JOB_STATE.ACKNOWLEDGED => "acknowledged",
                BG_JOB_STATE.CANCELLED => "cancelled",
                _ => item.State
            };

            job.GetProgress(out BG_JOB_PROGRESS p);
            item.BytesTotal = p.BytesTotal;
            item.BytesTransferred = p.BytesTransferred;

            job.EnumFiles(out IEnumBackgroundCopyFiles files);
            files.GetCount(out uint fc);
            bool filesChanged = false;
            for (uint f = 0; f < Math.Min(fc, 64); f++)
            {
                files.Next(1, out IBackgroundCopyFile file, out uint ff);
                if (ff == 0) break;
                file.GetRemoteName(out string remote);
                file.GetLocalName(out string local);
                lock (item.Files)
                {
                    var existing = item.Files.FirstOrDefault(x => string.Equals(x.RemoteName, remote, StringComparison.OrdinalIgnoreCase));
                    if (existing == null)
                    {
                        item.Files.Add(new BitsFileRef { RemoteName = remote, LocalName = local });
                        filesChanged = true;
                    }
                    else if (string.IsNullOrEmpty(existing.LocalName) && !string.IsNullOrEmpty(local))
                    {
                        existing.LocalName = local;
                        filesChanged = true;
                    }
                }
                if (string.IsNullOrEmpty(item.Url) && !string.IsNullOrEmpty(remote))
                {
                    item.Url = remote;
                    var (host, port) = SplitUrl(remote);
                    item.Host = host;
                    item.Port = port;
                }
            }
            if (filesChanged) item.NotifyFilesChanged();

            OnJobUpserted?.Invoke(item);

            if (EnrichmentEnabled && item.Host != null && !_enrichDone.ContainsKey(key + ":dns"))
                TriggerEnrichment(key);
            if (item.State is "transferred" or "acknowledged")
                Complete(item, -1);
        }

        // -----------------------------------------------------------------------
        // Enrichment: forward DNS → owner → signer → reason
        // -----------------------------------------------------------------------

        private void TriggerEnrichment(string key)
        {
            if (!EnrichmentEnabled) return;
            if (!_jobs.TryGetValue(key, out var item) || string.IsNullOrEmpty(item.Host)) return;
            if (!_enrichDone.TryAdd(key + ":dns", 0)) return;

            _ = Task.Run(async () =>
            {
                try
                {
                    string[] ips = await _dns.ResolveForwardAsync(item.Host);
                    if (ips is { Length: > 0 })
                    {
                        item.ResolvedIps = string.Join(", ", ips.Take(4));
                        string owner = null;
                        foreach (string ip in ips.Take(4))
                        {
                            string classified = IpClassification.Classify(ip);
                            if (classified != "Unclassified" && classified != "IPv6/other")
                            {
                                owner = classified == "Microsoft" || classified == "Azure"
                                    ? $"{classified} (Microsoft)"
                                    : classified;
                                break;
                            }
                        }
                        if (owner == null && ips.Length > 0)
                        {
                            try
                            {
                                var rdap = await RdapService.Instance.LookupAsync(ips[0]);
                                owner = rdap?.Org ?? rdap?.Netname;
                            }
                            catch { /* offline: leave as unresolved */ }
                        }
                        if (!string.IsNullOrEmpty(owner)) item.Org = owner;
                        SetStatOrg(item, owner);
                    }
                }
                catch { /* DNS offline — the row simply stays unenriched */ }

                // Creator signature (file may be gone for old jobs — that's fine)
                if (_enrichDone.TryAdd(key + ":signer", 0) && !string.IsNullOrEmpty(item.CreatorImage))
                {
                    try
                    {
                        if (File.Exists(item.CreatorImage))
                        {
                            var (trusted, subject, hr) = Helpers.AuthenticodeVerifier.Verify(item.CreatorImage);
                            item.CreatorSigner = trusted
                                ? $"✓ {subject}"
                                : $"unverified (0x{hr:X8})";
                        }
                        else item.CreatorSigner = "creator image no longer exists";
                    }
                    catch { item.CreatorSigner = "signature check failed"; }
                }

                // Reason + verdict (needs host/org/direction in place)
                if (_enrichDone.TryAdd(key + ":reason", 0))
                {
                    var explained = BitsReasonCatalog.Explain(item);
                    if (explained != null)
                    {
                        item.ReasonText = $"{explained.Title} — {explained.Text}";
                        // An upload verdict must never be downgraded by a catalog match
                        item.Verdict = item.IsUpload ? "Review" : explained.Verdict;
                    }
                }

                OnJobUpserted?.Invoke(item);
            });
        }

        // -----------------------------------------------------------------------
        // Completion: hash delivered files (metadata only), persist once
        // -----------------------------------------------------------------------

        private void Complete(BitsJobItem item, int fileCount)
        {
            lock (item.Files)
            {
                foreach (var f in item.Files)
                {
                    if (f.HashStatus != "pending" || string.IsNullOrEmpty(f.LocalName)) continue;
                    try
                    {
                        if (!File.Exists(f.LocalName))
                        {
                            f.HashStatus = "gone (moved or deleted after delivery)";
                            continue;
                        }
                        var fi = new FileInfo(f.LocalName);
                        f.LocalSize = fi.Length;
                        f.Sha256 = Sha256File(f.LocalName);
                        f.HashStatus = "hashed";
                    }
                    catch (UnauthorizedAccessException)
                    {
                        f.HashStatus = "access denied";
                    }
                    catch (IOException)
                    {
                        f.HashStatus = "busy (still transferring?)";
                    }
                }
                if (item.Files.Count == 0 && fileCount > 0)
                    item.Timeline.Add(new BitsEventRecord
                    {
                        TimeUtc = DateTime.UtcNow,
                        EventId = 4,
                        Text = $"{fileCount} file(s) delivered — local paths unknown (job predates live tracing or ran as another session); URL basename is the filename."
                    });
            }
            item.NotifyFilesChanged();
            if (item.State == null) item.State = "completed";
            PersistJob(item);
        }

        /// <summary>SHA-256 of a delivered file. Size + hash only — content bytes are never retained.</summary>
        internal static string Sha256File(string path)
        {
            using var sha = SHA256.Create();
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            byte[] hash = sha.ComputeHash(stream);
            var sb = new StringBuilder(hash.Length * 2);
            foreach (byte b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        private void PersistJob(BitsJobItem item)
        {
            string key = item.JobId ?? $"name:{item.Name?.ToLowerInvariant()}";
            if (key == null || !_persisted.TryAdd(key, 0)) return;
            try
            {
                Directory.CreateDirectory(BitsDir);   // idempotent; Start() may not have run (self-test)
                var record = new
                {
                    item.JobId,
                    item.Name,
                    item.FirstSeenUtc,
                    item.LastSeenUtc,
                    item.CreatorImage,
                    item.CreatorPid,
                    item.CreatorSigner,
                    item.OwnerAccount,
                    item.Direction,
                    item.Url,
                    item.Host,
                    item.Port,
                    item.ResolvedIps,
                    item.Org,
                    BytesTotal = item.BytesTotal == 0 ? null : (long?)item.BytesTotal,
                    BytesTransferred = item.BytesTransferred == 0 ? null : (long?)item.BytesTransferred,
                    item.StatusText,
                    item.State,
                    item.Verdict,
                    item.ReasonText,
                    Files = item.Files.Select(f => new { f.RemoteName, f.LocalName, f.LocalSize, f.Sha256, f.HashStatus }).ToList()
                };
                File.AppendAllText(JobsLogPath, JsonSerializer.Serialize(record) + Environment.NewLine);
            }
            catch { /* disk issues never stop tracing */ }
        }

        // -----------------------------------------------------------------------
        // Frequency stats + persistence
        // -----------------------------------------------------------------------

        private static string StatKey(BitsJobItem item) => $"{item.CreatorImage ?? "?"}|{item.Host ?? "?"}";

        private void AddStat(BitsJobItem item)
        {
            if (string.IsNullOrEmpty(item.Host)) return;
            lock (_statsSync)
            {
                string key = StatKey(item);
                if (!_stats.TryGetValue(key, out var stat))
                {
                    stat = new BitsJobStat { CreatorImage = item.CreatorImage, Host = item.Host, Org = item.Org };
                    _stats[key] = stat;
                }
                stat.Add(item.LastSeenUtc == default ? DateTime.UtcNow : item.LastSeenUtc, item.IsUpload);
                if (stat.LastSeenUtc < _statsFirstKey) _statsFirstKey = stat.LastSeenUtc;
                _statsDirty = true;
            }
        }

        private void SetStatOrg(BitsJobItem item, string owner)
        {
            if (string.IsNullOrEmpty(item.Host) || string.IsNullOrEmpty(owner)) return;
            lock (_statsSync)
            {
                if (_stats.TryGetValue(StatKey(item), out var stat) && string.IsNullOrEmpty(stat.Org))
                {
                    stat.Org = owner;
                    _statsDirty = true;
                }
            }
        }

        public List<BitsJobStat> StatsSnapshot()
        {
            lock (_statsSync) return _stats.Values.OrderByDescending(s => s.LastSeenUtc).ToList();
        }

        public List<BitsJobItem> JobsSnapshot()
        {
            return _jobs.Values.Where(j => j.JobId != null || j.Name != null)
                                .OrderByDescending(j => j.LastSeenUtc).ToList();
        }

        private sealed class StatsDto
        {
            public string CreatorImage { get; set; }
            public string Host { get; set; }
            public string Org { get; set; }
            public int JobCount { get; set; }
            public int UploadCount { get; set; }
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
            public Dictionary<string, int> Daily { get; set; }
        }

        private void PersistStatsIfDirty()
        {
            List<StatsDto> snapshot;
            lock (_statsSync)
            {
                if (!_statsDirty) return;
                _statsDirty = false;
                snapshot = _stats.Values.Select(s => new StatsDto
                {
                    CreatorImage = s.CreatorImage,
                    Host = s.Host,
                    Org = s.Org,
                    JobCount = s.JobCount,
                    UploadCount = s.UploadCount,
                    FirstSeenUtc = s.FirstSeenUtc,
                    LastSeenUtc = s.LastSeenUtc,
                    Daily = s.Daily
                }).ToList();
            }
            try
            {
                string tmp = StatsPath + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true }));
                if (File.Exists(StatsPath)) File.Replace(tmp, StatsPath, null);
                else File.Move(tmp, StatsPath);
            }
            catch { /* retried on the next dirty flush */ }
        }

        private void LoadStats()
        {
            try
            {
                if (!File.Exists(StatsPath)) return;
                var list = JsonSerializer.Deserialize<List<StatsDto>>(File.ReadAllText(StatsPath));
                if (list == null) return;
                lock (_statsSync)
                {
                    foreach (var dto in list)
                    {
                        var stat = new BitsJobStat
                        {
                            CreatorImage = dto.CreatorImage,
                            Host = dto.Host,
                            Org = dto.Org
                        };
                        stat.Restore(dto.JobCount, dto.UploadCount, dto.FirstSeenUtc, dto.LastSeenUtc, dto.Daily);
                        _stats[$"{dto.CreatorImage ?? "?"}|{dto.Host ?? "?"}"] = stat;
                    }
                }
            }
            catch { /* corrupt file — start fresh */ }
        }
    }
}
