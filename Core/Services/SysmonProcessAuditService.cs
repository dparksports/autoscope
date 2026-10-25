using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Xml.Linq;

namespace AutoScope.Services
{
    /// <summary>One Sysmon EventID 1 (ProcessCreate) record.</summary>
    public class SysmonProcessEvent
    {
        public DateTime Time { get; set; }
        public int ProcessId { get; set; }
        public int ParentProcessId { get; set; }
        public string Image { get; set; }
        public string CommandLine { get; set; }
        public string ParentImage { get; set; }
        public string User { get; set; }
    }

    /// <summary>
    /// Live and historical feed of Sysmon process-creation events (EventID 1):
    /// every launch with its full command line and parent image — the record
    /// Windows does not keep by default, and the reason short-lived processes
    /// (spawned helpers, one-shot scripts) become attributable after they exit.
    /// </summary>
    public class SysmonProcessAuditService
    {
        private const string ChannelName = "Microsoft-Windows-Sysmon/Operational";
        private const string ProcessCreateXPath = "*[System[(EventID=1)]]";

        private EventLogWatcher _watcher;

        public event Action<SysmonProcessEvent> OnProcessCreated;
        public event Action<string> OnError;

        public bool IsRunning { get; private set; }

        public void Start()
        {
            if (IsRunning) return;
            try
            {
                var query = new EventLogQuery(ChannelName, PathType.LogName, ProcessCreateXPath);
                _watcher = new EventLogWatcher(query);
                _watcher.EventRecordWritten += Watcher_EventRecordWritten;
                _watcher.Enabled = true;
                IsRunning = true;
            }
            catch (EventLogNotFoundException)
            {
                OnError?.Invoke("Sysmon is not installed — process-creation capture is unavailable.");
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Failed to start process-creation watcher: {ex.Message}");
            }
        }

        public void Stop()
        {
            if (_watcher != null)
            {
                _watcher.Enabled = false;
                _watcher.Dispose();
                _watcher = null;
            }
            IsRunning = false;
        }

        /// <summary>
        /// Reads the most recent ProcessCreate events from the log. Bounded by
        /// time (not just count) so the sequential read stays cheap even when
        /// the channel holds months of events.
        /// </summary>
        /// <param name="maxCount">Upper bound on rows returned.</param>
        /// <param name="window">How far back to read.</param>
        public List<SysmonProcessEvent> ReadRecent(int maxCount, TimeSpan? window = null)
        {
            var results = new List<SysmonProcessEvent>();
            window ??= TimeSpan.FromHours(1);

            try
            {
                long windowMs = (long)window.Value.TotalMilliseconds;
                string xpath = $"*[System[(EventID=1) and TimeCreated[timediff(@SystemTime) <= {windowMs}]]]";
                var query = new EventLogQuery(ChannelName, PathType.LogName, xpath);
                using var reader = new EventLogReader(query);
                for (var record = reader.ReadEvent(); record != null; record = reader.ReadEvent())
                {
                    var evt = ParseRecord(record);
                    if (evt != null) results.Add(evt);
                }
            }
            catch (EventLogNotFoundException)
            {
                // Not installed — caller shows install guidance
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Failed to read process-creation history: {ex.Message}");
            }

            return results
                .OrderByDescending(e => e.Time)
                .Take(maxCount)
                .ToList();
        }

        private void Watcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;
            try
            {
                var evt = ParseRecord(e.EventRecord);
                if (evt != null) OnProcessCreated?.Invoke(evt);
            }
            catch { /* one malformed record must not stop the feed */ }
        }

        private static SysmonProcessEvent ParseRecord(EventRecord record)
        {
            var doc = XDocument.Parse(record.ToXml());
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var eventData = doc.Root?.Element(ns + "EventData");
            if (eventData == null) return null;

            var evt = new SysmonProcessEvent { Time = record.TimeCreated ?? DateTime.MinValue };
            foreach (var data in eventData.Elements(ns + "Data"))
            {
                string name = data.Attribute("Name")?.Value;
                switch (name)
                {
                    case "Image": evt.Image = data.Value; break;
                    case "CommandLine": evt.CommandLine = data.Value; break;
                    case "ParentImage": evt.ParentImage = data.Value; break;
                    case "User": evt.User = data.Value; break;
                    case "ProcessId": evt.ProcessId = int.TryParse(data.Value, out int pid) ? pid : 0; break;
                    case "ParentProcessId": evt.ParentProcessId = int.TryParse(data.Value, out int ppid) ? ppid : 0; break;
                }
            }
            return evt;
        }
    }
}
