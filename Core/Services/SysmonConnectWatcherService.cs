using System;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Xml.Linq;

namespace AutoScope.Services
{
    /// <summary>
    /// Watches Sysmon EID 3 (network connect) for ALL processes — no image
    /// filter, no spawn tracking — and raises the full 4-tuple. Used by the
    /// Traffic Patterns tab to attribute captured TCP flows to their pid/image
    /// via TcpStreamCaptureService.TagFlow. The python-focused watcher in
    /// ImageSpawnWatcherService stays separate; TagFlow is first-writer-wins,
    /// so both watching at once is harmless.
    /// </summary>
    public sealed class SysmonConnectWatcherService
    {
        private EventLogWatcher _watcher;

        public event Action<string> OnError;
        public event Action<SysmonConnectEvent> OnConnect;

        public void Start()
        {
            try
            {
                var query = new EventLogQuery("Microsoft-Windows-Sysmon/Operational",
                    PathType.LogName, "*[System[(EventID=3)]]");
                _watcher = new EventLogWatcher(query);
                _watcher.EventRecordWritten += Watcher_EventRecordWritten;
                _watcher.Enabled = true;
            }
            catch (EventLogNotFoundException)
            {
                OnError?.Invoke("Sysmon is not installed. Install it from the Sysmon Audit tab — process attribution needs it.");
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Failed to start connect watcher: {ex.Message}");
            }
        }

        public void Stop()
        {
            _watcher?.Dispose();
            _watcher = null;
        }

        private void Watcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                if (e.EventRecord == null) return;

                // EventData is parsed BY NAME, never by property index — the
                // field order varies across Sysmon versions.
                var doc = XDocument.Parse(e.EventRecord.ToXml());
                XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
                var eventData = doc.Root?.Element(ns + "EventData");
                if (eventData == null) return;

                string image = "", pidRaw = "", srcIp = "", srcPort = "", dstIp = "", dstPort = "", proto = "tcp";
                foreach (var data in eventData.Elements(ns + "Data"))
                {
                    switch (data.Attribute("Name")?.Value)
                    {
                        case "Image": image = data.Value; break;
                        case "ProcessId": pidRaw = data.Value; break;
                        case "SourceIp": srcIp = data.Value; break;
                        case "SourcePort": srcPort = data.Value; break;
                        case "DestinationIp": dstIp = data.Value; break;
                        case "DestinationPort": dstPort = data.Value; break;
                        case "Protocol": proto = data.Value; break;
                    }
                }

                int pid = ParsePid(pidRaw);
                if (pid <= 0 || string.IsNullOrEmpty(image)) return;

                OnConnect?.Invoke(new SysmonConnectEvent
                {
                    TimeUtc = e.EventRecord.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
                    Pid = pid,
                    Image = image,
                    SourceIp = srcIp,
                    SourcePort = ParsePort(srcPort),
                    DestIp = dstIp,
                    DestPort = ParsePort(dstPort),
                    Protocol = proto
                });
            }
            catch { /* a malformed record never takes the watcher down */ }
        }

        /// <summary>Sysmon PIDs are decimal in most EID 3 versions but hex (0x…) in some.</summary>
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
    }

    /// <summary>A TCP/UDP connect as seen by Sysmon EID 3, full 4-tuple, any process.</summary>
    public class SysmonConnectEvent
    {
        public DateTime TimeUtc { get; set; }
        public int Pid { get; set; }
        public string Image { get; set; }
        public string SourceIp { get; set; }
        public int SourcePort { get; set; }
        public string DestIp { get; set; }
        public int DestPort { get; set; }
        public string Protocol { get; set; }

        public bool IsTcp => string.Equals(Protocol, "tcp", StringComparison.OrdinalIgnoreCase);
    }
}
