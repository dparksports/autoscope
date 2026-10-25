using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
using AutoScope.Models;

namespace AutoScope.Services
{
    public class SysmonWatcherService
    {
        private EventLogWatcher _watcher;
        private readonly ConcurrentDictionary<string, SvchostMonitorItem> _trackedIps;
        private readonly DnsResolutionService _dnsService;

        // Same regex from monitor_ultimate.py
        private static readonly Regex KnownDomainsRegex = new Regex(
            @"(?i)(microsoft|windows|azure|msedge|trafficmanager|google|1e100|googleapis|bing|live|office|skype|msn|azureedge)",
            RegexOptions.Compiled);

        public event Action<string> OnError;
        public event Action<SvchostMonitorItem> OnNewConnectionTracked;

        private readonly ConcurrentBag<string> _targetProcesses = new ConcurrentBag<string> { "svchost.exe" };
        public bool MonitorAllProcesses { get; set; } = false;
        public bool FilterKnownCloudIps { get; set; } = false;

        // Processes the user asked to keep out of the list, matched on the
        // image file name (e.g. "chrome.exe"), case-insensitively.
        private readonly ConcurrentBag<string> _ignoredProcesses = new ConcurrentBag<string>();
        // WinUI port: was CWD-relative ("ignored_processes.txt") — an
        // elevated launch starts in C:\Windows\System32, which scattered
        // the file (and broke migration). Anchored to the app data dir now.
        private static string IgnoredProcessesPath => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoScope", "ignored_processes.txt");

        public SysmonWatcherService(
            ConcurrentDictionary<string, SvchostMonitorItem> trackedIps,
            DnsResolutionService dnsService)
        {
            _trackedIps  = trackedIps;
            _dnsService  = dnsService;
            LoadIgnoredProcesses();
        }

        public void AddTargetProcess(string processName)
        {
            if (!_targetProcesses.Contains(processName, StringComparer.OrdinalIgnoreCase))
            {
                _targetProcesses.Add(processName);
            }
        }

        // -----------------------------------------------------------------------
        // User ignore list
        // -----------------------------------------------------------------------

        /// <summary>Process names currently on the ignore list.</summary>
        public IReadOnlyCollection<string> IgnoredProcesses => _ignoredProcesses.ToArray();

        /// <summary>
        /// Adds a process to the ignore list: its connections will no longer
        /// create list entries. The ".exe" suffix is added when missing.
        /// </summary>
        public void AddIgnoredProcess(string processName)
        {
            string normalized = NormalizeProcessName(processName);
            if (normalized.Length == 0) return;
            if (_ignoredProcesses.Contains(normalized, StringComparer.OrdinalIgnoreCase)) return;

            _ignoredProcesses.Add(normalized);
            SaveIgnoredProcesses();
        }

        public void RemoveIgnoredProcess(string processName)
        {
            string normalized = NormalizeProcessName(processName);
            if (normalized.Length == 0) return;

            var remaining = _ignoredProcesses
                .Where(p => !p.Equals(normalized, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (remaining.Count == _ignoredProcesses.Count) return;

            // ConcurrentBag has no conditional removal — drain it and refill
            while (_ignoredProcesses.TryTake(out _)) { }
            foreach (var p in remaining) _ignoredProcesses.Add(p);
            SaveIgnoredProcesses();
        }

        /// <summary>True when the given process name (or full image path) is ignored.</summary>
        public bool IsProcessIgnored(string processName)
        {
            string normalized = NormalizeProcessName(processName);
            return normalized.Length > 0 &&
                   _ignoredProcesses.Contains(normalized, StringComparer.OrdinalIgnoreCase);
        }

        private static string NormalizeProcessName(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return string.Empty;
            string name = Path.GetFileName(processName.Trim());
            if (name.Length == 0) return string.Empty;
            if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name += ".exe";
            return name;
        }

        // ── File-backed ignore check for other tabs ─────────────────────────
        //
        // The ignore list is a user setting ("stop listing this process"), so
        // the Traffic Patterns tab honors it too, even though its packet-
        // capture pipeline never goes through a SysmonWatcherService instance.
        // Cached with a short TTL: consulted per finalized flow and per
        // snapshot, and instance methods rewrite the file on every change.

        private static readonly object _fileIgnoreLock = new object();
        private static HashSet<string> _fileIgnored = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static DateTime _fileIgnoredLoadedUtc = DateTime.MinValue;

        /// <summary>
        /// True when the process name is on the shared ignore list file
        /// (ignored_processes.txt) — the same list the Process Monitor enforces.
        /// </summary>
        public static bool IsIgnoredByFile(string processName)
        {
            string normalized = NormalizeProcessName(processName);
            if (normalized.Length == 0) return false;
            lock (_fileIgnoreLock)
            {
                if ((DateTime.UtcNow - _fileIgnoredLoadedUtc).TotalSeconds > 30)
                {
                    var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    try
                    {
                        foreach (string line in File.ReadAllLines(IgnoredProcessesPath))
                        {
                            string n = NormalizeProcessName(line);
                            if (n.Length > 0) set.Add(n);
                        }
                    }
                    catch { /* missing or unreadable file — empty list */ }
                    _fileIgnored = set;
                    _fileIgnoredLoadedUtc = DateTime.UtcNow;
                }
                return _fileIgnored.Contains(normalized);
            }
        }

        private void LoadIgnoredProcesses()
        {
            try
            {
                foreach (var line in File.ReadAllLines(IgnoredProcessesPath))
                    AddIgnoredProcess(line);
            }
            catch { /* first run or unreadable file — start with an empty ignore list */ }
        }

        private void SaveIgnoredProcesses()
        {
            try
            {
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(IgnoredProcessesPath));
                File.WriteAllLines(IgnoredProcessesPath,
                    _ignoredProcesses.OrderBy(p => p, StringComparer.OrdinalIgnoreCase));
            }
            catch { /* persistence is best-effort — filtering still works without it */ }
        }

        public void Start()
        {
            try
            {
                var query = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName, "*[System[(EventID=3)]]");
                _watcher = new EventLogWatcher(query);
                _watcher.EventRecordWritten += Watcher_EventRecordWritten;
                _watcher.Enabled = true;
            }
            catch (EventLogNotFoundException)
            {
                OnError?.Invoke("Sysmon is not installed. Please install Sysmon to use this feature.");
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Failed to start Sysmon watcher: {ex.Message}");
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
        }

        /// <summary>
        /// Seeds the tracked-IP table with the machine's currently
        /// established TCP connections. The event path only sees connections
        /// opened from now on — long-lived channels (svchost's boot-time WNS
        /// link, persistent update/telemetry sockets) never fire a new
        /// Event ID 3, so without this snapshot they stay invisible until
        /// they happen to reconnect. Same filters as the event path (ignore
        /// list, ignored IPs, cloud filter, one row per IP); rows surface
        /// through OnNewConnectionTracked exactly like event-driven ones,
        /// so callers on any thread get UI marshaling for free. Returns the
        /// number of rows seeded. IPv4 only — GetExtendedTcpTable queries
        /// AF_INET, and the live event path covers v6 anyway. The kernel
        /// table is enumerated before any per-PID name lookup, so the join
        /// can never name a PID from data older than the connection rows
        /// themselves (the netstat-era PID-reuse race).
        /// </summary>
        public int SeedBaseline()
        {
            List<TcpConnectionTable.Row> connections;
            try { connections = TcpConnectionTable.GetEstablished(); }
            catch { return 0; } // enumeration unavailable — the event path still works

            int seeded = 0;
            foreach (var c in connections)
            {
                try
                {
                    string destIp = c.RemoteIp;
                    if (string.IsNullOrEmpty(destIp) || IsIgnoredIp(destIp)) continue;
                    if (FilterKnownCloudIps && IsKnownCloudIp(destIp)) continue;

                    int pid = c.Pid;
                    string image = TryGetProcessPath(pid);
                    string processName = ResolveProcessName(pid);
                    if (string.IsNullOrEmpty(processName) && !string.IsNullOrEmpty(image))
                        processName = Path.GetFileName(image);
                    if (string.IsNullOrEmpty(processName)) continue; // unattributable

                    // Same gates as Watcher_EventRecordWritten, same order
                    if (IsProcessIgnored(image) || IsProcessIgnored(processName)) continue;
                    bool isTarget = MonitorAllProcesses;
                    if (!isTarget)
                    {
                        string matchName = image ?? NormalizeProcessName(processName);
                        foreach (var target in _targetProcesses)
                            if (matchName.EndsWith(target, StringComparison.OrdinalIgnoreCase)) { isTarget = true; break; }
                    }
                    if (!isTarget) continue;
                    if (_trackedIps.ContainsKey(destIp)) continue; // a row already covers this IP

                    string initialHost = _dnsService.GetCachedHostname(destIp) ?? destIp;
                    if (FilterKnownCloudIps && KnownDomainsRegex.IsMatch(initialHost)) continue;

                    var item = new SvchostMonitorItem
                    {
                        ProcessId = pid,
                        ProcessName = processName,
                        ImagePath = image,
                        RemoteIp = destIp,
                        Hostname = initialHost,
                        Protocol = "tcp",
                        ProcessStartedUtc = TryGetProcessStartUtc(pid),
                        // Alive right now by definition — a real LastSeen
                        // keeps the row out of the stale-dimming skip list
                        LastSeen = DateTime.UtcNow,
                        RxBytes = 0, TxBytes = 0, RxPackets = 0, TxPackets = 0
                    };

                    if (_trackedIps.TryAdd(destIp, item))
                    {
                        OnNewConnectionTracked?.Invoke(item);
                        _dnsService.EnqueueForResolution(item);
                        seeded++;
                    }
                }
                catch { /* one bad row must not abort the snapshot */ }
            }
            return seeded;
        }

        private void Watcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                if (e.EventRecord == null) return;

                string xml = e.EventRecord.ToXml();
                var doc = XDocument.Parse(xml);
                XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";

                var eventData = doc.Root?.Element(ns + "EventData");
                if (eventData == null) return;

                string image = string.Empty;
                string processId = string.Empty;
                string destIp = string.Empty;
                string destHost = string.Empty;
                string utcTime = string.Empty;
                string protocol = "TCP"; // Default

                foreach (var data in eventData.Elements(ns + "Data"))
                {
                    string name = data.Attribute("Name")?.Value;
                    if (name == "Image") image = data.Value;
                    else if (name == "ProcessId") processId = data.Value;
                    else if (name == "DestinationIp") destIp = data.Value;
                    else if (name == "DestinationHostname") destHost = data.Value;
                    else if (name == "UtcTime") utcTime = data.Value;
                    else if (name == "Protocol") protocol = data.Value;
                }

                // User ignore list: these processes never create list entries
                if (IsProcessIgnored(image)) return;

                // Monitor target processes
                bool isTarget = MonitorAllProcesses;
                if (!isTarget)
                {
                    foreach (var target in _targetProcesses)
                    {
                        if (image.EndsWith(target, StringComparison.OrdinalIgnoreCase))
                        {
                            isTarget = true;
                            break;
                        }
                    }
                }

                if (!isTarget) return;
                if (string.IsNullOrEmpty(destIp) || IsIgnoredIp(destIp)) return;
                
                if (FilterKnownCloudIps && IsKnownCloudIp(destIp)) return;

                // The event's own Image is the ground truth — it names the
                // exact process that opened this connection. A live PID
                // lookup can only degrade it: an exited PID returns nothing,
                // a recycled one returns the WRONG tenant's name. Live
                // lookup runs only when Sysmon itself gave no image.
                int pid = int.TryParse(processId, out int p) ? p : 0;
                string processName = string.IsNullOrEmpty(image) ? ResolveProcessName(pid) : Path.GetFileName(image);

                if (_trackedIps.TryGetValue(destIp, out var existing))
                {
                    // Same process reconnecting — the row already covers it.
                    if (existing.ProcessId == pid) return;

                    // A different PID on an already-tracked IP: when the row's
                    // original process has exited, hand the row to the newcomer
                    // so counters accrue to a live process instead of a ghost
                    // PID. While the original is still alive the row stays with
                    // it — the dictionary is keyed by remote IP alone, so one
                    // row per IP is all the model allows.
                    if (existing.ProcessId <= 0 || IsProcessAlive(existing.ProcessId)) return;

                    existing.Reattribute(pid, processName, string.IsNullOrEmpty(image) ? null : image,
                        TryGetProcessStartUtc(pid));
                    return;
                }

                // Seed cache if Sysmon already gave us the hostname
                if (!string.IsNullOrEmpty(destHost) && destHost != "-")
                    _dnsService.SeedFromSysmon(destIp, destHost);

                // Build the item immediately with whatever we have; DNS service
                // will fill in Hostname asynchronously and the DataGrid will refresh.
                string initialHost = _dnsService.GetCachedHostname(destIp) ?? destIp;

                if (FilterKnownCloudIps && KnownDomainsRegex.IsMatch(initialHost)) return;

                var item = new SvchostMonitorItem
                {
                    ProcessId   = pid,
                    ProcessName = processName,
                    ImagePath   = string.IsNullOrEmpty(image) ? null : image,
                    RemoteIp    = destIp,
                    Hostname    = initialHost,
                    Protocol    = protocol,
                    // Capture-time identity anchor: the start time binds the
                    // row to this tenant of the PID, so a later inquiry can
                    // never mistake a recycled PID's new owner for it.
                    ProcessStartedUtc = TryGetProcessStartUtc(pid),
                    // Seed from the event itself: the packets that triggered
                    // this event usually crossed the wire before the row
                    // entered tracking, so a one-shot connection would else
                    // show "—" forever (and never dim — IsStale skips rows
                    // with a default LastSeen).
                    LastSeen = TryParseUtcTime(utcTime) ?? DateTime.UtcNow,
                    RxBytes = 0, TxBytes = 0, RxPackets = 0, TxPackets = 0
                };

                if (_trackedIps.TryAdd(destIp, item))
                {
                    OnNewConnectionTracked?.Invoke(item);

                    // Queue for async resolution (no-op if cache already had a real name)
                    _dnsService.EnqueueForResolution(item);
                }
            }
            catch { }
        }

        // -----------------------------------------------------------------------
        // Process name resolution
        // -----------------------------------------------------------------------

        /// <summary>
        /// Looks up the process name for a given PID.
        /// Returns empty string if the process has already exited or access is denied.
        /// </summary>
        private static string ResolveProcessName(int pid)
        {
            if (pid <= 0) return string.Empty;
            try
            {
                return Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                // Process has already exited, or we don't have access (e.g. System/Idle)
                return string.Empty;
            }
        }

        /// <summary>
        /// The PID's executable path, or null when unreadable (exited, System,
        /// or access denied). Baseline rows carry it so their identity
        /// survives process exit exactly like Sysmon-sourced rows.
        /// </summary>
        private static string TryGetProcessPath(int pid)
        {
            if (pid <= 0) return null;
            try { return Process.GetProcessById(pid).MainModule?.FileName; }
            catch { return null; }
        }

        /// <summary>
        /// The PID's start time (UTC), or null when unreadable (exited or
        /// access denied). Called once per row creation — this is the
        /// timestamp that keeps a row's identity safe from PID recycling.
        /// </summary>
        private static DateTime? TryGetProcessStartUtc(int pid)
        {
            if (pid <= 0) return null;
            try { return Process.GetProcessById(pid).StartTime.ToUniversalTime(); }
            catch { return null; }
        }

        /// <summary>True while the PID still exists (PID 0, System/Idle, never exits).</summary>
        private static bool IsProcessAlive(int pid)
        {
            if (pid <= 0) return true;
            try { Process.GetProcessById(pid); return true; }
            catch { return false; }
        }

        /// <summary>
        /// Parses Sysmon's UtcTime field ("2026-10-13 23:48:53.123"). Null
        /// when absent or in an unexpected format.
        /// </summary>
        private static DateTime? TryParseUtcTime(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            if (DateTime.TryParseExact(value.Trim(),
                    new[] { "yyyy-MM-dd HH:mm:ss.fff", "yyyy-MM-dd HH:mm:ss" },
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var parsed))
                return parsed;
            return null;
        }

        // -----------------------------------------------------------------------
        // IP filtering helpers
        // -----------------------------------------------------------------------

        private static bool IsIgnoredIp(string ipStr) =>
            // Shared with the sampled paths: loopback / link-local / ULA /
            // multicast / broadcast for BOTH families. IPv6 events used to
            // slip past this with only a literal "::1" check, seeding
            // link-local and ULA destinations as if they were internet rows.
            TcpConnectionTable.IsLocalOrNonRoutable(ipStr);

        private static readonly IPNetwork[] KnownCidrBlocks = {
            new IPNetwork(IPAddress.Parse("20.0.0.0"), 8),
            new IPNetwork(IPAddress.Parse("52.0.0.0"), 8),
            new IPNetwork(IPAddress.Parse("13.64.0.0"), 11),
            new IPNetwork(IPAddress.Parse("40.74.0.0"), 15),
            new IPNetwork(IPAddress.Parse("104.40.0.0"), 13),
            new IPNetwork(IPAddress.Parse("137.116.0.0"), 16),
            new IPNetwork(IPAddress.Parse("204.79.197.0"), 24),
            new IPNetwork(IPAddress.Parse("8.8.4.0"), 24),
            new IPNetwork(IPAddress.Parse("8.8.8.0"), 24),
            new IPNetwork(IPAddress.Parse("34.0.0.0"), 8),
            new IPNetwork(IPAddress.Parse("35.0.0.0"), 8),
            new IPNetwork(IPAddress.Parse("74.125.0.0"), 16),
            new IPNetwork(IPAddress.Parse("142.250.0.0"), 15),
            new IPNetwork(IPAddress.Parse("172.217.0.0"), 16),
            new IPNetwork(IPAddress.Parse("216.58.192.0"), 19)
        };

        private static bool IsKnownCloudIp(string ipStr)
        {
            if (!IPAddress.TryParse(ipStr, out var ip)) return false;
            foreach (var net in KnownCidrBlocks)
            {
                if (net.Contains(ip)) return true;
            }
            return false;
        }
    }

    // Helper for CIDR math
    public class IPNetwork
    {
        private readonly uint _networkAddress;
        private readonly uint _subnetMask;

        public IPNetwork(IPAddress ipAddress, int prefixLength)
        {
            byte[] ipBytes = ipAddress.GetAddressBytes();
            if (BitConverter.IsLittleEndian) Array.Reverse(ipBytes);
            uint ip = BitConverter.ToUInt32(ipBytes, 0);

            _subnetMask = prefixLength == 0 ? 0 : 0xFFFFFFFF << (32 - prefixLength);
            _networkAddress = ip & _subnetMask;
        }

        public bool Contains(IPAddress ipAddress)
        {
            if (ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
            byte[] ipBytes = ipAddress.GetAddressBytes();
            if (BitConverter.IsLittleEndian) Array.Reverse(ipBytes);
            uint ip = BitConverter.ToUInt32(ipBytes, 0);

            return (ip & _subnetMask) == _networkAddress;
        }
    }
}
