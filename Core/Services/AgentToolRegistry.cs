using System.Collections.Generic;
using AutoCommand.Engines.Bridge;
using AutoCommand.Engines.Watch;
using AutoCommand.Engines.Firewall;
using AutoCommand.Engines.Core;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using SvchostAnalyzer.Core;

using AutoCommand.Engines.Diagnosis;

namespace AutoScope.Services
{
    /// <summary>
    /// The MCP tool surface the AI-access bridge exposes. Read-only tools
    /// wrap services the running (elevated) app already trusts — the AI gets
    /// answers, never credentials and never raw UAC prompts. Mutating tools
    /// exist only when the user enabled them for the session, and every call
    /// passes through the bridge's confirmation dialog before executing.
    ///
    /// Handlers run on a background thread; they must not touch UI state.
    /// Anything that needs elevation fails with a plain-language note when
    /// the session happens to run non-elevated — degrade, never guess.
    /// </summary>
    public static class AgentToolRegistry
    {
        public sealed record Tool(
            string Name,
            string Description,
            JsonObject Schema,
            bool Mutating,
            Func<JsonObject, string> Handler,
            Func<JsonObject, string> ConfirmDetail = null);

        // ── registry access ───────────────────────────────────────────────

        private static readonly List<Tool> Tools = new()
        {
            new Tool(
                "get_monitor_rows",
                "Live snapshot of every established outbound TCP connection on the machine (IPv4 and IPv6), " +
                "attributed to its process — svchost instances decoded to their hosted service " +
                "(SCM ground truth + -k/-s command-line tokens) and each destination classified " +
                "(Microsoft/Azure, Akamai, Gcore, unclassified). Same view as AutoScope's Process Monitor.",
                Schema(),
                false,
                a => ToJson(BuildMonitorSnapshot())),
            new Tool(
                "get_svchost_identity",
                "Identify one svchost.exe instance: the services the SCM says it hosts (ground truth), " +
                "its command-line -k group and -s service claim, and whether the claim corroborates. " +
                "A mismatch is a masquerade signal.",
                Schema(("pid", "Process ID of the svchost.exe instance", true)),
                false,
                a => GetSvchostIdentity(a)),

            new Tool(
                "run_pid_inquiry",
                "Full provenance trace of a PID: verdict, identity, verified spawn chain, hosted services, " +
                "Sysmon corroboration — the same report AutoScope's PID Inquiry window renders. " +
                "Needs the elevated app for SYSTEM process command lines; degrades gracefully otherwise.",
                Schema(("pid", "Process ID to trace", true)),
                false,
                a => RunPidInquiry(a)),

            new Tool(
                "tail_sysmon",
                "Recent events from the Sysmon/Operational log (process creates, network connections, " +
                "process terminates). Needs the elevated app; returns a clear note when unreadable. " +
                "With archive=true: reads the app's Sysmon archive instead — every event backfilled or " +
                "watched since the archive began (default 30 days), including events that already " +
                "wrapped out of the rolling live channel.",
                Schema(("minutes", "Look this many minutes back (default 30)", false),
                       ("eid", "Filter to one Sysmon event ID (e.g. 1=process create, 3=network)", false),
                       ("contains", "Only events whose description contains this text (case-insensitive)", false),
                       ("max", "Maximum events to return (default 50, cap 500)", false),
                       ("archive", "true = query the app's Sysmon archive instead of the live log", false)),
                false,
                a => TailSysmon(a)),

            new Tool(
                "trace_analyze",
                "Run AutoScope's svchost trace analyzer. With seconds>0: capture live traffic for that " +
                "long, then analyze (parentage, identity corroboration, destinations, beacon regularity, " +
                "upload dominance). With seconds=0: analyze the most recent saved capture file instead.",
                Schema(("seconds", "Live capture length in seconds (default 0 = analyze latest capture file, cap 120)", false),
                       ("path", "Explicit .jsonl capture path to analyze instead", false)),
                false,
                a => TraceAnalyze(a)),

            new Tool(
                "classify_ip",
                "Classify a destination IP against session-verified ranges (Microsoft/Azure, Akamai, Gcore), " +
                "return the same block-warning text the app shows before blocking, AND report whether the IP " +
                "is currently on AutoScope's explicit blocked list (rule count, since when) — the part the " +
                "range classifier alone cannot see.",
                Schema(("ip", "IPv4 address to classify", true)),
                false,
                a => ClassifyIp(a)),

            new Tool(
                "get_transmissions",
                "Recent recorded TLS transmissions (the Transmissions tab's archive): per conversation — process, " +
                "pid, destination, SNI hostname, RDAP provider, wire and decrypted byte counts, status " +
                "(decrypted / encrypted-no-keys), SHA-256 and whether full bodies are on disk. METADATA ONLY: " +
                "bodies contain credentials and are never returned over the bridge; read them in the app.",
                Schema(("max", "Maximum rows to return (default 50, cap 200)", false),
                       ("pid", "Only rows for this process ID", false),
                       ("contains", "Only rows whose process/SNI/IP/provider/status contains this text", false),
                       ("minutes", "Look this many minutes back (default 1440 = 24h)", false)),
                false,
                a => GetTransmissions(a)),

            new Tool(
                "list_blocks",
                "Inventory of every AutoScope firewall block (the Blocks tab's data): per target — kind, " +
                "owner class, enabled/total rules, created time and recent hit counts from the live " +
                "Sysmon-joined feed. This is the authoritative 'is it blocked' source: classify_ip's range " +
                "answer alone cannot see explicit blocked-list entries.",
                Schema(("minutes", "Hit-count lookback window in minutes (default 60)", false)),
                false,
                a => ListBlocks(a)),

            new Tool(
                "list_recent_block_hits",
                "Processes recently caught hitting AutoScope firewall blocks, LIVE: Sysmon EID 3 connect " +
                "attempts joined against the blocked-target inventory — process, pid, blocked destination, " +
                "first/last seen, attempt count. Windows Firewall blocks silently (connect fails with " +
                "access-denied, nothing is logged by default), so this join — not pfirewall.log — is the " +
                "real-time 'who is being blocked' feed, and the fastest way to explain a " +
                "'This site can't be reached' error.",
                Schema(("minutes", "Look-back window (default 60, cap 1440)", false),
                       ("contains", "Only rows whose process or destination contains this text (case-insensitive)", false),
                       ("max", "Maximum aggregated rows (default 50, cap 200)", false)),
                false,
                a => ListRecentBlockHits(a)),

            new Tool(
                "check_host",
                "'Why can't I reach this site?' in one call: resolve a hostname, then per address — range " +
                "classification, whether it is on AutoScope's blocked list (with rule count and since " +
                "when), and recent blocked-connect attempts against it — ending in a plain-English verdict. " +
                "Accounts for DNS rotation: blocks are per-IP, so a blocked front-end can make a site fail " +
                "intermittently while other Google/Microsoft/CDN pages still work.",
                Schema(("host", "Hostname to check (e.g. accounts.google.com)", true),
                       ("minutes", "Recent-hit lookback (default 120)", false)),
                false,
                a => CheckHost(a)),

            new Tool(
                "diagnose_site",
                "Run the Site Doctor pipeline for one hostname — the 'why is this site slow / broken / failing " +
                "to sign in' question: passive fingerprint from the recorded-transmissions archive, a " +
                "dependency-block pass (were the page's other hosts — captcha, assets, APIs — silently blocked " +
                "during this browser's recorded visits? blocked connects carry no hostname, so only the " +
                "block-hit join can see them), then a capped live probe run (~10-25 quick operations, every one " +
                "listed in the result) — DNS rotation sampling, per-edge TCP plus two TLS hello shapes, " +
                "control-host comparison — and the plain-English verdict with evidence. Read-only; nothing is " +
                "blocked, killed or changed. Takes roughly 30 seconds.",
                Schema(("host", "Hostname to diagnose (e.g. chat.z.ai)", true),
                       ("minutes", "Archive lookback window in minutes (default 1440)", false)),
                false,
                a => DiagnoseSite(a)),

            // ── mutating: only present when the session allows, each call confirmed ──

            new Tool(
                "block_ip",
                "Create outbound TCP+UDP firewall block rules for a remote IP (the same 2-rule scheme " +
                "and provenance notes as the app's Process Monitor). Asks the user in AutoScope for every call.",
                Schema(("ip", "Remote IP to block", true),
                       ("reason", "Why — stored in the rule's provenance description", false),
                       ("dry_run", "true = validate the IP and preview without asking the user or changing anything", false)),
                true,
                a => BlockIp(a).GetAwaiter().GetResult(),
                a => $"Create outbound firewall BLOCK rules for {a["ip"]}?\n\n{IpClassification.WarningText(a["ip"]?.GetValue<string>())}" +
                     ReasonSuffix(a)),

            new Tool(
                "unblock_ip",
                "Remove firewall block rules previously created for a remote IP. Asks the user for every call.",
                Schema(("ip", "Remote IP to unblock", true),
                       ("dry_run", "true = report which rules would be removed without asking or removing", false)),
                true,
                a =>
                {
                    string ip = a["ip"]?.GetValue<string>();
                    if (string.Equals(a["dry_run"]?.GetValue<string>(), "true", StringComparison.OrdinalIgnoreCase))
                    {
                        var inv = AutoScope.Services.Fw.Service.GetBlockedInventoryAsync().GetAwaiter().GetResult();
                        var t = inv.FirstOrDefault(x => string.Equals(x.Ip, ip, StringComparison.OrdinalIgnoreCase));
                        return t == null
                            ? $"dry run — no block rules exist for {ip}; nothing would be removed."
                            : $"dry run — would remove {t.EnabledRules} of {t.Rules} rule(s) for {ip}" +
                              $"; no rules changed, no confirmation asked.";
                    }
                    int n = AutoScope.Services.Fw.Service.RemoveBlockRulesForIpAsync(ip)
                                   .GetAwaiter().GetResult();
                    return $"Removed {n} rule(s).";
                },
                a => $"Remove firewall block rules for {a["ip"]}?"),

            new Tool(
                "kill_process",
                "Forcefully terminate a process by PID. The confirmation dialog shows the LIVE process " +
                "name at the moment of the ask (PID-reuse guard). Asks the user for every call.",
                Schema(("pid", "Process ID to terminate", true),
                       ("reason", "Why", false),
                       ("expect_name", "Process name you saw when you looked this PID up — the kill refuses if the PID now belongs to a different process (PID-reuse guard)", false),
                       ("dry_run", "true = report the live process without asking or killing", false)),
                true,
                a => KillProcess(a),
                a => DescribeLiveProcess(a["pid"]?.GetValue<int>() ?? 0) + ReasonSuffix(a)),

            new Tool(
                "disable_task",
                "Disable a scheduled task (reversible: schtasks /Change /TN <path> /ENABLE). " +
                "Asks the user for every call.",
                Schema(("task_path", "Scheduled task path", true),
                       ("reason", "Why", false),
                       ("dry_run", "true = report the task's current state without asking or changing it", false)),
                true,
                a => DisableTask(a),
                a => $"Disable scheduled task '{a["task_path"]}'?" + ReasonSuffix(a)),
        };

        public static string[] Names(bool includeMutating) =>
            Tools.Where(t => includeMutating || !t.Mutating).Select(t => t.Name).ToArray();

        public static Tool Find(string name, bool includeMutating) =>
            Tools.FirstOrDefault(t => t.Name == name && (includeMutating || !t.Mutating));

        public static JsonArray Descriptors(bool includeMutating)
        {
            var arr = new JsonArray();
            foreach (var t in Tools.Where(t => includeMutating || !t.Mutating))
                arr.Add(new JsonObject
                {
                    ["name"] = t.Name,
                    ["description"] = t.Description,
                    ["inputSchema"] = t.Schema.DeepClone(),
                });
            return arr;
        }

        // ── read tool handlers ────────────────────────────────────────────

        // Last snapshot's live (pid → name, start time) pairs, so the next
        // snapshot can flag a PID whose name changed instead of silently
        // attaching the new holder's name — the PID-reuse trap.
        private static readonly object _lastSeenLock = new();
        private static Dictionary<int, (string Name, DateTime? StartedUtc)> _lastSeen = new();

        public static JsonObject BuildMonitorSnapshot()
        {
            // Kernel table FIRST, name snapshot second — the join must never
            // name a PID from data older than the connection table, or a PID
            // reused in between gets the previous owner's name attached.
            // GetExtendedTcpTable returns the whole table at one kernel
            // instant: no child process, no parse, microseconds of skew.
            var connections = TcpConnectionTable.GetEstablished();

            var procs = new Dictionary<int, (string Name, DateTime? StartedUtc)>();
            try
            {
                // CreationDate rides along because a bare PID is not an
                // identity — (pid, start time) is, the same rule the PID
                // Inquiry enforces against PID recycling.
                using var s = new ManagementObjectSearcher(
                    "SELECT ProcessId, Name, CreationDate FROM Win32_Process");
                foreach (ManagementObject o in s.Get())
                {
                    DateTime? started = null;
                    try
                    {
                        if (o["CreationDate"] is string dmtf && dmtf.Length > 0)
                            started = ManagementDateTimeConverter.ToDateTime(dmtf).ToUniversalTime();
                    }
                    catch { /* some system rows have no readable date — the name still joins */ }
                    procs[Convert.ToInt32(o["ProcessId"])] = (o["Name"]?.ToString() ?? "?", started);
                }
            }
            catch { /* WMI failed — rows carry PID only */ }

            var seenNow = new Dictionary<int, (string, DateTime?)>();
            var rows = new JsonArray();
            foreach (var c in connections)
            {
                string name; DateTime? started; string attribution;
                if (procs.TryGetValue(c.Pid, out var live))
                {
                    name = live.Name; started = live.StartedUtc; attribution = "live";
                    seenNow[c.Pid] = (live.Name, live.StartedUtc);
                }
                else
                {
                    // The owner exited between the two snapshots. Never
                    // attach a possibly-reused name: recover the identity
                    // Sysmon recorded at create time, else say it exited.
                    string recovered = TryRecoverNameFromSysmon(c.Pid);
                    if (recovered != null)
                    {
                        name = recovered; attribution = "recovered-from-sysmon";
                    }
                    else
                    {
                        name = "(exited during snapshot)"; attribution = "exited";
                    }
                    started = null;
                }

                var row = new JsonObject
                {
                    ["local"] = c.LocalEndPoint,
                    ["remote"] = c.RemoteEndPoint,
                    ["pid"] = c.Pid,
                    ["process"] = name,
                    ["classification"] = TraceText.Classify(c.RemoteIp),
                    ["attribution"] = attribution,
                };
                if (started != null)
                    row["process_started_utc"] = started.Value.ToString("yyyy-MM-dd HH:mm:ss");

                lock (_lastSeenLock)
                {
                    if (_lastSeen.TryGetValue(c.Pid, out var prev) &&
                        !string.Equals(prev.Name, name, StringComparison.OrdinalIgnoreCase))
                        row["pid_reused_since_last_snapshot"] = true;
                }

                if (name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
                {
                    var id = SvchostIdentityService.Resolve(c.Pid);
                    row["svchost"] = new JsonObject
                    {
                        ["services"] = id.ServicesCsv,
                        ["k"] = id.Group,
                        ["s"] = id.DeclaredService,
                        ["cmdline_visible"] = id.CommandLineVisible,
                        ["mismatch"] = id.Mismatch,
                    };
                }
                rows.Add(row);
            }
            lock (_lastSeenLock) { _lastSeen = seenNow; }
            return new JsonObject { ["type"] = "monitor_snapshot", ["rows"] = rows, ["row_count"] = rows.Count };
        }

        /// <summary>
        /// The image name Sysmon recorded when this PID was created, from the
        /// most recent matching create event in the last hour. The event
        /// carries the image itself, so PID reuse cannot misattribute — this
        /// is ground truth, not a lookup against the live process table.
        /// Null when Sysmon is absent, unreadable (non-elevated session), or
        /// has no recent event for the PID. Only consulted for rows whose
        /// owner already exited.
        /// </summary>
        private static string TryRecoverNameFromSysmon(int pid)
        {
            try
            {
                var query = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName,
                    $"*[System[EventID=1 and TimeCreated[timediff(@SystemTime) <= 3600000]] " +
                    $"and EventData[Data[@Name='ProcessId']='{pid}']]");
                string best = null;
                DateTime bestTime = DateTime.MinValue;
                using var reader = new EventLogReader(query);
                for (var ev = reader.ReadEvent(); ev != null; ev = reader.ReadEvent())
                using (ev)
                {
                    if (ev.TimeCreated is { } t && t > bestTime)
                    {
                        // EID 1 property layout: 0 RuleName, 1 UtcTime,
                        // 2 ProcessGuid, 3 ProcessId, 4 Image, …
                        var props = ev.Properties;
                        if (props.Count > 4 && props[4].Value is string img && img.Length > 0)
                        {
                            bestTime = t;
                            best = Path.GetFileName(img);
                        }
                    }
                }
                return best;
            }
            catch { return null; } // not installed / unreadable non-elevated — degrade, never guess
        }


        private static string GetSvchostIdentity(JsonObject a)
        {
            int pid = a["pid"]?.GetValue<int>() ?? 0;
            string name;
            try
            {
                using var proc = Process.GetProcessById(pid);
                name = proc.ProcessName;
            }
            catch { return $"PID {pid} is not running."; }
            if (!name.Equals("svchost", StringComparison.OrdinalIgnoreCase) &&
                !name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
                return $"PID {pid} is '{name}', not svchost.exe.";

            var id = SvchostIdentityService.Resolve(pid);
            return ToJson(new JsonObject
            {
                ["pid"] = pid,
                ["scm_services"] = id.ServicesCsv.Length > 0 ? id.ServicesCsv : "(none — strongest masquerade red flag)",
                ["services_detail"] = id.ServicesDetail,
                ["k_group"] = id.Group,
                ["s_declared"] = id.DeclaredService,
                ["command_line_visible"] = id.CommandLineVisible,
                ["mismatch"] = id.Mismatch,
                ["readable_line_without_k"] = id.NoK,
                ["verdict"] = id.Mismatch || id.NoK
                    ? "SUSPICIOUS — self-declared identity contradicts the SCM"
                    : id.CommandLineVisible ? "corroborated" : "no command line readable — rerun the app elevated to corroborate",
            });
        }

        private static string RunPidInquiry(JsonObject a)
        {
            int pid = a["pid"]?.GetValue<int>() ?? 0;
            var report = ProcessProvenanceService.Collect(pid);
            return TraceText.BuildReportText(report);
        }

        private static string TailSysmon(JsonObject a)
        {
            int minutes = a["minutes"]?.GetValue<int>() ?? 30;
            minutes = Math.Clamp(minutes, 1, 24 * 60);
            int? eid = a["eid"] is JsonNode e ? e.GetValue<int>() : null;
            string contains = a["contains"]?.GetValue<string>();
            int max = Math.Clamp(a["max"]?.GetValue<int>() ?? 50, 1, 500);
            bool archive = a["archive"] is JsonNode ab && ab.GetValue<bool>();

            if (archive)
            {
                var events = SysmonArchiveService.Search(eid, contains, DateTime.UtcNow.AddMinutes(-minutes), max);
                if (events.Count == 0)
                    return $"No matching events in the Sysmon archive (last {minutes} min). " +
                           "The archive fills at every elevated app start (backfill) and while the app runs.";
                var sb2 = new StringBuilder();
                foreach (var ev in events)
                {
                    string stamp = ev.TsUtc.ToLocalTime().ToString("HH:mm:ss");
                    string pid = ev.Data.GetValueOrDefault("ProcessId", "");
                    string img = ev.Data.GetValueOrDefault("Image", "");
                    string cmd = ev.Data.GetValueOrDefault("CommandLine", "");
                    string line = $"{stamp}  EID {ev.Eid}  PID {pid}  {img}" +
                                  (cmd.Length > 0 ? $" | {cmd}" : "");
                    if (line.Length > 400) line = line[..400] + "…";
                    sb2.AppendLine(line);
                }
                return sb2.ToString();
            }

            try
            {
                var since = DateTime.UtcNow.AddMinutes(-minutes);
                var query = new EventLogQuery("Microsoft-Windows-Sysmon/Operational",
                    PathType.LogName, "*[System[TimeCreated[@SystemTime >= '" + since.ToString("yyyy-MM-ddTHH:mm:ss.000Z") + "']]]");
                using var reader = new EventLogReader(query);
                var sb = new StringBuilder();
                int shown = 0, scanned = 0;
                for (var ev = reader.ReadEvent(); ev != null && shown < max; ev = reader.ReadEvent())
                using (ev)
                {
                    scanned++;
                    if (eid.HasValue && ev.Id != eid.Value) continue;
                    string desc;
                    try { desc = ev.FormatDescription() ?? ""; } catch { desc = ""; }
                    if (!string.IsNullOrEmpty(contains) &&
                        !desc.Contains(contains, StringComparison.OrdinalIgnoreCase)) continue;
                    int pid = -1;
                    try { pid = Convert.ToInt32(ev.Properties[3]?.Value); } catch { }
                    string stamp = ev.TimeCreated?.ToLocalTime().ToString("HH:mm:ss") ?? "??";
                    string line = stamp + $"  EID {ev.Id}  PID {pid}  " +
                                  desc.Replace("\r\n", " | ").Replace("\n", " | ").TrimEnd();
                    if (line.Length > 400) line = line[..400] + "…";
                    sb.AppendLine(line);
                    shown++;
                }
                if (shown == 0)
                    return $"No matching Sysmon events in the last {minutes} min (scanned {scanned}). " +
                           "Zero scanned usually means the log is empty or Sysmon config dropped this event class.";
                return sb.ToString();
            }
            catch (UnauthorizedAccessException)
            {
                return "The Sysmon log is not readable from this session — the running AutoScope instance " +
                       "is not elevated. Restart AutoScope as Administrator and start a new AI session.";
            }
            catch (Exception ex)
            {
                return "Sysmon log read failed: " + ex.Message;
            }
        }

        private static string TraceAnalyze(JsonObject a)
        {
            int seconds = a["seconds"]?.GetValue<int>() ?? 0;
            string path = a["path"]?.GetValue<string>();

            try
            {
                if (seconds <= 0)
                {
                    string file = path;
                    if (string.IsNullOrEmpty(file))
                    {
                        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                               "AutoScope", "captures");
                        file = Directory.Exists(dir)
                            ? Directory.GetFiles(dir, "*.jsonl").OrderByDescending(File.GetLastWriteTime).FirstOrDefault()
                            : null;
                    }
                    if (file == null || !File.Exists(file))
                        return "No capture file to analyze (none passed, none in the captures folder). " +
                               "Call again with seconds>0 to capture live.";
                    var result = TraceAnalyzer.Analyze(new[] { file });
                    return $"analyzed: {Path.GetFileName(file)}\n\n{result.Report}";
                }

                seconds = Math.Min(seconds, 120);
                string temp = Path.Combine(Path.GetTempPath(), $"agent-trace-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl");
                using (var engine = new CaptureEngine(new CaptureOptions
                {
                    OutFile = temp,
                    PollMs = 1000,
                    Duration = TimeSpan.FromSeconds(seconds),
                }))
                {
                    var done = new ManualResetEventSlim(false);
                    engine.Completed += _ => done.Set();
                    engine.Start();
                    done.Wait(TimeSpan.FromSeconds(seconds + 10));
                }
                var analysis = TraceAnalyzer.Analyze(new[] { temp });
                try { File.Delete(temp); } catch { }
                return $"live capture {seconds}s (exit {analysis.Flags} flag(s)):\n\n{analysis.Report}";
            }
            catch (InvalidOperationException ex)
            {
                return "Capture could not start (another capture is likely running in the app): " + ex.Message;
            }
            catch (Exception ex)
            {
                return "trace_analyze failed: " + ex.Message;
            }
        }

        private static string ClassifyIp(JsonObject a)
        {
            string ip = a["ip"]?.GetValue<string>() ?? "";
            EnsureFeedStarted();
            var blocked = BlockHitFeedService.Instance.BlockedIp(ip);
            var o = new JsonObject
            {
                ["ip"] = ip,
                ["classification"] = IpClassification.Classify(ip),
                ["microsoft_infra"] = IpClassification.IsMicrosoftInfra(ip),
                ["block_warning"] = IpClassification.WarningText(ip),
                ["blocked"] = blocked != null,
            };
            if (blocked != null)
            {
                o["blocked_rules"] = $"{blocked.EnabledRules}/{blocked.Rules} enabled";
                o["blocked_class"] = blocked.Class;
                o["blocked_since"] = blocked.Created?.ToString("yyyy-MM-dd HH:mm") ?? "unknown (legacy rule)";
                o["note"] = "On AutoScope's blocked list — the AS-BLOCK firewall rules drop connects " +
                            "silently at the kernel (instant access-denied). See list_recent_block_hits " +
                            "for which processes are hitting it and check_host for the site-level picture.";
            }
            return ToJson(o);
        }

        /// <summary>Start() is idempotent — every blocked-list reader ensures the feed lives.</summary>
        private static void EnsureFeedStarted()
        {
            try { BlockHitFeedService.Instance.Start(); } catch { }
        }

        private static string ListBlocks(JsonObject a)
        {
            int minutes = Math.Clamp(a["minutes"]?.GetValue<int>() ?? 60, 1, 24 * 60);
            EnsureFeedStarted();
            var inv = AutoScope.Services.Fw.Service.GetBlockedInventoryAsync().GetAwaiter().GetResult();
            var feedHits = BlockHitFeedService.Instance.FeedHitsByIp(minutes);

            var arr = new JsonArray();
            foreach (var t in inv)
            {
                int h = t.Kind == "ip" && feedHits.TryGetValue(t.Ip, out int c) ? c : 0;
                arr.Add(new JsonObject
                {
                    ["target"] = t.Target,
                    ["kind"] = t.Kind,
                    ["class"] = t.Class,
                    ["rules"] = $"{t.EnabledRules}/{t.Rules} enabled",
                    ["created"] = t.Created?.ToString("yyyy-MM-dd HH:mm") ?? "legacy",
                    [$"hits_{minutes}m"] = h,
                    ["note"] = string.IsNullOrEmpty(t.Description) ? "" :
                        (t.Description.Length > 160 ? t.Description[..160] + "…" : t.Description),
                });
            }
            var feed = BlockHitFeedService.Instance;
            return ToJson(new JsonObject
            {
                ["type"] = "blocked_inventory",
                ["targets"] = arr.Count,
                ["rows"] = arr,
                ["feed_inventory_refreshed_utc"] = feed.LastRefreshUtc == default ? null : feed.LastRefreshUtc.ToString("yyyy-MM-dd HH:mm:ss"),
            });
        }

        private static string ListRecentBlockHits(JsonObject a)
        {
            int minutes = Math.Clamp(a["minutes"]?.GetValue<int>() ?? 60, 1, 1440);
            int max = Math.Clamp(a["max"]?.GetValue<int>() ?? 50, 1, 200);
            string contains = a["contains"]?.GetValue<string>();
            EnsureFeedStarted();
            var feed = BlockHitFeedService.Instance;

            var aggs = feed.Aggregates(minutes, 200);
            if (!string.IsNullOrEmpty(contains))
                aggs = aggs.Where(x =>
                    (x.Process?.IndexOf(contains, StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (x.Image?.IndexOf(contains, StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (x.DestIp?.IndexOf(contains, StringComparison.OrdinalIgnoreCase) >= 0)).ToList();

            if (aggs.Count == 0)
                return $"No blocked-connect hits in the last {minutes} min. The feed joins live Sysmon EID 3 " +
                       "attempts against the blocked inventory — it needs Sysmon installed and sees attempts " +
                       "from service start onward (history persists across restarts). " +
                       (feed.WatcherError != null ? $"Feed note: {feed.WatcherError}" :
                        "If you are chasing a 'site can't be reached' error, also try check_host.");

            var arr = new JsonArray();
            foreach (var x in aggs.Take(max))
            {
                arr.Add(new JsonObject
                {
                    ["ts_last_utc"] = x.LastUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                    ["process"] = x.Process,
                    ["pid"] = x.Pid,
                    ["image"] = x.Image,
                    ["destination"] = $"{x.DestIp}:{x.DestPort}",
                    ["blocked_kind"] = x.MatchKind,   // ip = destination IP block, app = process block
                    ["attempts"] = x.Count,
                    ["first_utc"] = x.FirstUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                });
            }
            return ToJson(new JsonObject
            {
                ["type"] = "block_hits",
                ["window_minutes"] = minutes,
                ["rows"] = arr,
                ["row_count"] = arr.Count,
                ["inventory_refreshed_utc"] = feed.LastRefreshUtc == default ? null : feed.LastRefreshUtc.ToString("yyyy-MM-dd HH:mm:ss"),
            });
        }

        /// <summary>
        /// Site-level blocked triage: resolve → per-IP verdict → plain English.
        /// The error users actually see ("This site can't be reached") is Chrome's
        /// rendering of an instantly-denied connect — so the verdict keys off
        /// blocked-list membership, not range classification.
        /// </summary>
        private static string CheckHost(JsonObject a)
        {
            string host = a["host"]?.GetValue<string>() ?? "";
            int minutes = Math.Clamp(a["minutes"]?.GetValue<int>() ?? 120, 1, 1440);
            if (string.IsNullOrWhiteSpace(host))
                return "check_host: 'host' is required.";
            host = host.Trim();
            try { if (host.Contains("://")) host = new Uri(host).Host; }   // tolerate pasted URLs
            catch { /* not URL-shaped — treat as a bare hostname */ }

            EnsureFeedStarted();
            var feed = BlockHitFeedService.Instance;

            System.Net.IPAddress[] addrs;
            try { addrs = System.Net.Dns.GetHostAddresses(host); }
            catch (Exception ex)
            {
                return ToJson(new JsonObject
                {
                    ["host"] = host,
                    ["verdict"] = $"DNS resolution failed ({ex.Message}) — the hostname itself is unreachable " +
                                  "before any firewall decision. Not an AutoScope block.",
                });
            }

            var recent = feed.Recent(minutes, 2000)
                .Where(h => h.MatchKind == "ip")
                .GroupBy(h => h.DestIp)
                .ToDictionary(g => g.Key, g => g.Count());

            var rows = new JsonArray();
            var blockedAddrs = new List<string>();
            foreach (var addr in addrs)
            {
                string ip = addr.ToString();
                var b = feed.BlockedIp(ip);
                recent.TryGetValue(ip, out int hits);
                if (b != null) blockedAddrs.Add(ip);
                rows.Add(new JsonObject
                {
                    ["ip"] = ip,
                    ["classification"] = IpClassification.Classify(ip),
                    ["blocked"] = b != null,
                    ["blocked_since"] = b?.Created?.ToString("yyyy-MM-dd HH:mm"),
                    [$"blocked_attempts_{minutes}m"] = hits,
                });
            }

            string verdict;
            if (blockedAddrs.Count > 0)
                verdict = $"{host} resolves to {addrs.Length} address(es); {blockedAddrs.Count} are on " +
                          "AutoScope's blocked list. Connects to those fail INSTANTLY with access-denied " +
                          "(kernel-level firewall block), which browsers show as 'This site can't be reached'. " +
                          "Because blocks are per-IP and this host rotates addresses, the site may work from " +
                          "other networks or fail intermittently. Unblock via unblock_ip or the Blocks tab.";
            else if (rows.Any(r => ((JsonNode)r!["blocked_attempts_" + minutes + "m"]).GetValue<int>() > 0))
                verdict = "No currently-resolved address is blocked, but blocked-connect attempts were seen " +
                          "recently — DNS rotation likely served a blocked address earlier. List the feed with " +
                          "list_recent_block_hits and intersect with this host's address pool.";
            else
                verdict = $"No AutoScope block matches any of {host}'s {addrs.Length} resolved address(es) " +
                          $"and no blocked-connect attempts were seen in the last {minutes} min — if the site " +
                          "still fails, the cause is upstream (network, DNS filtering on the router, or the " +
                          "remote end), not a local block rule.";

            return ToJson(new JsonObject
            {
                ["type"] = "check_host",
                ["host"] = host,
                ["rows"] = rows,
                ["verdict"] = verdict,
            });
        }

        /// <summary>Read-only archive query — metadata only by design; the
        /// decrypted bodies stay on disk for the user to view in the tab.</summary>
        private static string GetTransmissions(JsonObject a)
        {
            int max = Math.Clamp(a["max"]?.GetValue<int>() ?? 50, 1, 200);
            int minutes = Math.Clamp(a["minutes"]?.GetValue<int>() ?? 1440, 1, 60 * 24 * 30);
            int? pid = a["pid"] is JsonNode p ? p.GetValue<int>() : null;
            string contains = a["contains"]?.GetValue<string>();

            var rows = TransmissionsArchiveService.Read(max, pid, contains, DateTime.UtcNow.AddMinutes(-minutes));
            if (rows.Count == 0)
                return $"No archived transmissions matching the filter (last {minutes} min). " +
                       "Rows appear when the Transmissions tab has watched a TLS flow that decrypted " +
                       "or pushed more than 10 KB upstream.";

            var arr = new JsonArray();
            foreach (var r in rows)
            {
                arr.Add(new JsonObject
                {
                    ["ts_utc"] = r.TsUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                    ["pid"] = r.Pid,
                    ["process"] = r.ProcessDisplay,
                    ["destination"] = r.ServerEndpoint,
                    ["sni"] = r.Sni,
                    ["provider"] = r.ProviderAndCountry,
                    ["tls"] = r.TlsVersion,
                    ["status"] = r.Status,
                    ["client_bytes"] = r.ClientBytes,
                    ["server_bytes"] = r.ServerBytes,
                    ["client_app_bytes"] = r.ClientAppBytes,
                    ["server_app_bytes"] = r.ServerAppBytes,
                    ["big_upload"] = r.BigUpload,
                    ["has_content_on_disk"] = r.HasContent,
                    ["sha256"] = r.Sha256,
                    ["message_count"] = r.MessageCount,
                    ["content_kinds"] = r.ContentKinds,
                });
            }
            return ToJson(new JsonObject { ["type"] = "transmissions", ["rows"] = arr, ["row_count"] = arr.Count });
        }

        /// <summary>
        /// diagnose_site: the tab's whole pipeline over the bridge — same
        /// engines, same caps, same honest verdicts. The bridge handler runs
        /// on a background thread; DNS sampling is tightened to 3s so the
        /// whole call lands around 30 seconds.
        /// </summary>
        private static string DiagnoseSite(JsonObject a)
        {
            string host = a["host"]?.GetValue<string>()?.Trim().TrimEnd('.');
            if (string.IsNullOrEmpty(host)) return "Missing 'host' — the hostname to diagnose.";
            int minutes = Math.Clamp(a["minutes"]?.GetValue<int>() ?? 1440, 1, 60 * 24 * 30);

            var rows = TransmissionsArchiveService.Read(4000, null, null, DateTime.UtcNow.AddMinutes(-minutes))
                .Select(r => new AutoCommand.Engines.Core.TrafficRow(r.TsUtc, r.Pid, r.Image, r.ProcessDisplay, r.RemoteIp, r.RemotePort, r.Sni, r.ClientBytes, r.ServerBytes)).ToList();
            var siteRows = rows.Where(r => string.Equals(r.Sni, host, StringComparison.OrdinalIgnoreCase)).ToList();
            var all = SiteFingerprintService.AllFingerprints(rows);
            var fingerprint = SiteFingerprintService.Fingerprint(
                siteRows, SiteFingerprintService.BaselineEdgeCount(all));

            var controls = SiteFingerprintService.TopHosts(rows, 10)
                .Where(h => !string.Equals(h, host, StringComparison.OrdinalIgnoreCase))
                .Take(SiteProbeService.MaxControlHosts)
                .ToList();
            if (controls.Count == 0) controls = new List<string> { "example.com" };

            SiteProbeReport report;
            try
            {
                report = SiteProbeService.Shared.RunAsync(
                    host,
                    fingerprint.Edges.Select(e => e.Ip),
                    controls,
                    progress: null,
                    CancellationToken.None,
                    dnsSampleInterval: TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
            }
            catch (ArgumentException ex) { return ex.Message; }

            // Dependency pass — same engine as the tab: were any of the
            // page's other hosts silently blocked during this browser's
            // recorded visits? Blocked connects carry no hostname, so only
            // this join can see them. Degrades to null, never throws.
            AutoCommand.Engines.Diagnosis.Report dep = null;
            try
            {
                BlockHitFeedService.Instance.Start();
                dep = DependencyBlockService.AnalyzeLiveAsync(host, minutes, null, System.Threading.CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            catch { dep = null; }

            var verdict = SiteVerdict.Decide(fingerprint, report, dep);

            var edgeArr = new JsonArray();
            foreach (var e in report.Edges)
                edgeArr.Add(new JsonObject
                {
                    ["ip"] = e.Ip,
                    ["tcp_ms"] = e.TcpConnectMs,
                    ["tcp_error"] = e.TcpError,
                    ["tls_default_ms"] = e.TlsDefaultMs,
                    ["tls_default_version"] = e.TlsDefaultVersion,
                    ["tls_default_error"] = e.TlsDefaultError,
                    ["tls_plain_ms"] = e.TlsPlainMs,
                    ["tls_plain_version"] = e.TlsPlainVersion,
                    ["tls_plain_error"] = e.TlsPlainError,
                });

            var controlArr = new JsonArray();
            foreach (var c in report.Controls)
                controlArr.Add(new JsonObject
                {
                    ["host"] = c.Host,
                    ["tcp_ms"] = c.TcpConnectMs,
                    ["tls_ms"] = c.TlsMs,
                    ["error"] = c.Error,
                });

            var evidenceArr = new JsonArray();
            foreach (var line in verdict.Evidence) evidenceArr.Add(line);

            var signalArr = new JsonArray();
            foreach (var s in fingerprint.Signals) signalArr.Add(s);

            var opsArr = new JsonArray();
            foreach (var op in report.Operations.Take(60))
                opsArr.Add($"[{op.Kind}] {op.Detail}");

            var ipArr = new JsonArray();
            foreach (var ip in report.Dns.DistinctIps) ipArr.Add(ip);

            var root = new JsonObject
            {
                ["type"] = "site_diagnosis",
                ["host"] = host,
                ["verdict"] = new JsonObject
                {
                    ["kind"] = verdict.Kind.ToString(),
                    ["headline"] = verdict.Headline,
                    ["next_step"] = verdict.NextStep,
                    ["evidence"] = evidenceArr,
                },
                ["fingerprint"] = new JsonObject
                {
                    ["conversations"] = fingerprint.Conversations,
                    ["distinct_edges"] = fingerprint.Edges.Count,
                    ["burst_windows"] = fingerprint.BurstWindows,
                    ["window_local"] = fingerprint.SpanDisplay,
                    ["signals"] = signalArr,
                },
                ["probes"] = new JsonObject
                {
                    ["dns_samples"] = report.Dns.Samples.Count,
                    ["dns_distinct_ips"] = ipArr,
                    ["dns_rotated"] = report.Dns.AnswerRotated,
                    ["edges"] = edgeArr,
                    ["controls"] = controlArr,
                },
                ["operations"] = opsArr,
            };

            if (dep != null && (dep.InWindow.Count > 0 || dep.Nearby.Count > 0 || dep.Rotations.Count > 0))
            {
                var depArr = new JsonArray();
                foreach (var h in dep.InWindow.Concat(dep.Nearby))
                {
                    var served = new JsonArray();
                    foreach (var sh in h.ServedHosts) served.Add(sh);
                    depArr.Add(new JsonObject
                    {
                        ["ip"] = h.Ip,
                        ["process"] = h.Process,
                        ["attempts"] = h.Attempts,
                        ["first_utc"] = h.FirstUtc,
                        ["last_utc"] = h.LastUtc,
                        ["in_visit_window"] = dep.InWindow.Contains(h),
                        ["served_hosts"] = served,
                        ["blocked_since"] = h.BlockedSince,
                        ["block_class"] = h.BlockClass,
                    });
                }
                var rotArr = new JsonArray();
                foreach (var f in dep.Rotations)
                    rotArr.Add(new JsonObject
                    {
                        ["host"] = f.Host,
                        ["blocked_addresses"] = f.BlockedAddresses,
                        ["total_addresses"] = f.TotalAddresses,
                    });
                root["dependency_blocks"] = new JsonObject
                {
                    ["hits"] = depArr,
                    ["rotation"] = rotArr,
                    ["visit_times_utc"] = dep.VisitTimesUtc.Count,
                };
            }

            return ToJson(root);
        }

        // ── mutating handlers (already user-confirmed when reached) ───────

        private static async Task<string> BlockIp(JsonObject a)
        {
            string ip = a["ip"]?.GetValue<string>();
            if (!System.Net.IPAddress.TryParse(ip, out _)) return $"'{ip}' is not a valid IP address.";
            string reason = a["reason"]?.GetValue<string>();
            if (string.Equals(a["dry_run"]?.GetValue<string>(), "true", StringComparison.OrdinalIgnoreCase))
                return $"dry run — would create outbound TCP+UDP block rules for {ip}" +
                       (string.IsNullOrEmpty(reason) ? "" : $" ({reason})") +
                       "; no rules changed, no confirmation asked. Call again without dry_run to do it.";
            string note = $"[agent request, user-confirmed {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC]" +
                          (string.IsNullOrEmpty(reason) ? "" : $" {reason}") + " · AutoScope AI access";
            var (created, updated) = await AutoScope.Services.Fw.Service.AddIpBlockAsync(ip, note);
            return created > 0
                ? $"Blocked {ip} — {created} outbound TCP/UDP rule(s) created, provenance written to the rule description."
                : $"Block for {ip} already existed — refreshed its provenance ({updated} rule(s)).";
        }

        private static string KillProcess(JsonObject a)
        {
            int pid = a["pid"]?.GetValue<int>() ?? 0;
            if (pid <= 4) return "Refusing to kill PID 0–4 (system).";
            if (string.Equals(a["dry_run"]?.GetValue<string>(), "true", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    using var probe = Process.GetProcessById(pid);
                    return $"dry run — PID {pid} is '{probe.ProcessName}'; nothing killed, no confirmation asked.";
                }
                catch (ArgumentException) { return $"dry run — PID {pid} already exited."; }
                catch (Exception ex) { return $"dry run — could not read PID {pid}: {ex.Message}"; }
            }
            string expectName = a["expect_name"]?.GetValue<string>();
            try
            {
                var proc = Process.GetProcessById(pid);
                string name = proc.ProcessName;
                // PID-reuse guard: the user confirmed a SPECIFIC process.
                // If the PID now belongs to a different image, refuse —
                // the agent must re-look and re-ask.
                if (!string.IsNullOrEmpty(expectName) &&
                    !string.Equals(name, expectName, StringComparison.OrdinalIgnoreCase))
                    return $"Refused: PID {pid} now belongs to '{name}', but confirmation was for " +
                           $"'{expectName}' (PID reuse). Look the PID up again and ask fresh.";
                proc.Kill();
                return $"Terminated PID {pid} ('{name}').";
            }
            catch (ArgumentException) { return $"PID {pid} already exited."; }
            catch (Exception ex) { return $"Kill failed: {ex.Message}"; }
        }

        private static string DisableTask(JsonObject a)
        {
            string path = a["task_path"]?.GetValue<string>();
            try
            {
                if (string.Equals(a["dry_run"]?.GetValue<string>(), "true", StringComparison.OrdinalIgnoreCase))
                    return $"dry run — would disable scheduled task '{path}'" +
                           " (reversible via schtasks /Change /TN … /ENABLE); nothing changed, no confirmation asked.";
                TaskSchedulerService.Instance.SetTaskEnabledAsync(path, false).GetAwaiter().GetResult();
                return $"Disabled scheduled task '{path}'. Re-enable with: schtasks /Change /TN \"{path}\" /ENABLE";
            }
            catch (Exception ex) { return $"Disable failed: {ex.Message}"; }
        }

        // ── schema / description helpers ──────────────────────────────────

        private static JsonObject Schema(params (string Name, string Desc, bool Required)[] props)
        {
            var properties = new JsonObject();
            var required = new JsonArray();
            foreach (var (name, desc, req) in props)
            {
                bool isInt = name is "pid" or "minutes" or "eid" or "max" or "seconds";
                bool isBool = name is "archive";
                properties[name] = new JsonObject
                {
                    ["type"] = isBool ? "boolean" : isInt ? "integer" : "string",
                    ["description"] = desc,
                };
                if (req) required.Add(name);
            }
            return new JsonObject
            {
                ["type"] = "object",
                ["properties"] = properties,
                ["required"] = required,
            };
        }

        private static string ReasonSuffix(JsonObject a)
        {
            string reason = a["reason"]?.GetValue<string>();
            return string.IsNullOrEmpty(reason) ? "" : $"\n\nStated reason: {reason}";
        }

        private static string DescribeLiveProcess(int pid)
        {
            try
            {
                var proc = Process.GetProcessById(pid);
                return $"Terminate PID {pid} — LIVE process '{proc.ProcessName}'" +
                       $" (started {proc.StartTime:yyyy-MM-dd HH:mm:ss})?";
            }
            catch { return $"Terminate PID {pid}? (process not found — it may have exited; the call will be a no-op)"; }
        }

        private static string ToJson(JsonObject o) => o.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    }
}
