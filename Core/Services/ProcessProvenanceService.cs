using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Xml.Linq;

namespace AutoScope.Services
{
    /// <summary>One hop in the ancestry chain, ordered child → root.</summary>
    public sealed class ChainLink
    {
        public int Pid;
        public string Name;
        public string ExePath;
        public string CommandLine;
        public string Owner;
        public DateTime? Created;

        /// <summary>
        /// False when this PID could not have been the real parent — Windows
        /// recycled it (the current owner started AFTER the child), or the
        /// process is already gone and only hints/events identify it.
        /// </summary>
        public bool Verified = true;

        /// <summary>Why the link is unverified / how it was observed.</summary>
        public string Note;
    }

    public sealed class EvidenceItem
    {
        public string Source;
        public string Detail;
    }

    /// <summary>
    /// Everything the PID inquiry could establish about one process: live
    /// identity, parent chain, spawn mechanism and corroborating records.
    /// </summary>
    public sealed class ProvenanceReport
    {
        public int Pid;
        public bool Alive;
        public string Name;
        public string ExePath;
        public string CommandLine;
        public string Owner;
        public string Session;
        public string Memory;
        public DateTime? Created;

        /// <summary>
        /// True when the live PID is NOT the process the caller asked about:
        /// the hinted identity disagrees with the live snapshot, so Windows
        /// recycled the PID and the subject has exited. Identity, chain and
        /// verdict then describe the exited subject; the unrelated current
        /// owner of the number is reported separately (CurrentOwner*).
        /// </summary>
        public bool Recycled;

        /// <summary>Name of the unrelated process that now owns the recycled PID.</summary>
        public string CurrentOwnerName;

        /// <summary>Start time of the unrelated process that now owns the recycled PID.</summary>
        public DateTime? CurrentOwnerCreated;

        /// <summary>One-line identity of the current PID owner, for report text.</summary>
        public string CurrentOwnerSummary;

        public string Verdict;
        public string VerdictDetail;

        public List<ChainLink> Chain = new();
        public List<EvidenceItem> Evidence = new();
        public List<string> Warnings = new();
        public TimeSpan Elapsed;
    }

    /// <summary>
    /// Answers "how was this PID spawned?" for any process — the machine
    /// forensics playbook behind the Process Monitor's PID inquiry:
    ///
    ///   1. Live WMI snapshot (identity, owner, command line, creation time)
    ///   2. Parent-chain walk with a PID-reuse guard: a parent only counts
    ///      when its creation time predates the child's. Windows recycles
    ///      PIDs aggressively; a naive PPID lookup blames an innocent process.
    ///      The same guard covers the TARGET itself: when the caller's hints
    ///      (capture-time name/image, the subject's start time, the last
    ///      sighting) disagree with the live snapshot, the PID was recycled —
    ///      the report describes the EXITED subject and never merges it with
    ///      the unrelated process that inherited the number.
    ///   3. Corroboration from recorded create-events: Sysmon EID 1 (ground
    ///      truth that survives process exit), Security 4688 as fallback
    ///   4. Interactive-shell evidence: PSReadLine history matches for the
    ///      typed command line
    ///   5. Autostart surface: Run keys / Startup folder / services hosted
    ///
    /// All I/O is synchronous and intended to run on a background thread —
    /// the whole collection takes a moment (several WMI roundtrips + event
    /// log queries) and must never block the UI.
    /// </summary>
    public static class ProcessProvenanceService
    {
        private const string SysmonLog = "Microsoft-Windows-Sysmon/Operational";

        private static readonly string[] InteractiveShells =
        {
            "powershell.exe", "pwsh.exe", "cmd.exe", "bash.exe", "wt.exe",
            "windowsterminal.exe", "conhost.exe", "openconsole.exe"
        };

        // Chain walk stops once one of these is on it — everything above
        // them is session/OS infrastructure that adds no spawn information.
        private static readonly HashSet<string> RootNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "explorer.exe", "services.exe", "wininit.exe", "smss.exe",
            "winlogon.exe", "lsass.exe", "csrss.exe"
        };

        public static ProvenanceReport Collect(int pid, string knownName = null,
                                                string knownImagePath = null,
                                                TaskLaunchInfo taskHint = null,
                                                DateTime? hintSeenUtc = null,
                                                DateTime? knownCreatedUtc = null)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var r = new ProvenanceReport
            {
                Pid = pid,
                Name = knownName ?? $"<PID {pid}>",
                ExePath = knownImagePath,
            };

            var target = QueryProcess(pid);

            // Target-PID reuse guard. The hints describe the process the
            // caller SAW (capture-time name/image, the subject's own start
            // time, the last traffic sighting); the live snapshot describes
            // whoever owns the PID NOW. When they disagree, Windows recycled
            // the PID in between: the subject has exited and the live process
            // is an unrelated bystander. Merging the two tenants is exactly
            // how a report ends up claiming bash.exe was launched by a
            // SYSTEM scheduled task.
            bool recycled = false;
            if (target != null)
            {
                bool createdMismatch =
                    knownCreatedUtc.HasValue && target.Created.HasValue &&
                    (target.Created.Value.ToUniversalTime() - knownCreatedUtc.Value.ToUniversalTime()).Duration()
                        > TimeSpan.FromSeconds(5);
                bool newerThanLastSighting =
                    hintSeenUtc.HasValue && target.Created.HasValue &&
                    target.Created.Value.ToUniversalTime() > hintSeenUtc.Value.ToUniversalTime();
                recycled = createdMismatch || newerThanLastSighting ||
                           !NamesMatch(knownName, target.Name) ||
                           !ImagesMatch(knownImagePath, target.ExePath);
            }

            if (target != null && !recycled)
            {
                r.Alive = true;
                r.Name = target.Name;
                r.ExePath ??= target.ExePath;
                r.CommandLine = target.CommandLine;
                r.Owner = target.Owner;
                r.Created = target.Created;
                r.Session = target.SessionId == 1
                    ? "1 (console)"
                    : target.SessionId.ToString();
                r.Memory = FormatBytes(target.WorkingSet);
            }
            else if (recycled)
            {
                r.Recycled = true;
                r.Alive = false;   // the SUBJECT is dead — only its PID lives on

                r.CurrentOwnerName = target.Name;
                r.CurrentOwnerCreated = target.Created;
                string ownerCmd = target.CommandLine;
                if (!string.IsNullOrEmpty(ownerCmd) && ownerCmd.Length > 240)
                    ownerCmd = ownerCmd.Substring(0, 240) + "…";
                r.CurrentOwnerSummary =
                    $"{target.Name} · image {target.ExePath ?? "?"} · started {target.Created:yyyy-MM-dd HH:mm:ss} · " +
                    $"owner {target.Owner ?? "?"} · session {target.SessionId}";
                r.Warnings.Add(
                    $"PID {pid} was recycled: the process this inquiry is about ({r.Name}) has exited. " +
                    $"The PID now belongs to {target.Name} (started {target.Created:yyyy-MM-dd HH:mm:ss}) — an " +
                    "unrelated process. Identity, chain and verdict describe the exited subject; the current " +
                    "PID owner is listed separately in the evidence.");
                r.Evidence.Add(new EvidenceItem
                {
                    Source = "Current PID owner (unrelated)",
                    Detail = $"PID {pid} now belongs to {target.Name}, started " +
                             $"{target.Created:yyyy-MM-dd HH:mm:ss}, owner {target.Owner ?? "?"}.\r\n" +
                             $"      image: {target.ExePath ?? "?"}\r\n" +
                             $"      command line: {ownerCmd ?? "(unreadable)"}"
                });

                // Everything downstream must treat the subject as a dead
                // process: a null target keeps the chain walk, the hosted-
                // service scan and the Sysmon record preference from reading
                // the bystander as the subject.
                target = null;
            }
            else
            {
                r.Warnings.Add("Process is not running — live snapshot unavailable. " +
                               "Identity comes from Process Monitor hints and recorded create-events.");
            }

            BuildChain(r, target);
            CorroborateSysmon(r, hintSeenUtc);
            CorroborateAudit4688(r);
            ScanShellHistory(r);
            ScanStartupEntries(r);
            var hostedServices = EnumerateHostedServices(r, target);
            AnalyzeSvchostIdentity(r, target, hostedServices);
            AddTaskHintEvidence(r, taskHint);
            (r.Verdict, r.VerdictDetail) = Classify(r, taskHint);

            sw.Stop();
            r.Elapsed = sw.Elapsed;
            return r;
        }

        // ── chain walk ────────────────────────────────────────────────────

        private static void BuildChain(ProvenanceReport r, ProcSnap target)
        {
            if (target == null)
            {
                r.Chain.Add(new ChainLink
                {
                    Pid = r.Pid,
                    Name = r.Name,
                    ExePath = r.ExePath,
                    CommandLine = r.CommandLine,
                    Created = r.Created,
                    Verified = false,
                    Note = r.Recycled
                        ? "subject exited before this inquiry — the PID now belongs to a different, unrelated process (see evidence)"
                        : "not running at inquiry time"
                });
                return;
            }

            var current = target;
            var seen = new HashSet<int> { current.Pid };

            for (int hop = 0; hop < 12; hop++)
            {
                r.Chain.Add(new ChainLink
                {
                    Pid = current.Pid,
                    Name = current.Name,
                    ExePath = current.ExePath,
                    CommandLine = current.CommandLine,
                    Owner = current.Owner,
                    Created = current.Created
                });
                if (RootNames.Contains(current.Name ?? string.Empty)) break;

                int ppid = current.ParentPid;
                if (ppid <= 0 || seen.Contains(ppid)) break;

                var parent = QueryProcess(ppid);
                if (parent == null)
                {
                    r.Chain.Add(new ChainLink
                    {
                        Pid = ppid,
                        Name = "<exited>",
                        Verified = false,
                        Note = "parent exited before this inquiry — lineage beyond this point is " +
                               "unrecoverable from live data (the PID may meanwhile have been recycled)"
                    });
                    break;
                }

                // PID-reuse guard: the PID now names a process that started
                // AFTER the child — it cannot be the real parent.
                if (current.Created.HasValue && parent.Created.HasValue &&
                    parent.Created.Value > current.Created.Value)
                {
                    r.Chain.Add(new ChainLink
                    {
                        Pid = ppid,
                        Name = parent.Name,
                        ExePath = parent.ExePath,
                        CommandLine = parent.CommandLine,
                        Owner = parent.Owner,
                        Created = parent.Created,
                        Verified = false,
                        Note = $"PID reuse: PID {ppid} now belongs to a process started at " +
                               $"{parent.Created.Value:HH:mm:ss}, AFTER this child — not the real parent"
                    });
                    r.Warnings.Add($"Parent PID {ppid} was recycled (its current owner is newer than " +
                                   "the child). True parent unknown from live data — check the recorded create-events.");
                    break;
                }

                seen.Add(ppid);
                current = parent;
            }
        }

        // ── PID-tenant identity helpers ───────────────────────────────────

        /// <summary>
        /// Case-insensitive process-name compare with .exe normalization —
        /// "taskhostw", "taskhostw.exe" and "TASKHOSTW.EXE" are the same
        /// process. Null/empty sides constrain nothing (no hint, no veto).
        /// </summary>
        private static bool NamesMatch(string hinted, string live)
        {
            if (string.IsNullOrEmpty(hinted) || string.IsNullOrEmpty(live)) return true;
            string Normalize(string s)
            {
                s = s.Trim().ToLowerInvariant();
                return s.EndsWith(".exe", StringComparison.Ordinal) ? s : s + ".exe";
            }
            return Normalize(hinted) == Normalize(live);
        }

        /// <summary>
        /// Image-path compare tolerant of spelling differences between
        /// sources (Sysmon paths vs WMI paths): exact path first, file name
        /// as fallback. Null/empty sides constrain nothing.
        /// </summary>
        private static bool ImagesMatch(string hinted, string live)
        {
            if (string.IsNullOrEmpty(hinted) || string.IsNullOrEmpty(live)) return true;
            if (string.Equals(hinted.Trim(), live.Trim(), StringComparison.OrdinalIgnoreCase)) return true;
            return string.Equals(Path.GetFileName(hinted.Trim()), Path.GetFileName(live.Trim()),
                StringComparison.OrdinalIgnoreCase);
        }

        // ── recorded create-events (survive process exit) ──────────────────

        /// <summary>Sysmon Event ID 1 — the authoritative record of the spawn.</summary>
        private static void CorroborateSysmon(ProvenanceReport r, DateTime? hintSeenUtc)
        {
            try
            {
                var query = new EventLogQuery(SysmonLog, PathType.LogName,
                    $"*[System[(EventID=1)]] and *[EventData[Data[@Name='ProcessId']='{r.Pid}']]")
                {
                    ReverseDirection = true // newest first
                };
                using var reader = new EventLogReader(query);

                // Up to 5 newest create-events: a recycled PID can have
                // several tenants in the log. Which record speaks for the
                // SUBJECT is decided by preference, not recency alone:
                //   1. the record matching the subject's known creation time
                //      (the alive / same-tenant case)
                //   2. a record for the hinted image at/before the last
                //      sighting — a dead subject, never a later tenant
                //   3. any record at/before the last sighting
                //   4. the newest record (legacy behavior when no hints exist)
                var records = new List<(Dictionary<string, string> Fields, DateTime? Utc)>();
                for (int i = 0; i < 5; i++)
                {
                    var rec = reader.ReadEvent();
                    if (rec == null) break;
                    using (rec)
                    {
                        var fields = ParseEventData(rec);
                        TryParseSysmonUtc(fields, out DateTime utc);
                        records.Add((fields, utc == default ? (DateTime?)null : utc));

                        if (r.Created.HasValue && utc != default &&
                            (utc.ToLocalTime() - r.Created.Value).Duration() <= TimeSpan.FromSeconds(5))
                        {
                            records.Clear();            // authoritative match —
                            records.Add((fields, utc)); // nothing else competes
                            break;
                        }
                    }
                }

                // The live channel is a rolling window — an old spawn can
                // have wrapped out of it. The app's Sysmon archive holds
                // every event it ever backfilled or watched, so fall back to
                // it before declaring ancestry unrecoverable. Same record
                // shape, same preference rules below.
                bool fromArchive = false;
                if (records.Count == 0)
                {
                    foreach (var a in AutoScope.Services.SysmonArchiveService.SearchCreateEvents(r.Pid, 5))
                        records.Add((a.Data, (DateTime?)a.TsUtc));
                    fromArchive = records.Count > 0;
                }

                (Dictionary<string, string> Fields, DateTime? Utc) best = default;
                int bestScore = -1;
                DateTime? windowUtc = hintSeenUtc?.ToUniversalTime();
                foreach (var (fields, utc) in records)
                {
                    bool inWindow = utc.HasValue && windowUtc.HasValue &&
                                    utc.Value <= windowUtc.Value + TimeSpan.FromSeconds(5);
                    bool imageMatch = r.ExePath != null &&
                                      fields.TryGetValue("Image", out string img) &&
                                      ImagesMatch(r.ExePath, img);

                    int score = inWindow && imageMatch ? 3
                              : inWindow ? 2
                              : imageMatch && windowUtc == null ? 1
                              : 0;
                    if (score > bestScore)
                    {
                        bestScore = score;
                        best = (fields, utc);
                    }
                }
                if (best.Fields == null) return;
                var bestFields = best.Fields;
                DateTime? bestUtc = best.Utc;
                if (bestUtc == null && TryParseSysmonUtc(bestFields, out DateTime fallbackUtc))
                    bestUtc = fallbackUtc;

                // Dead process with no hints: the event IS the identity
                if (!r.Alive)
                {
                    if (bestFields.TryGetValue("Image", out string img))
                    {
                        r.Name = Path.GetFileName(img);
                        r.ExePath ??= img;
                    }
                    r.CommandLine ??= bestFields.TryGetValue("CommandLine", out string cl) ? cl : null;
                    r.Owner ??= bestFields.TryGetValue("User", out string usr) ? usr : null;
                    if (bestUtc != null) r.Created ??= bestUtc.Value.ToLocalTime();
                }

                string when = bestUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "time unknown";
                string detail =
                    $"created {when} · image {bestFields.GetValueOrDefault("Image")}" +
                    $" · parent {bestFields.GetValueOrDefault("ParentImage")} (PID {bestFields.GetValueOrDefault("ParentProcessId")})" +
                    $" · user {bestFields.GetValueOrDefault("User")}";
                if (bestFields.TryGetValue("CommandLine", out string cl2) && !string.IsNullOrEmpty(cl2))
                    detail += $"\r\n      command line: {cl2}";
                if (bestFields.TryGetValue("ParentCommandLine", out string pcl) && !string.IsNullOrEmpty(pcl))
                    detail += $"\r\n      parent command line: {pcl}";
                r.Evidence.Add(new EvidenceItem
                {
                    Source = fromArchive
                        ? "Sysmon archive create-event (EID 1) — wrapped out of the live log"
                        : "Sysmon create-event (EID 1)",
                    Detail = detail
                });
            }
            catch (EventLogNotFoundException)
            {
                r.Warnings.Add("Sysmon is not installed — no recorded create-events. Live data only; " +
                               "exited processes become untraceable.");
            }
            catch (Exception ex)
            {
                r.Warnings.Add("Sysmon create-event lookup failed: " + ex.Message);
            }
        }

        /// <summary>Security 4688 fallback when Sysmon is absent (needs audit policy + admin).</summary>
        private static void CorroborateAudit4688(ProvenanceReport r)
        {
            if (r.Evidence.Any(e => e.Source.StartsWith("Sysmon", StringComparison.Ordinal))) return;
            try
            {
                string hex = "0x" + r.Pid.ToString("X");
                var query = new EventLogQuery("Security", PathType.LogName,
                    $"*[System[(EventID=4688)]] and *[EventData[Data[@Name='NewProcessId']='{hex}']]")
                {
                    ReverseDirection = true
                };
                using var reader = new EventLogReader(query);
                var rec = reader.ReadEvent();
                if (rec == null) return;

                var fields = ParseEventData(rec);
                if (!r.Alive)
                {
                    r.Name = fields.TryGetValue("NewProcessName", out string np) ? Path.GetFileName(np) : r.Name;
                    r.ExePath ??= fields.GetValueOrDefault("NewProcessName");
                }
                r.Evidence.Add(new EvidenceItem
                {
                    Source = "Security audit 4688",
                    Detail = $"created {rec.TimeCreated?.ToLocalTime():yyyy-MM-dd HH:mm:ss} · " +
                             $"image {fields.GetValueOrDefault("NewProcessName")} · " +
                             $"creator process ID {fields.GetValueOrDefault("ProcessId")}"
                });
            }
            catch
            {
                // Security log is admin-only and 4688 auditing is off by
                // default — absence of this evidence is the normal case.
            }
        }

        // ── interactive-shell evidence ─────────────────────────────────────

        /// <summary>
        /// PSReadLine persists every command typed in an interactive
        /// PowerShell session (no timestamps). A history line containing the
        /// process's script/executable is strong "typed by a human" evidence —
        /// it is what settles interactive launches.
        /// </summary>
        private static void ScanShellHistory(ProvenanceReport r)
        {
            try
            {
                string file = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
                if (!File.Exists(file)) return;

                string exeName = string.IsNullOrEmpty(r.ExePath) ? null : Path.GetFileName(r.ExePath);
                string script = ExtractScriptToken(r.CommandLine);

                var hits = new List<string>();
                string[] lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i].Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;

                    bool strong =
                        (!string.IsNullOrEmpty(r.ExePath) &&
                         line.Contains(r.ExePath, StringComparison.OrdinalIgnoreCase)) ||
                        (!string.IsNullOrEmpty(script) &&
                         line.IndexOf(script, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (strong) hits.Add(line);
                    if (hits.Count >= 3) break;
                }

                foreach (string hit in hits)
                    r.Evidence.Add(new EvidenceItem
                    {
                        Source = "PowerShell history (PSReadLine)",
                        Detail = $"typed in an interactive session:\r\n      {hit}"
                    });
            }
            catch
            {
                // history unreadable/absent — evidence simply not available
            }
        }

        /// <summary>First script-looking token of a command line ("x.py", "y.ps1", …).</summary>
        private static string ExtractScriptToken(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine)) return null;
            foreach (string token in commandLine.Split(' ', '\t'))
            {
                string t = token.Trim('"');
                string ext = Path.GetExtension(t);
                if (ext is ".py" or ".ps1" or ".bat" or ".cmd" or ".js" or ".vbs" or ".pl" or ".rb" or ".sh")
                    return Path.GetFileName(t);
            }
            return null;
        }

        // ── autostart surface ──────────────────────────────────────────────

        /// <summary>Run keys + Startup folder via Win32_StartupCommand, matched against the image.</summary>
        private static void ScanStartupEntries(ProvenanceReport r)
        {
            if (string.IsNullOrEmpty(r.ExePath)) return;
            try
            {
                string exeName = Path.GetFileName(r.ExePath);
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, Command, Location FROM Win32_StartupCommand");
                foreach (ManagementObject o in searcher.Get())
                {
                    string cmd = o["Command"]?.ToString() ?? string.Empty;
                    if (cmd.IndexOf(exeName, StringComparison.OrdinalIgnoreCase) < 0 &&
                        cmd.IndexOf(r.ExePath, StringComparison.OrdinalIgnoreCase) < 0) continue;

                    r.Evidence.Add(new EvidenceItem
                    {
                        Source = "Autostart (logon)",
                        Detail = $"{o["Location"]}: '{o["Name"]}' → {cmd}"
                    });
                }
            }
            catch
            {
                // best-effort evidence only
            }
        }

        /// <summary>
        /// Services hosted by the target itself (svchost rows; also flags any
        /// process hosting one). Returns the service names for the identity
        /// cross-check.
        /// </summary>
        private static List<string> EnumerateHostedServices(ProvenanceReport r, ProcSnap target)
        {
            if (target == null) return new List<string>();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT Name, DisplayName, State FROM Win32_Service WHERE ProcessId = {r.Pid}");
                var names = new List<string>();
                var lines = new List<string>();
                foreach (ManagementObject o in searcher.Get())
                {
                    string name = o["Name"]?.ToString();
                    if (string.IsNullOrEmpty(name)) continue;
                    names.Add(name);
                    lines.Add($"{name} — {o["DisplayName"]} ({o["State"]})");
                }
                if (names.Count > 0)
                    r.Evidence.Add(new EvidenceItem
                    {
                        Source = "Services hosted",
                        Detail = string.Join("\r\n      ", lines)
                    });
                return names;
            }
            catch
            {
                // best-effort evidence only
                return new List<string>();
            }
        }

        /// <summary>
        /// Decodes a svchost subject's command line ("-k netsvcs -p -s
        /// WpnService") into its identity: the -k service group (a pool dozens
        /// of instances share) and the -s single tenant, corroborated against
        /// the SCM-resident services — the ground truth a genuine instance
        /// always matches. A hidden command line (standard users cannot read
        /// SYSTEM svchost lines) is disclosed, never guessed.
        /// </summary>
        private static void AnalyzeSvchostIdentity(ProvenanceReport r, ProcSnap target, List<string> hostedServices)
        {
            bool isSvchost =
                string.Equals(r.Name, "svchost.exe", StringComparison.OrdinalIgnoreCase) ||
                (r.ExePath?.EndsWith("\\svchost.exe", StringComparison.OrdinalIgnoreCase) ?? false);
            if (!isSvchost) return;

            var id = SvchostAnalyzer.Core.SvchostIdentity.Parse(r.CommandLine);
            if (string.IsNullOrEmpty(r.CommandLine))
            {
                r.Warnings.Add(
                    "svchost command line hidden — standard users cannot read SYSTEM svchost command lines. " +
                    "Rerun elevated to corroborate the -k group / -s service against the SCM services above.");
                return;
            }

            string group = id.Group ?? "<none>";
            string declared = id.DeclaredService ?? "<none — grouped host>";
            string detail = $"-k group: {group} (the service pool) · -s service: {declared}";

            // Corroborate only against the live SCM map while the subject is
            // the PID's live tenant — a recycled PID hosts someone else now.
            if (target != null && hostedServices.Count > 0)
            {
                string csv = string.Join(",", hostedServices);
                detail += SvchostAnalyzer.Core.SvchostIdentity.Mismatches(id.DeclaredService, csv)
                    ? $"\r\n      ⚠ -s '{id.DeclaredService}' is NOT among the SCM services for this PID ({csv}) — masquerade signal"
                    : "\r\n      command line corroborates the SCM services ✓";
            }
            else
            {
                detail += "\r\n      SCM corroboration unavailable (subject exited — PID may host other services now)";
            }
            r.Evidence.Add(new EvidenceItem { Source = "Svchost identity", Detail = detail });

            if (id.Group == null)
                r.Warnings.Add(
                    "svchost command line has no -k service group — the SCM always passes -k to a real service host; " +
                    "this is a masquerade signal (see audit-svchost.ps1).");
        }

        private static void AddTaskHintEvidence(ProvenanceReport r, TaskLaunchInfo taskHint)
        {
            if (taskHint == null || string.IsNullOrEmpty(taskHint.TaskPath)) return;
            string detail = $"task '{taskHint.TaskPath}'";
            if (!string.IsNullOrEmpty(taskHint.UserContext)) detail += $" running as {taskHint.UserContext}";
            if (!string.IsNullOrEmpty(taskHint.HandlerDll))
                detail += taskHint.HandlerDllExists == true
                    ? $"\r\n      COM handler: {taskHint.HandlerDll}"
                    : $"\r\n      COM handler CLSID {taskHint.HandlerClassId} — DLL missing (orphaned task of uninstalled software)";
            r.Evidence.Add(new EvidenceItem { Source = "Task Scheduler attribution", Detail = detail });
        }

        // ── verdict ────────────────────────────────────────────────────────

        private static (string Verdict, string Detail) Classify(ProvenanceReport r, TaskLaunchInfo taskHint)
        {
            var parent = r.Chain.Count > 1 ? r.Chain[1] : null;
            string pn = parent?.Name?.ToLowerInvariant();

            if (r.Alive && string.Equals(r.Name, "System", StringComparison.OrdinalIgnoreCase))
                return ("Kernel process", "PID 4 is the Windows kernel process — the root every chain ends at.");
            if (r.Recycled)
            {
                string nowOwns = $"{r.CurrentOwnerName} (started {r.CurrentOwnerCreated:yyyy-MM-dd HH:mm:ss})";
                if (taskHint != null && !string.IsNullOrEmpty(taskHint.TaskPath))
                    return ("Scheduled task (PID since recycled)",
                            $"Launched by scheduled task '{taskHint.TaskPath}'" +
                            (string.IsNullOrEmpty(taskHint.UserContext) ? "" : $", running as {taskHint.UserContext}") +
                            $". That process has exited; PID {r.Pid} now belongs to {nowOwns} — an unrelated " +
                            "process that inherited the recycled PID. Everything below describes the exited subject.");
                return ("PID recycled (process exited)",
                        $"The subject has exited and PID {r.Pid} was reused — it now belongs to {nowOwns}, which " +
                        "is unrelated to the spawn being traced. Identity and chain below describe the exited " +
                        "subject, reconstructed from recorded create-events.");
            }
            if (taskHint != null && !string.IsNullOrEmpty(taskHint.TaskPath))
                return ("Scheduled task",
                        $"Launched by scheduled task '{taskHint.TaskPath}'" +
                        (string.IsNullOrEmpty(taskHint.UserContext) ? "" : $", running as {taskHint.UserContext}"));
            if (pn == "taskhostw.exe")
                return ("Scheduled task",
                        "Parent is taskhostw.exe — the Task Scheduler's host process. No task name was " +
                        "captured for this instance (task history may have been disabled at launch time).");
            if (pn == "services.exe")
                return ("Windows service",
                        "Parent is services.exe — the Service Control Manager. See 'Services hosted' in the evidence.");
            if (pn == "explorer.exe")
                return ("User-launched (interactive)",
                        "Parent is the shell (explorer.exe) — started by direct user action: double-click, " +
                        "Start menu, or a shortcut.");
            if (pn != null && InteractiveShells.Contains(pn))
                return ("User-launched from a terminal",
                        $"Parent is {parent.Name} — typed or scripted in a console session; see the " +
                        "PowerShell-history evidence below when present.");
            if (pn == "winlogon.exe" || pn == "userinit.exe")
                return ("Logon autostart",
                        "Parent is the logon chain — started automatically at sign-in. Check the autostart " +
                        "evidence below (Run keys / Startup folder).");
            if (r.Alive && string.Equals(r.Name, "svchost.exe", StringComparison.OrdinalIgnoreCase))
                return ("Windows service host",
                        "svchost instance hosting the services listed in the evidence section.");
            if (parent == null || parent.Name == "<exited>")
                return ("Parent unknown (exited)",
                        "The parent exited before this inquiry and no create-event was found — ancestry " +
                        "is unrecoverable. Sysmon (Process Monitor → Setup Sysmon) makes every future " +
                        "spawn retroactively traceable.");
            if (!parent.Verified)
                return ("Parent unverifiable", parent.Note);
            return ("Spawned by another process",
                    $"Parent: {parent.Name} (PID {parent.Pid}). Follow the chain upward — intermediates " +
                    "like venv/python launchers legitimately re-spawn the real interpreter as a child.");
        }

        // ── WMI plumbing ───────────────────────────────────────────────────

        private sealed class ProcSnap
        {
            public int Pid, ParentPid, SessionId;
            public string Name, ExePath, CommandLine, Owner;
            public DateTime? Created;
            public long WorkingSet;
        }

        private static ProcSnap QueryProcess(int pid)
        {
            try
            {
                // SELECT * (not a column projection): GetOwner invocation on
                // projected objects fails in this System.Management build.
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject o in searcher.Get())
                {
                    string owner = null;
                    try
                    {
                        // 3-arg overload: the 2-arg (string, object[]) path is
                        // broken in this System.Management build and throws
                        // InvalidOperationException on every invoke.
                        if (o.InvokeMethod("GetOwner", null, null) is ManagementBaseObject ownerInfo &&
                            ownerInfo["User"] != null)
                            owner = $"{ownerInfo["Domain"]}\\{ownerInfo["User"]}";
                    }
                    catch { /* protected system processes have no readable owner */ }

                    return new ProcSnap
                    {
                        Pid = pid,
                        ParentPid = Convert.ToInt32(o["ParentProcessId"] ?? 0),
                        SessionId = Convert.ToInt32(o["SessionId"] ?? 0),
                        Name = o["Name"]?.ToString(),
                        ExePath = o["ExecutablePath"]?.ToString(),
                        CommandLine = o["CommandLine"]?.ToString(),
                        Owner = owner,
                        Created = ParseDmtf(o["CreationDate"]?.ToString()),
                        WorkingSet = Convert.ToInt64(o["WorkingSetSize"] ?? 0L)
                    };
                }
            }
            catch
            {
                // access denied / RPC failure — caller treats as "not running"
            }
            return null;
        }

        private static DateTime? ParseDmtf(string dmtf)
        {
            if (string.IsNullOrEmpty(dmtf)) return null;
            try { return ManagementDateTimeConverter.ToDateTime(dmtf); }
            catch { return null; }
        }

        /// <summary>Sysmon's UtcTime field ("2026-10-10 18:56:42.123") as a UTC DateTime.</summary>
        private static bool TryParseSysmonUtc(Dictionary<string, string> fields, out DateTime utc)
        {
            utc = default;
            return fields.TryGetValue("UtcTime", out string raw) &&
                   DateTime.TryParse(raw, null,
                       System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                       out utc);
        }

        /// <summary>EventData of an event record as a Name → Value dictionary.</summary>
        private static Dictionary<string, string> ParseEventData(EventRecord rec)
        {
            var fields = new Dictionary<string, string>();
            var doc = XDocument.Parse(rec.ToXml());
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var eventData = doc.Root?.Element(ns + "EventData");
            if (eventData == null) return fields;
            foreach (var data in eventData.Elements(ns + "Data"))
            {
                string name = data.Attribute("Name")?.Value;
                if (name != null) fields[name] = data.Value;
            }
            return fields;
        }

        private static string FormatBytes(long bytes) => bytes switch
        {
            < 1024 => $"{bytes} B",
            < 1048576 => $"{bytes / 1024.0:F1} KB",
            _ => $"{bytes / 1048576.0:F1} MB"
        };
    }
}
