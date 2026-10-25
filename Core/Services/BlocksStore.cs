using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace AutoScope.Services
{
    /// <summary>One firewall block, as persisted in blocks.txt (v3).</summary>
    public sealed class BlockRecord
    {
        public string Kind;             // "ip" | "proc"
        public string Key;              // remote IP or executable path — joins to firewall rules
        public string ProcessName = ""; // monitor-row label at block time (audit only)
        public DateTime CreatedUtc;
        public string ServiceKey = "";  // grouping identity: service name, exe stem, "svchost:<group>", or "" while unresolved
        public string SvcDisplayName = "";
        public string ClassAtBlock = "";// classifier snapshot: "Akamai (MS CDN)", "Windows component", "Application", …
        public string Origin = "";      // which surface created it: monitor | blocks-tab | migration | repair
        public string Attrib = "none";  // how ServiceKey was resolved: live | sysmon | catalog | none
        public string Status = "on";    // on | off (paused — rules disabled, record kept)
        public DateTime StatusUtc;

        public bool IsIp => Kind == "ip";

        public override string ToString() => Kind == "ip"
            ? $"IP  {Key}  ({(string.IsNullOrEmpty(SvcDisplayName) ? ProcessName : SvcDisplayName)}, blocked {CreatedUtc.ToLocalTime():yyyy-MM-dd HH:mm})"
            : $"EXE {Key}  ({(string.IsNullOrEmpty(SvcDisplayName) ? ProcessName : SvcDisplayName)}, blocked {CreatedUtc.ToLocalTime():yyyy-MM-dd HH:mm})";
    }

    /// <summary>
    /// v3 persistence for the block list — the evolution of the monitor's
    /// CWD-relative blocked.txt. Schema (pipe-delimited, one block per line):
    ///
    ///   v3|kind|key|createdUtc|serviceKey|svcDisplayName|classAtBlock|origin|attrib|status|statusUtc
    ///
    /// Design rules, learned from the two prior formats:
    ///   • Version-prefixed rows — the loader tolerates (and preserves) lines
    ///     it does not understand instead of silently dropping them.
    ///   • Stable path under %LOCALAPPDATA%\AutoScope — the CWD-relative
    ///     file was orphaned by every versioned install folder.
    ///   • Identity is captured at block time (serviceKey/svcDisplayName):
    ///     the PID dies, but "which service did I block" must not.
    ///   • Lifecycle goes to an append-only event log (blocks-events.log);
    ///     the state file stays lean and rewrite-safe.
    /// The firewall rules remain the source of truth for traffic; this store
    /// carries the identity, classification snapshot and history they lack.
    /// </summary>
    public static class BlocksStore
    {
        private static readonly object _gate = new();

        public static string DataDirectory { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoScope");

        public static string StorePath => Path.Combine(DataDirectory, "blocks.txt");
        public static string EventLogPath => Path.Combine(DataDirectory, "blocks-events.log");

        /// <summary>Lines the loader could not interpret, kept verbatim so a
        /// future version (or a human) can still recover them.</summary>
        public static readonly List<string> Unrecognized = new();

        private static readonly List<BlockRecord> _records = new();
        public static IReadOnlyList<BlockRecord> Records { get { lock (_gate) return _records.ToList(); } }

        private static bool _loaded;

        // ── lifecycle ─────────────────────────────────────────────────────

        public static void Load()
        {
            lock (_gate)
            {
                if (_loaded) return;
                _loaded = true;
                _records.Clear();
                Unrecognized.Clear();

                bool importedAny = false;
                try
                {
                    if (File.Exists(StorePath))
                        LoadFrom(StorePath);
                }
                catch { /* unreadable store — start empty, rules are the truth */ }

                // One-time import of legacy monitor files: our own CWD-relative
                // blocked.txt plus any prior install's copy discovered in its
                // versioned folder (read-only — their file is left in place).
                foreach (string legacy in CandidateLegacyPaths())
                {
                    try
                    {
                        if (!File.Exists(legacy)) continue;
                        if (ImportLegacy(legacy))
                        {
                            if (IsOwnLegacyPath(legacy)) RenameImported(legacy);
                            importedAny = true;
                        }
                    }
                    catch { /* best-effort import — never block startup */ }
                }

                // Persist the import immediately — the legacy file was renamed,
                // so an exit without a write must not lose the records.
                if (importedAny) Save();
            }
        }

        /// <summary>Loads v3 rows; anything else is kept in Unrecognized.</summary>
        private static void LoadFrom(string path)
        {
            foreach (string line in File.ReadAllLines(path))
            {
                string trimmed = line.Trim();
                if (trimmed.Length == 0) continue;

                if (trimmed.StartsWith("v3|", StringComparison.Ordinal))
                {
                    var r = ParseV3(trimmed);
                    if (r != null) { _records.Add(r); continue; }
                }
                Unrecognized.Add(line);
            }
        }

        private static BlockRecord ParseV3(string line)
        {
            try
            {
                string[] p = line.Split('|');
                if (p.Length < 11) return null;
                var r = new BlockRecord
                {
                    Kind = p[1],
                    Key = p[2],
                    CreatedUtc = DateTime.Parse(p[3], System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.RoundtripKind),
                    ServiceKey = p[4],
                    SvcDisplayName = p[5],
                    ClassAtBlock = p[6],
                    Origin = p[7],
                    Attrib = p[8],
                    Status = p[9],
                    StatusUtc = DateTime.TryParse(p[10], System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.RoundtripKind, out var st) ? st : DateTime.UtcNow,
                };
                if (r.Kind != "ip" && r.Kind != "proc") return null;
                if (string.IsNullOrEmpty(r.Key)) return null;
                return r;
            }
            catch { return null; }
        }

        /// <summary>
        /// Legacy blocked.txt candidates. The CWD-relative files are ours and
        /// get renamed after import; the discovered ones belong to OTHER
        /// installs (the app ships as versioned folders — every update
        /// extracts to Downloads\AutoScope-v<ver>\ leaving the previous
        /// release's blocked.txt behind), so they are read but never touched.
        /// Own-dir candidates first, then discovered, newest install first.
        /// </summary>
        internal static IEnumerable<string> CandidateLegacyPaths()
        {
            string cwd = Path.Combine(Environment.CurrentDirectory, "blocked.txt");
            string baseDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "blocked.txt");
            yield return cwd;
            if (!string.Equals(baseDir, cwd, StringComparison.OrdinalIgnoreCase))
                yield return baseDir;

            // prior versioned install folders (Downloads / Desktop) and any
            // app-local copy — sorted newest folder name first
            var roots = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                DataDirectory,
            };
            foreach (string root in roots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                List<string> hits = null;
                try
                {
                    hits = Directory.GetDirectories(root, "AutoScope-v*")
                        .OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase)
                        .Select(d => Path.Combine(d, "blocked.txt"))
                        .Where(File.Exists)
                        .ToList();
                    var direct = Path.Combine(root, "blocked.txt");
                    if (File.Exists(direct)) hits.Add(direct);
                }
                catch { /* unreadable root — skip it */ }
                if (hits == null) continue;
                foreach (string h in hits) yield return h;
            }
        }

        internal static bool IsOwnLegacyPath(string path)
        {
            string cwd = Environment.CurrentDirectory;
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            return path.StartsWith(cwd, StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith(baseDir, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Imports v2 (kind|key|process|ts, 4 fields) and the older myfirewall
        /// rows (ip|process|ts or process|"Default Policy"|ts, 3 fields).
        /// Records synthesized by the firewall-reconcile pass (origin
        /// "reconcile") are UPGRADED by a matching legacy row — the legacy
        /// row carries the richer data (precise timestamps, process labels).
        /// Returns true when at least one record was added or upgraded.
        /// </summary>
        private static bool ImportLegacy(string path)
        {
            int imported = 0;
            var known = _records.ToDictionary(r => r.Kind + ":" + r.Key, r => r, StringComparer.OrdinalIgnoreCase);
            var pending = new List<BlockRecord>();

            foreach (string line in File.ReadAllLines(path))
            {
                string trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;
                string[] p = trimmed.Split('|');

                BlockRecord r = null;
                if (p.Length == 4 && (p[0] == "ip" || p[0] == "proc"))
                    r = FromV2(p);
                else if (p.Length == 3)
                    r = FromMyFirewall(p); // both column orders — detected by which field parses as an IP
                if (r == null) { Unrecognized.Add(line); continue; }

                string dedupe = r.Kind + ":" + r.Key;
                if (known.TryGetValue(dedupe, out var existing))
                {
                    // reconcile-synthesized rows are lower fidelity — upgrade
                    if (existing.Origin == "reconcile")
                    {
                        r.Status = existing.Status;
                        _records[_records.IndexOf(existing)] = r;
                        known[dedupe] = r;
                        imported++;
                    }
                    continue;
                }
                known[dedupe] = r;
                pending.Add(r);
                imported++;
            }

            if (imported > 0)
            {
                _records.AddRange(pending);
                AppendEvent("imported", "-", "-", $"{imported} record(s) from {Path.GetFileName(path)}", "migration");
            }
            return imported > 0;
        }

        private static BlockRecord FromV2(string[] p)
        {
            if (!DateTime.TryParse(p[3], out DateTime ts)) ts = DateTime.UtcNow;
            var r = new BlockRecord
            {
                Kind = p[0], Key = p[1], ProcessName = p[2],
                CreatedUtc = ts.ToUniversalTime(), StatusUtc = ts.ToUniversalTime(),
                Origin = "migration", Attrib = "none",
                ClassAtBlock = p[0] == "ip" ? IpClassifier.Classify(p[1]) : ClassForPath(p[1]),
            };
            SeedServiceFromLabel(r);
            return r;
        }

        private static BlockRecord FromMyFirewall(string[] p)
        {
            bool field0IsIp = System.Net.IPAddress.TryParse(p[0], out _);
            bool field2IsIp = System.Net.IPAddress.TryParse(p[2], out _);
            if (!field0IsIp && !field2IsIp) return null; // e.g. proc|Default Policy|ts — no target to manage
            string ip = field0IsIp ? p[0] : p[2];
            string proc = field0IsIp ? p[1] : p[0];
            if (!DateTime.TryParse(field0IsIp ? p[2] : p[1], out DateTime ts)) ts = DateTime.UtcNow;
            var r = new BlockRecord
            {
                Kind = "ip", Key = ip, ProcessName = proc,
                CreatedUtc = ts.ToUniversalTime(), StatusUtc = ts.ToUniversalTime(),
                Origin = "migration", Attrib = "none",
                ClassAtBlock = IpClassifier.Classify(ip),
            };
            SeedServiceFromLabel(r);
            return r;
        }

        /// <summary>Best-effort identity for imported rows: a named process
        /// becomes its exe-stem group; svchost/unknown stay unresolved pending
        /// the Sysmon repair pass.</summary>
        private static void SeedServiceFromLabel(BlockRecord r)
        {
            string label = (r.ProcessName ?? "").Trim();
            if (label.Length == 0 || label.StartsWith("<", StringComparison.Ordinal)) return;
            if (label.StartsWith("svchost", StringComparison.OrdinalIgnoreCase)) return;
            r.ServiceKey = System.IO.Path.GetFileNameWithoutExtension(label).ToLowerInvariant();
            r.SvcDisplayName = ServiceCatalog.TryGet(r.ServiceKey, out var c) ? c.DisplayName : label;
            r.Attrib = "catalog";
        }

        private static void RenameImported(string legacy)
        {
            try
            {
                string bak = legacy + ".imported-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
                File.Copy(legacy, bak);
                File.Delete(legacy);
            }
            catch { /* keep the original rather than risk a double-import failing */ }
        }

        /// <summary>
        /// Pulls the service identity out of a block rule's provenance
        /// description — BuildProvenance writes
        /// "[blocked ts] svchost.exe [netprofm] PID 1216 → …", so the
        /// firewall rules themselves are a durable identity carrier the
        /// reconcile path can read without the archive. The bracketed label
        /// is the monitor's resolved identity ("WpnService", "A+B",
        /// "A+2 more"); the primary service is the first token.
        /// </summary>
        public static bool TryParseServiceFromDescription(string desc, out string serviceKey, out string displayName)
        {
            serviceKey = displayName = null;
            if (string.IsNullOrEmpty(desc)) return false;
            int close = desc.IndexOf(']');
            if (close < 0 || !desc.StartsWith("[blocked ", StringComparison.Ordinal)) return false;

            string rest = desc.Substring(close + 1).TrimStart();
            int bracket = rest.IndexOf('[');
            if (bracket <= 0) return false;
            int end = rest.IndexOf(']', bracket + 1);
            if (end <= bracket) return false;

            string proc = rest.Substring(0, bracket).Trim();
            if (!proc.StartsWith("svchost", StringComparison.OrdinalIgnoreCase)) return false;

            string label = rest.Substring(bracket + 1, end - bracket - 1).Trim();
            if (label.Length == 0) return false;
            int plus = label.IndexOf('+');
            if (plus > 0) label = label.Substring(0, plus).Trim(); // "A+2 more" → primary
            if (label.Length == 0 || label.Equals("no service", StringComparison.OrdinalIgnoreCase)) return false;

            serviceKey = label.ToLowerInvariant();
            displayName = ServiceCatalog.TryGet(serviceKey, out var c) ? c.DisplayName : label;
            return true;
        }

        public static string ClassForPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return "Application";
            string lower = path.ToLowerInvariant();
            if (lower.Contains("\\windows\\") || lower.StartsWith("c:\\windows")) return "Windows component";
            if (lower.Contains("\\programdata\\microsoft\\windows defender")) return "Windows Defender";
            return "Application";
        }

        // ── writes ────────────────────────────────────────────────────────

        /// <summary>Inserts or refreshes one block. Re-blocking the same key
        /// keeps the original CreatedUtc (history) but updates identity.</summary>
        /// <summary>
        /// Adopts firewall block-rule targets the store doesn't know yet —
        /// the same reconcile the Blocks tab runs on reload, lifted here so
        /// App startup can run it too. Keeps AutoScope's blocked list in
        /// step with rules created by AutoCommand (AC-BLOCK) since the
        /// migration snapshot. Returns how many records were adopted.
        /// </summary>
        public static async System.Threading.Tasks.Task<int> ReconcileWithFirewallAsync(
            System.Collections.Generic.List<FirewallService.BlockedTarget> inventory = null)
        {
            inventory ??= await FirewallService.Instance.GetBlockedInventoryAsync();
            int added = 0;
            var known = new System.Collections.Generic.HashSet<string>(
                Records.Select(r => (r.IsIp ? "ip:" : "app:") + r.Key.ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);
            foreach (var t in inventory)
            {
                if (known.Contains(t.Key)) continue;
                var r = new BlockRecord
                {
                    Kind = t.Kind == "ip" ? "ip" : "proc",
                    Key = t.Kind == "ip" ? t.Ip : t.AppPath,
                    ProcessName = System.IO.Path.GetFileName(t.AppPath ?? ""),
                    CreatedUtc = t.Created ?? DateTime.UtcNow,
                    StatusUtc = t.Created ?? DateTime.UtcNow,
                    ClassAtBlock = t.Kind == "ip" ? IpClassifier.Classify(t.Ip) : ClassForPath(t.AppPath ?? ""),
                    Origin = "reconcile",
                    Attrib = "none",
                };
                // The rules carry their own provenance — the service the
                // monitor resolved at block time is embedded in the
                // description, so reconcile recovers identity without
                // the archive.
                if (TryParseServiceFromDescription(t.Description, out string sk, out string dn))
                {
                    r.ServiceKey = sk;
                    r.SvcDisplayName = dn;
                    r.Attrib = "rule-desc";
                }
                else if (r.Kind == "proc" && !string.IsNullOrEmpty(r.Key))
                {
                    r.ServiceKey = System.IO.Path.GetFileNameWithoutExtension(r.Key).ToLowerInvariant();
                    r.SvcDisplayName = ServiceCatalog.DisplayNameFor(r.ServiceKey, null);
                    r.Attrib = "catalog";
                }
                if (!string.IsNullOrEmpty(r.Key))
                {
                    AddOrUpdate(r, "reconcile");
                    known.Add((r.IsIp ? "ip:" : "app:") + r.Key.ToLowerInvariant());
                    added++;
                }
            }
            return added;
        }

        public static void AddOrUpdate(BlockRecord record, string origin = "monitor")
        {
            if (record == null || string.IsNullOrEmpty(record.Key)) return;
            lock (_gate)
            {
                Load();
                int i = _records.FindIndex(b => b.Kind == record.Kind &&
                    b.Key.Equals(record.Key, StringComparison.OrdinalIgnoreCase));
                if (i >= 0)
                {
                    var old = _records[i];
                    record.CreatedUtc = old.CreatedUtc; // first-block time survives re-blocks
                    _records[i] = record;
                }
                else _records.Add(record);
                Save();
                AppendEvent("created", record.Kind, record.Key,
                    $"{record.ServiceKey}|{record.ClassAtBlock}", origin);
            }
        }

        public static void Remove(string kind, string key, string origin = "monitor")
        {
            lock (_gate)
            {
                Load();
                var r = _records.FirstOrDefault(b => b.Kind == kind &&
                    b.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
                _records.RemoveAll(b => b.Kind == kind &&
                    b.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
                Save();
                if (r != null)
                    AppendEvent("removed", kind, key, $"{r.ServiceKey}|after {DateTime.UtcNow - r.CreatedUtc:dd\\d\\ hh\\h\\ mm\\m}", origin);
            }
        }

        /// <summary>Marks the desired state (on/off). The firewall's Enabled
        /// flags stay authoritative for traffic; this is the durable intent.</summary>
        public static void SetStatus(string kind, string key, string status, string origin = "blocks-tab")
        {
            lock (_gate)
            {
                Load();
                var r = _records.FirstOrDefault(b => b.Kind == kind &&
                    b.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
                if (r == null || r.Status == status) return;
                r.Status = status;
                r.StatusUtc = DateTime.UtcNow;
                Save();
                AppendEvent(status == "on" ? "resumed" : "paused", kind, key, r.ServiceKey, origin);
            }
        }

        /// <summary>Bulk status flip for a whole service group (fired after the
        /// firewall rules are toggled so the log reflects the actual outcome).</summary>
        public static void SetStatusForGroup(string serviceKey, string status, string origin = "blocks-tab")
        {
            lock (_gate)
            {
                Load();
                int n = 0;
                foreach (var r in _records.Where(b => ServiceGroupKey(b).Equals(serviceKey, StringComparison.OrdinalIgnoreCase)))
                {
                    if (r.Status == status) continue;
                    r.Status = status;
                    r.StatusUtc = DateTime.UtcNow;
                    n++;
                }
                if (n > 0)
                {
                    Save();
                    AppendEvent(status == "on" ? "resumed" : "paused", "-", "-", $"{serviceKey} × {n}", origin);
                }
            }
        }

        /// <summary>Replaces the identity fields of one record (Sysmon repair).</summary>
        public static void SetAttribution(string kind, string key, string serviceKey, string displayName, string source) =>
            SetAttributions(new[] { (kind, key, serviceKey, displayName, source) });

        /// <summary>Batch form of SetAttribution — one save for the whole
        /// repair pass instead of a file rewrite per record.</summary>
        public static void SetAttributions(
            IEnumerable<(string kind, string key, string serviceKey, string displayName, string source)> updates)
        {
            lock (_gate)
            {
                Load();
                var applied = new List<(string kind, string key, string svc, string src)>();
                foreach (var u in updates)
                {
                    var r = _records.FirstOrDefault(b => b.Kind == u.kind &&
                        b.Key.Equals(u.key, StringComparison.OrdinalIgnoreCase));
                    if (r == null) continue;
                    r.ServiceKey = u.serviceKey ?? "";
                    r.SvcDisplayName = u.displayName ?? "";
                    r.Attrib = u.source;
                    applied.Add((u.kind, u.key, u.serviceKey, u.source));
                }
                if (applied.Count == 0) return;
                Save();
                foreach (var a in applied)
                    AppendEvent("attributed", a.kind, a.key, $"{a.svc} via {a.src}", "repair");
            }
        }

        /// <summary>The grouping key the Blocks tab folds rows under — never
        /// the bare "svchost.exe" label: unresolved rows group as
        /// "svchost:unresolved" so the repair pass can find them.</summary>
        public static string ServiceGroupKey(BlockRecord r)
        {
            if (!string.IsNullOrEmpty(r.ServiceKey)) return r.ServiceKey;
            string label = (r.ProcessName ?? "").Trim();
            if (label.Length == 0 || label.StartsWith("<", StringComparison.Ordinal) ||
                label.StartsWith("svchost", StringComparison.OrdinalIgnoreCase))
                return "svchost:unresolved";
            return System.IO.Path.GetFileNameWithoutExtension(label).ToLowerInvariant();
        }

        // ── persistence ───────────────────────────────────────────────────

        private static void Save()
        {
            try
            {
                Directory.CreateDirectory(DataDirectory);
                var sb = new StringBuilder();
                foreach (var r in _records)
                    sb.Append(string.Join("|",
                        "v3", r.Kind, Sanitize(r.Key), r.CreatedUtc.ToString("O"),
                        Sanitize(r.ServiceKey), Sanitize(r.SvcDisplayName), Sanitize(r.ClassAtBlock),
                        Sanitize(r.Origin), Sanitize(r.Attrib), r.Status, r.StatusUtc.ToString("O")))
                       .AppendLine();
                // unknown lines survive rewrites at the tail, verbatim
                foreach (string u in Unrecognized) sb.AppendLine(u);
                File.WriteAllText(StorePath, sb.ToString());
            }
            catch { /* best-effort: the firewall rules are the source of truth */ }
        }

        private static string Sanitize(string s) =>
            (s ?? "").Replace('|', '/');

        /// <summary>Append-only audit trail: utc|action|kind|key|detail|origin.</summary>
        public static void AppendEvent(string action, string kind, string key, string detail, string origin)
        {
            try
            {
                Directory.CreateDirectory(DataDirectory);
                File.AppendAllText(EventLogPath,
                    $"{DateTime.UtcNow:O}|{action}|{kind}|{key}|{Sanitize(detail)}|{origin}{Environment.NewLine}");
            }
            catch { /* history is best-effort */ }
        }
    }
}
