using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AutoScope.Helpers;

namespace AutoScope.Services
{
    // -----------------------------------------------------------------------
    // Rule knowledge base (Assets/telemetry_rules.json, seed fallback below)
    // -----------------------------------------------------------------------

    public class TelemetryRule
    {
        public string Id { get; set; }
        public string AppName { get; set; }
        public string Category { get; set; }
        public string Mechanism { get; set; }
        public string Scope { get; set; }
        public string RiskNote { get; set; }
        public List<string> WatchDomains { get; set; } = new();
        public DetectionSpec Detection { get; set; }
        public ProbeSpec StateProbe { get; set; }
        public OptOutSpec OptOut { get; set; }
        public EnforceSpec Enforce { get; set; }
    }

    public class DetectionSpec
    {
        public string Type { get; set; }        // file | env | os
        public string Path { get; set; }
    }

    public class ProbeSpec
    {
        public string Type { get; set; }        // json | env | registry
        public string Path { get; set; }
        public string Key { get; set; }
        public string Var { get; set; }
        public string RegKey { get; set; }
        public string RegName { get; set; }
        public List<string> OffValues { get; set; } = new();

        /// <summary>
        /// Optional JSON token type the target app expects ("bool" | "number" | "string").
        /// A value that matches an offValue but has the wrong token type is reported
        /// Ineffective rather than Off — e.g. ultralytics loads settings with plain
        /// json.load, so "sync": "false" (string) is truthy and telemetry stays on.
        /// </summary>
        public string ValueType { get; set; }
    }

    public class OptOutSpec
    {
        public string Type { get; set; }        // json | env | registry
        public string Path { get; set; }
        public string Key { get; set; }
        public string Value { get; set; }

        /// <summary>Optional: write Value as this JSON token type ("bool" | "number" | "string").</summary>
        public string ValueType { get; set; }
        public string Var { get; set; }
        public string RegKey { get; set; }
        public string RegName { get; set; }
        public string Kind { get; set; } = "dword";
    }

    /// <summary>
    /// Network-level enforcement for telemetry the target app ignores its opt-out
    /// flag for (or that only takes effect on processes started after the change).
    /// </summary>
    public class EnforceSpec
    {
        public string Type { get; set; }                       // hosts

        /// <summary>
        /// Address to pin to: "0.0.0.0" (default — silent, fails instantly) or
        /// "127.0.0.1" (sinkhole — a local listener can log each attempt).
        /// Only these two values are ever honored.
        /// </summary>
        public string Address { get; set; } = "0.0.0.0";

        public List<string> Domains { get; set; } = new();     // pinned hostnames
    }

    public enum TelemetryState { On, Off, Ineffective, Unknown }

    public class TelemetryRuleStatus
    {
        public TelemetryRule Rule { get; set; }
        public bool Detected { get; set; }
        public TelemetryState State { get; set; }
        public string StateText => State switch
        {
            TelemetryState.On => "Telemetry on",
            TelemetryState.Off => "Opted out",
            TelemetryState.Ineffective => "Opt-out not honored",
            _ => "Unknown"
        };
        public string Evidence { get; set; }
        public bool HasRevertSnapshot { get; set; }
        public bool Enforced { get; set; }     // network block active
    }

    // -----------------------------------------------------------------------
    // Service
    // -----------------------------------------------------------------------

    /// <summary>
    /// Opt-out manager for telemetry across installed software. Rules live in
    /// Assets/telemetry_rules.json (updatable without a rebuild); each rule
    /// knows how to detect the app, whether its telemetry is on, and how to
    /// opt out and revert. Every applied change is snapshotted to
    /// telemetry_state.json so opt-outs are one-click reversible. Rules that
    /// also carry an <c>enforce</c> block can pin the telemetry domain to
    /// 0.0.0.0 in the hosts file — enforcement that does not depend on the
    /// target honoring its own switch.
    /// </summary>
    public class TelemetryRulesService
    {
        private const string RulesFile = "Assets\\telemetry_rules.json";
        private static string StateFile => System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, "telemetry_state.json");

        // Hosts lines are written under a marker carrying the rule id so the
        // app removes only its own lines — never user edits — on revert.
        private const string HostsMarkerPrefix = "# AutoScope telemetry-block ";

        // Removal and status scan BOTH apps' markers: a pin created by
        // AutoScope's Black Hole tab must be removable here, and vice
        // versa — "act from either app" dies at brand-locked markers.
        private static readonly string[] AllMarkerPrefixes =
        {
            "# AutoScope telemetry-block ",
            "# ShieldsUp telemetry-block ",
        };

        private sealed class ChangeRecord
        {
            public string RuleId { get; set; }
            public string Kind { get; set; }        // json | env | registry | hosts
            public string Target { get; set; }      // file path / var name / reg key
            public string Name { get; set; }        // json key / reg value name
            public string PreviousValue { get; set; } // raw JSON token text; null-marker = was absent
            public DateTime ChangedAt { get; set; }
        }

        // telemetry_rules.json uses camelCase keys; matching is case-insensitive
        // so hand-edited rules with PascalCase keys also load
        private static readonly JsonSerializerOptions RuleJsonOptions =
            new() { PropertyNameCaseInsensitive = true };

        private readonly string _rulesPath = Path.Combine(AppContext.BaseDirectory, RulesFile);
        private List<ChangeRecord> _changes = new();

        public TelemetryRulesService()
        {
            LoadChanges();
        }

        public List<TelemetryRule> Rules => LoadRules();

        private List<TelemetryRule> LoadRules()
        {
            try
            {
                if (File.Exists(_rulesPath))
                {
                    var doc = JsonNode.Parse(File.ReadAllText(_rulesPath)).AsObject();
                    var rules = doc["rules"].Deserialize<List<TelemetryRule>>(RuleJsonOptions);
                    if (rules is { Count: > 0 }) return rules;
                }
            }
            catch { /* fall through to built-in seed */ }
            return SeedRules();
        }

        /// <summary>Same content as the shipped JSON — used when the file is missing or corrupt.</summary>
        private static List<TelemetryRule> SeedRules() =>
            JsonSerializer.Deserialize<List<TelemetryRule>>(@"
[
  {
    ""id"": ""ultralytics-sync"",
    ""appName"": ""Ultralytics YOLO (Python)"",
    ""category"": ""Python library"",
    ""mechanism"": ""Sends anonymized usage statistics to Google Analytics at the end of predict/train/val/export runs, tied to a persistent install uuid (%APPDATA%\\Ultralytics\\settings.json). The switch is honored only when written as a JSON boolean — a quoted \""false\"" reads back as ON."",
    ""scope"": ""User"",
    ""riskNote"": ""Low — model training and inference are unaffected; this only disables the stats upload and Hub sync."",
    ""watchDomains"": [ ""google-analytics.com"" ],
    ""detection"": { ""type"": ""file"", ""path"": ""%APPDATA%\\Ultralytics\\settings.json"" },
    ""stateProbe"": { ""type"": ""json"", ""path"": ""%APPDATA%\\Ultralytics\\settings.json"", ""key"": ""sync"", ""offValues"": [ ""false"" ], ""valueType"": ""bool"" },
    ""optOut"": { ""type"": ""json"", ""path"": ""%APPDATA%\\Ultralytics\\settings.json"", ""key"": ""sync"", ""value"": ""false"", ""valueType"": ""bool"" },
    ""enforce"": { ""type"": ""hosts"", ""domains"": [ ""www.google-analytics.com"" ] }
  },
  {
    ""id"": ""ultralytics-offline"",
    ""appName"": ""Ultralytics YOLO (offline mode)"",
    ""category"": ""Python library"",
    ""mechanism"": ""YOLO_OFFLINE=1 makes the library skip all of its own network calls — usage statistics, package auto-install and version checks. Honored by the library itself; no settings file involved."",
    ""scope"": ""User — affects every new Python process"",
    ""riskNote"": ""Low-medium — also disables auto-install and update checks; model weights must already be on disk."",
    ""watchDomains"": [ ""google-analytics.com"", ""ultralytics.com"" ],
    ""detection"": { ""type"": ""file"", ""path"": ""%APPDATA%\\Ultralytics\\settings.json"" },
    ""stateProbe"": { ""type"": ""env"", ""var"": ""YOLO_OFFLINE"", ""offValues"": [ ""1"", ""true"" ] },
    ""optOut"": { ""type"": ""env"", ""var"": ""YOLO_OFFLINE"", ""value"": ""1"" }
  }
]", RuleJsonOptions) ?? new List<TelemetryRule>();

        // -----------------------------------------------------------------------
        // Evaluation
        // -----------------------------------------------------------------------

        public Task<List<TelemetryRuleStatus>> EvaluateAllAsync() => Task.Run(() =>
            Rules.Select(Evaluate).ToList());

        private TelemetryRuleStatus Evaluate(TelemetryRule rule)
        {
            var status = new TelemetryRuleStatus { Rule = rule, State = TelemetryState.Unknown };

            try
            {
                status.Detected = rule.Detection?.Type switch
                {
                    "file" => File.Exists(Expand(rule.Detection.Path)),
                    "os" => true,
                    _ => false
                };
            }
            catch { status.Detected = false; }

            if (!status.Detected)
            {
                status.Evidence = "Not detected on this machine.";
                return status;
            }

            var (state, evidence) = Probe(rule.StateProbe);
            status.State = state;
            status.Evidence = evidence;
            status.HasRevertSnapshot = _changes.Any(c => c.RuleId == rule.Id && c.Kind != "hosts");
            status.Enforced = rule.Enforce != null && HostsBlockActive(rule);
            return status;
        }

        private static (TelemetryState, string) Probe(ProbeSpec probe)
        {
            if (probe == null) return (TelemetryState.Unknown, "No state probe defined.");

            try
            {
                switch (probe.Type)
                {
                    case "json":
                    {
                        string path = Expand(probe.Path);
                        if (!File.Exists(path)) return (TelemetryState.Unknown, $"{probe.Path} not found.");
                        JsonNode node = ReadJsonKey(path, probe.Key);
                        string evidence = $"{probe.Key} = {node?.ToJsonString() ?? "(absent)"} in {probe.Path}";
                        if (node == null) return (TelemetryState.On, evidence);
                        return MatchJson(probe, node, evidence);
                    }
                    case "env":
                    {
                        string value = Environment.GetEnvironmentVariable(probe.Var, EnvironmentVariableTarget.User)
                                       ?? Environment.GetEnvironmentVariable(probe.Var, EnvironmentVariableTarget.Machine);
                        return Match(value, probe.OffValues,
                            $"{probe.Var} = {value ?? "(not set)"}");
                    }
                    case "registry":
                    {
                        string value = ReadRegistry(probe.RegKey, probe.RegName);
                        return Match(value, probe.OffValues,
                            $"{probe.RegKey}\\{probe.RegName} = {value ?? "(not set)"}");
                    }
                }
            }
            catch (Exception ex)
            {
                return (TelemetryState.Unknown, $"Probe failed: {ex.Message}");
            }
            return (TelemetryState.Unknown, "Unknown probe type.");
        }

        private static (TelemetryState, string) Match(string current, List<string> offValues, string evidence)
        {
            bool off = current != null && offValues.Any(v =>
                string.Equals(v, current, StringComparison.OrdinalIgnoreCase));
            return (off ? TelemetryState.Off : TelemetryState.On, evidence);
        }

        /// <summary>
        /// JSON probes compare the node's text against offValues, and — when the
        /// rule declares the token type the target app expects — additionally
        /// require that type. Text match + type mismatch means an opt-out was
        /// written but the target reads it as ON: report Ineffective, not Off.
        /// </summary>
        private static (TelemetryState, string) MatchJson(ProbeSpec probe, JsonNode node, string evidence)
        {
            string text = node.ToString() ?? string.Empty;
            bool off = probe.OffValues.Any(v =>
                string.Equals(v, text, StringComparison.OrdinalIgnoreCase));
            if (off && !string.IsNullOrWhiteSpace(probe.ValueType))
            {
                bool typeMatches = probe.ValueType.Trim().ToLowerInvariant() switch
                {
                    "bool" => IsBooleanNode(node),
                    "number" => IsNumberNode(node),
                    "string" => IsStringNode(node),
                    _ => true,
                };
                if (!typeMatches)
                    return (TelemetryState.Ineffective,
                        $"{evidence} — matches the off value but is the wrong JSON type; " +
                        $"this app expects {probe.ValueType} and reads this as ON. Re-apply the opt-out to fix it.");
            }
            return (off ? TelemetryState.Off : TelemetryState.On, evidence);
        }

        private static bool IsBooleanNode(JsonNode node) =>
            node is JsonValue v && v.TryGetValue<bool>(out _);

        private static bool IsNumberNode(JsonNode node) =>
            node is JsonValue v && v.TryGetValue<double>(out _);

        private static bool IsStringNode(JsonNode node) =>
            node is JsonValue v && v.TryGetValue<string>(out _);

        // -----------------------------------------------------------------------
        // Apply / revert (the vendor's own opt-out switch)
        // -----------------------------------------------------------------------

        public async Task<(bool Success, string Message)> ApplyOptOutAsync(TelemetryRule rule)
        {
            if (rule?.OptOut == null) return (false, "Rule has no opt-out action.");
            try
            {
                switch (rule.OptOut.Type)
                {
                    case "json":
                    {
                        string path = Expand(rule.OptOut.Path);
                        if (!File.Exists(path))
                            await File.WriteAllTextAsync(path, "{}");
                        string previous = ReadJsonKey(path, rule.OptOut.Key)?.ToJsonString();
                        JsonNode value = ParseOptOutValue(rule.OptOut);
                        WriteJsonNode(path, rule.OptOut.Key, value);
                        RecordChange(rule.Id, "json", path, rule.OptOut.Key, previous);

                        // Verify against the file as written — some targets rewrite
                        // this file themselves (ultralytics migrates its schema),
                        // and a mismatched re-read means the opt-out did not stick.
                        string reread = ReadJsonKey(path, rule.OptOut.Key)?.ToJsonString();
                        bool verified = string.Equals(reread, value.ToJsonString(), StringComparison.Ordinal);
                        return (verified,
                            $"{rule.AppName}: set {rule.OptOut.Key} = {value.ToJsonString()} in {rule.OptOut.Path}" +
                            (verified
                                ? " — verified by re-reading the file."
                                : " — WARNING: re-read did not match; the target app may have rewritten the file. Re-apply after closing it.") +
                            RestartNote);
                    }
                    case "env":
                    {
                        string previous = Environment.GetEnvironmentVariable(rule.OptOut.Var, EnvironmentVariableTarget.User);
                        Environment.SetEnvironmentVariable(rule.OptOut.Var, rule.OptOut.Value, EnvironmentVariableTarget.User);
                        RecordChange(rule.Id, "env", rule.OptOut.Var, null, previous);
                        return (true, $"{rule.AppName}: set {rule.OptOut.Var} = {rule.OptOut.Value} (user).{RestartNote}");
                    }
                    case "registry":
                    {
                        string previous = ReadRegistry(rule.OptOut.RegKey, rule.OptOut.RegName);
                        WriteRegistry(rule.OptOut.RegKey, rule.OptOut.RegName, rule.OptOut.Value,
                            string.Equals(rule.OptOut.Kind, "dword", StringComparison.OrdinalIgnoreCase));
                        RecordChange(rule.Id, "registry", rule.OptOut.RegKey, rule.OptOut.RegName, previous);
                        return (true, $"{rule.AppName}: set {rule.OptOut.RegName} = {rule.OptOut.Value}.");
                    }
                    default:
                        return (false, $"Unknown opt-out type '{rule.OptOut.Type}'.");
                }
            }
            catch (Exception ex)
            {
                return (false, $"Opt-out failed: {ex.Message}");
            }
        }

        private static string RestartNote =>
            "\nAlready-running processes keep the old value — restart them for the change to take effect.";

        public async Task<(bool Success, string Message)> RevertAsync(TelemetryRule rule)
        {
            var record = _changes.LastOrDefault(c => c.RuleId == rule.Id && c.Kind != "hosts");
            if (record == null) return (false, "No snapshot for this rule — nothing to revert.");

            try
            {
                switch (record.Kind)
                {
                    case "json":
                        if (record.PreviousValue == null) RemoveJsonKey(record.Target, record.Name);
                        else WriteJsonNode(record.Target, record.Name, SafeParseNode(record.PreviousValue));
                        break;
                    case "env":
                        Environment.SetEnvironmentVariable(record.Target, record.PreviousValue,
                            EnvironmentVariableTarget.User);
                        break;
                    case "registry":
                        if (record.PreviousValue == null) DeleteRegistryValue(record.Target, record.Name);
                        else WriteRegistry(record.Target, record.Name, record.PreviousValue, true);
                        break;
                }
                _changes.Remove(record);
                SaveChanges();
                await Task.CompletedTask;
                return (true, $"{rule.AppName}: previous setting restored.");
            }
            catch (Exception ex)
            {
                return (false, $"Revert failed: {ex.Message}");
            }
        }

        // -----------------------------------------------------------------------
        // Enforcement (network block — needs no cooperation from the target)
        // -----------------------------------------------------------------------

        /// <summary>
        /// Pins the rule's telemetry domains in the hosts file under a marker
        /// line carrying the rule id. For targets like ultralytics this is
        /// functionally free — its telemetry POST swallows network errors — but it
        /// is system-wide for the domain, so browsers' requests to it fail too.
        /// Pass <paramref name="addressOverride"/> ("127.0.0.1") to pin in
        /// sinkhole mode so AutoScope's Black Hole tab can log each attempt.
        /// </summary>
        public async Task<(bool Success, string Message)> ApplyEnforceAsync(TelemetryRule rule, string addressOverride = null)
        {
            if (rule?.Enforce == null) return (false, "Rule has no network-block action.");
            if (!string.Equals(rule.Enforce.Type, "hosts", StringComparison.OrdinalIgnoreCase))
                return (false, $"Unknown enforcement type '{rule.Enforce.Type}'.");
            if (rule.Enforce.Domains.Count == 0) return (false, "Rule lists no domains to block.");

            try
            {
                if (HostsBlockActive(rule))
                    return (true, $"{rule.AppName}: network block already in place.");

                string hosts = HostsPath();
                var lines = File.Exists(hosts)
                    ? File.ReadAllLines(hosts).ToList()
                    : new List<string>();
                if (lines.Count > 0 && lines[^1].Trim().Length > 0) lines.Add("");
                lines.Add($"{HostsMarkerPrefix}{rule.Id}");
                lines.AddRange(rule.Enforce.Domains.Select(d =>
                    $"{NormalizePinAddress(addressOverride ?? rule.Enforce.Address)} {d}"));
                File.WriteAllLines(hosts, lines);

                RecordChange(rule.Id, "hosts", hosts, rule.Id, null);
                await FlushDnsCacheAsync();
                return (true,
                    $"{rule.AppName}: {rule.Enforce.Domains.Count} domain(s) pinned to 0.0.0.0 in the hosts file " +
                    "and the DNS cache flushed. The block is system-wide and reversible from this page.");
            }
            catch (UnauthorizedAccessException)
            {
                return (false, "The hosts file refused the write — the app must run elevated to block at the network level.");
            }
            catch (Exception ex)
            {
                return (false, $"Network block failed: {ex.Message}");
            }
        }

        public async Task<(bool Success, string Message)> RevertEnforceAsync(TelemetryRule rule)
        {
            if (rule?.Enforce == null) return (false, "Rule has no network-block action.");
            try
            {
                string hosts = HostsPath();
                if (!File.Exists(hosts) || !HostsBlockActive(rule))
                    return (true, $"{rule.AppName}: no network block present.");

                var blockedHosts = rule.Enforce.Domains.ToHashSet(StringComparer.OrdinalIgnoreCase);
                var lines = File.ReadAllLines(hosts).ToList();
                for (int i = 0; i < lines.Count; )
                {
                    if (IsMarkerForRule(lines[i].Trim(), rule.Id))
                    {
                        lines.RemoveAt(i);
                        // Match "<address> <hostname>" for the rule's domains at
                        // any address — the sinkhole toggle in AutoScope may
                        // have rewritten 0.0.0.0 to 127.0.0.1 since this block
                        // was written, and revert must still clean it up.
                        while (i < lines.Count)
                        {
                            var parts = lines[i].Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length == 2 && blockedHosts.Contains(parts[1])) lines.RemoveAt(i);
                            else break;
                        }
                    }
                    else i++;
                }
                File.WriteAllLines(hosts, lines);

                _changes.RemoveAll(c => c.RuleId == rule.Id && c.Kind == "hosts");
                SaveChanges();
                await FlushDnsCacheAsync();
                return (true, $"{rule.AppName}: network block removed and DNS cache flushed.");
            }
            catch (Exception ex)
            {
                return (false, $"Removing the network block failed: {ex.Message}");
            }
        }

        private static string HostsPath()
        {
            string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            if (string.IsNullOrEmpty(system))
                system = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows\System32";
            return Path.Combine(system, "drivers", "etc", "hosts");
        }

        /// <summary>
        /// Pins may only ever target 0.0.0.0 (silent) or 127.0.0.1 (sinkhole) —
        /// a hand-edited or tampered rules file must not be able to redirect a
        /// telemetry domain to an arbitrary address.
        /// </summary>
        private static string NormalizePinAddress(string address) =>
            string.Equals(address?.Trim(), "127.0.0.1", StringComparison.OrdinalIgnoreCase)
                ? "127.0.0.1"
                : "0.0.0.0";

        private static bool HostsBlockActive(TelemetryRule rule)
        {
            try
            {
                string hosts = HostsPath();
                if (!File.Exists(hosts)) return false;
                return File.ReadLines(hosts).Any(l => IsMarkerForRule(l.Trim(), rule.Id));
            }
            catch { return false; }
        }

        /// <summary>Matches a marker line from either app for the given rule id.</summary>
        private static bool IsMarkerForRule(string line, string ruleId) =>
            AllMarkerPrefixes.Any(p => string.Equals(line, p + ruleId, StringComparison.OrdinalIgnoreCase));

        private static async Task FlushDnsCacheAsync()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "ipconfig.exe",
                    Arguments = "/flushdns",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                };
                using var p = Process.Start(psi);
                if (p != null) await p.WaitForExitAsync();
            }
            catch { /* best-effort — the pin applies on next resolution regardless */ }
        }

        /// <summary>
        /// Checks the DNS resolver cache for a telemetry domain — the cheap
        /// "is it still beaconing?" test, mirroring a manual
        /// Get-DnsClientCache inspection.
        /// </summary>
        public async Task<bool> CheckRecentDnsLookupAsync(string domain)
        {
            var ps = $"if (Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object {{ $_.Entry -like '*{domain}*' }}) {{ 'SEEN' }} else {{ 'CLEAN' }}";
            var (output, _, _) = await ProcessRunner.RunWithDetailsAsync("powershell.exe",
                $"-NoProfile -NonInteractive -Command \"{ps}\"");
            return (output ?? string.Empty).Trim().EndsWith("SEEN", StringComparison.Ordinal);
        }

        // -----------------------------------------------------------------------
        // Primitive readers/writers
        // -----------------------------------------------------------------------

        private static string Expand(string path) =>
            Environment.ExpandEnvironmentVariables(path ?? string.Empty);

        private static JsonNode ReadJsonKey(string path, string key)
        {
            var root = JsonNode.Parse(File.ReadAllText(path))?.AsObject();
            return root != null && root.ContainsKey(key) ? root[key] : null;
        }

        /// <summary>Writes a value as a typed JSON token, preserving token type (true vs "true").</summary>
        private static void WriteJsonNode(string path, string key, JsonNode value)
        {
            var root = (JsonNode.Parse(File.ReadAllText(path)) as JsonObject) ?? new JsonObject();
            root[key] = value.DeepClone();
            File.WriteAllText(path, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }

        private static void WriteJsonKey(string path, string key, string value) =>
            WriteJsonNode(path, key, JsonValue.Create(value));

        /// <summary>Historic snapshots stored bare text; parse as a token and fall back to a string.</summary>
        private static JsonNode SafeParseNode(string snapshot) 
        {
            try { return JsonNode.Parse(snapshot); }
            catch { return JsonValue.Create(snapshot); }
        }

        /// <summary>Builds the JSON token to write from a rule's value + declared value type.</summary>
        private static JsonNode ParseOptOutValue(OptOutSpec optOut)
        {
            string type = optOut.ValueType?.Trim().ToLowerInvariant();
            try
            {
                return type switch
                {
                    "bool" => JsonValue.Create(bool.Parse(optOut.Value)),
                    "number" => JsonValue.Create(double.Parse(optOut.Value, CultureInfo.InvariantCulture)),
                    _ => JsonValue.Create(optOut.Value),
                };
            }
            catch (FormatException)
            {
                // A rule declaring bool/number with unparseable text is a KB bug;
                // write it as the string it literally says rather than failing the opt-out.
                return JsonValue.Create(optOut.Value);
            }
        }

        private static void RemoveJsonKey(string path, string key)
        {
            if (!File.Exists(path)) return;
            if (JsonNode.Parse(File.ReadAllText(path)) is not JsonObject root) return;
            root.Remove(key);
            File.WriteAllText(path, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }

        private static string ReadRegistry(string regKey, string name)
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(StripHklm(regKey));
            return key?.GetValue(name)?.ToString();
        }

        private static void WriteRegistry(string regKey, string name, string value, bool dword)
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(StripHklm(regKey));
            if (dword && int.TryParse(value, out int number))
                key.SetValue(name, number, Microsoft.Win32.RegistryValueKind.DWord);
            else
                key.SetValue(name, value, Microsoft.Win32.RegistryValueKind.String);
        }

        private static void DeleteRegistryValue(string regKey, string name)
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(StripHklm(regKey), writable: true);
            key?.DeleteValue(name, throwOnMissingValue: false);
        }

        private static string StripHklm(string regKey) =>
            regKey.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase)
                ? regKey[5..]
                : regKey;

        // -----------------------------------------------------------------------
        // Snapshot persistence (telemetry_state.json)
        // -----------------------------------------------------------------------

        private void RecordChange(string ruleId, string kind, string target, string name, string previousValue)
        {
            // One snapshot per rule AND kind — a rule can hold both an opt-out
            // revert snapshot and an active network block at the same time
            _changes.RemoveAll(c => c.RuleId == ruleId && c.Kind == kind);
            _changes.Add(new ChangeRecord
            {
                RuleId = ruleId,
                Kind = kind,
                Target = target,
                Name = name,
                PreviousValue = previousValue,
                ChangedAt = DateTime.Now
            });
            SaveChanges();
        }

        private void LoadChanges()
        {
            try
            {
                if (File.Exists(StateFile))
                    _changes = JsonSerializer.Deserialize<List<ChangeRecord>>(File.ReadAllText(StateFile)) ?? new();
            }
            catch { _changes = new(); }
        }

        private void SaveChanges()
        {
            try
            {
                File.WriteAllText(StateFile, JsonSerializer.Serialize(_changes,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* best-effort — the changed setting itself persists */ }
        }
    }
}
