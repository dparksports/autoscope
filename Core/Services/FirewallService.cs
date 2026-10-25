using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// Native Windows Firewall management via INetFwPolicy2 COM.
    /// Replaces all PowerShell Get-NetFirewallRule / Set-NetFirewallRule calls.
    /// Uses dynamic COM — no COM reference DLL needed.
    /// </summary>
    public class FirewallService
    {
        private static FirewallService _instance;
        public static FirewallService Instance => _instance ??= new FirewallService();

        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)]
        private static extern int SHLoadIndirectString(string pszSource, StringBuilder pszOutBuf, int cchOutBuf, IntPtr ppvReserved);

        private static readonly Dictionary<string, string> GroupNameCache = new Dictionary<string, string>(StringComparer.Ordinal);

        /// <summary>
        /// COM's INetFwRule.Grouping returns indirect resource strings (e.g. "@FirewallAPI.dll,-32752"),
        /// not the localized display names ("Network Discovery") that the profile presets use.
        /// </summary>
        public static string ResolveGroupName(string grouping)
        {
            if (string.IsNullOrEmpty(grouping) || grouping[0] != '@') return grouping;
            lock (GroupNameCache)
            {
                if (GroupNameCache.TryGetValue(grouping, out string cached)) return cached;
                string resolved = grouping;
                var sb = new StringBuilder(512);
                if (SHLoadIndirectString(grouping, sb, sb.Capacity, IntPtr.Zero) == 0 && sb.Length > 0)
                    resolved = sb.ToString();
                GroupNameCache[grouping] = resolved;
                return resolved;
            }
        }

        /// <summary>
        /// Case-insensitive group match against both the raw Grouping string and its resolved display name.
        /// </summary>
        private static bool GroupMatches(string ruleGrouping, string targetName)
        {
            if (string.IsNullOrEmpty(ruleGrouping) || string.IsNullOrEmpty(targetName)) return false;
            if (string.Equals(ruleGrouping, targetName, StringComparison.OrdinalIgnoreCase)) return true;
            return string.Equals(ResolveGroupName(ruleGrouping), targetName, StringComparison.OrdinalIgnoreCase);
        }

        private dynamic GetPolicy()
        {
            Type fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (fwPolicyType == null)
                throw new InvalidOperationException("Windows Firewall COM component not available.");
            return Activator.CreateInstance(fwPolicyType);
        }

        /// <summary>
        /// Load all firewall rules for a given direction using COM API.
        /// direction: 1 = Inbound, 2 = Outbound
        /// </summary>
        public Task<List<FirewallRuleItem>> LoadRulesAsync(int direction)
        {
            return Task.Run(() =>
            {
                var results = new List<FirewallRuleItem>();
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        try
                        {
                            int ruleDir = (int)rule.Direction;
                            if (ruleDir != direction) continue;

                            string grouping = ResolveGroupName((string)rule.Grouping) ?? "";
                            results.Add(new FirewallRuleItem
                            {
                                Name = rule.Name ?? "",
                                DisplayName = rule.Name ?? "",
                                DisplayGroup = string.IsNullOrEmpty(grouping) ? "(Ungrouped)" : grouping,
                                Direction = direction == 1 ? "Inbound" : "Outbound",
                                Enabled = (bool)rule.Enabled,
                                Action = ((int)rule.Action) == 1 ? "Allow" : "Block",
                                Profile = DecodeProfile((int)rule.Profiles),
                                Program = rule.ApplicationName ?? "",
                                Protocol = DecodeProtocol((int)rule.Protocol),
                                LocalPort = rule.LocalPorts ?? "",
                                RemotePort = rule.RemotePorts ?? "",
                                RemoteAddress = rule.RemoteAddresses ?? ""
                            });
                        }
                        catch
                        {
                            // Skip rules that can't be read
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"FirewallService.LoadRules Error: {ex.Message}");
                }
                return results;
            });
        }

        /// <summary>
        /// Toggle a single rule's enabled state via COM.
        /// </summary>
        public Task ToggleRuleAsync(string ruleName, bool enabled)
        {
            return Task.Run(() =>
            {
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        try
                        {
                            if ((string)rule.Name == ruleName)
                            {
                                rule.Enabled = enabled;
                            }
                        }
                        catch { }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"FirewallService.ToggleRule Error: {ex.Message}");
                }
            });
        }

        /// <summary>
        /// Outcome of a group-wide enable/disable so callers can show what actually happened.
        /// </summary>
        public class GroupToggleResult
        {
            public string GroupName { get; set; }
            public int Matched { get; set; }
            public int Changed { get; set; }
            public int Failed { get; set; }
            public string FirstError { get; set; }
            public bool FailedCompletely { get; set; }
            public string Notes { get; set; }
        }

        /// <summary>
        /// Toggle all rules in a group. Matches the raw Grouping string and its resolved display name.
        /// </summary>
        public Task<GroupToggleResult> ToggleGroupAsync(string groupName, bool enabled)
        {
            return Task.Run(() =>
            {
                var result = new GroupToggleResult { GroupName = groupName };
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        string ruleGroup;
                        bool wasEnabled;
                        try
                        {
                            ruleGroup = rule.Grouping ?? "";
                            wasEnabled = (bool)rule.Enabled;
                        }
                        catch
                        {
                            continue; // Rule unreadable — skip as before
                        }

                        bool matches = (string.IsNullOrEmpty(ruleGroup) && groupName == "(Ungrouped)")
                                       || GroupMatches(ruleGroup, groupName);
                        if (!matches) continue;

                        result.Matched++;
                        try
                        {
                            rule.Enabled = enabled;
                            if (wasEnabled != enabled) result.Changed++;
                        }
                        catch (Exception ex)
                        {
                            result.Failed++;
                            if (result.FirstError == null) result.FirstError = ex.Message;
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.FailedCompletely = true;
                    result.FirstError = ex.Message;
                }
                return result;
            });
        }

        /// <summary>
        /// Reset the firewall to the Windows default rule set (the COM equivalent of
        /// `netsh advfirewall reset`), then disable every remaining rule so both all
        /// inbound and all outbound traffic is blocked. Non-default rules — including
        /// AutoScope's own AS-BLOCK rules — do not survive the reset.
        /// </summary>
        public Task<GroupToggleResult> ResetToDefaultsAndLockdownAsync(IProgress<string> progress = null)
        {
            return Task.Run(() =>
            {
                var result = new GroupToggleResult { GroupName = "Lockdown (reset to defaults)" };
                try
                {
                    dynamic fwPolicy = GetPolicy();

                    int beforeCount = 0;
                    try { beforeCount = (int)fwPolicy.Rules.Count; } catch { }

                    progress?.Report("Restoring Windows default firewall rules…");
                    fwPolicy.RestoreLocalFirewallDefaults();

                    int afterCount = 0;
                    try { afterCount = (int)fwPolicy.Rules.Count; } catch { }
                    int removed = Math.Max(0, beforeCount - afterCount);

                    progress?.Report("Defaults restored — disabling every inbound and outbound rule…");

                    int disabledCount = 0;
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        bool wasEnabled;
                        try
                        {
                            wasEnabled = (bool)rule.Enabled;
                        }
                        catch
                        {
                            continue; // Rule unreadable — skip as before
                        }

                        result.Matched++;
                        try
                        {
                            rule.Enabled = false;
                            if (wasEnabled)
                            {
                                result.Changed++;
                                disabledCount++;
                            }
                        }
                        catch (Exception ex)
                        {
                            result.Failed++;
                            if (result.FirstError == null) result.FirstError = ex.Message;
                        }
                    }

                    result.Notes = $"Windows default rule set restored ({removed} non-default rule(s) removed); "
                                 + $"{disabledCount} rule(s) disabled — all inbound and outbound traffic is now blocked.";
                }
                catch (Exception ex)
                {
                    result.FailedCompletely = true;
                    result.FirstError = ex.Message;
                }
                return result;
            });
        }

        /// <summary>
        /// Get summary counts.
        /// </summary>
        public Task<(int TotalInbound, int EnabledInbound, int TotalOutbound, int EnabledOutbound)> GetSummaryAsync()
        {
            return Task.Run(() =>
            {
                int totalIn = 0, enabledIn = 0, totalOut = 0, enabledOut = 0;
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        try
                        {
                            int dir = (int)rule.Direction;
                            bool en = (bool)rule.Enabled;
                            if (dir == 1) { totalIn++; if (en) enabledIn++; }
                            else { totalOut++; if (en) enabledOut++; }
                        }
                        catch { }
                    }
                }
                catch { }
                return (totalIn, enabledIn, totalOut, enabledOut);
            });
        }

        /// <summary>
        /// Check if specific rules match their expected config state (for drift detection).
        /// Returns list of drifted rule names.
        /// </summary>
        public Task<List<string>> CheckDriftAsync(Dictionary<string, string> overrides)
        {
            return Task.Run(() =>
            {
                var drifted = new List<string>();
                if (overrides == null || overrides.Count == 0) return drifted;

                try
                {
                    dynamic fwPolicy = GetPolicy();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        try
                        {
                            string name = (string)rule.Name;
                            if (overrides.TryGetValue(name, out string expected))
                            {
                                bool actual = (bool)rule.Enabled;
                                bool expectedBool = expected == "True";
                                if (actual != expectedBool)
                                {
                                    drifted.Add($"{name} (Expected: {expected}, Actual: {(actual ? "True" : "False")})");
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
                return drifted;
            });
        }

        /// <summary>
        /// Adds inbound and outbound block rules for a specific application path.
        /// </summary>
        public Task AddBlockRuleForAppAsync(string appPath, string ruleName)
        {
            return Task.Run(() =>
            {
                try
                {
                    Type ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                    
                    // Outbound block
                    dynamic ruleOut = Activator.CreateInstance(ruleType);
                    ruleOut.Action = 0; // NET_FW_ACTION_BLOCK
                    ruleOut.Description = "AutoScope User Block";
                    ruleOut.Direction = 2; // NET_FW_RULE_DIR_OUT
                    ruleOut.Enabled = true;
                    ruleOut.InterfaceTypes = "All";
                    ruleOut.Name = $"{ruleName} (Outbound Block)";
                    ruleOut.ApplicationName = appPath;

                    // Inbound block
                    dynamic ruleIn = Activator.CreateInstance(ruleType);
                    ruleIn.Action = 0; // NET_FW_ACTION_BLOCK
                    ruleIn.Description = "AutoScope User Block";
                    ruleIn.Direction = 1; // NET_FW_RULE_DIR_IN
                    ruleIn.Enabled = true;
                    ruleIn.InterfaceTypes = "All";
                    ruleIn.Name = $"{ruleName} (Inbound Block)";
                    ruleIn.ApplicationName = appPath;

                    dynamic fwPolicy = GetPolicy();
                    fwPolicy.Rules.Add(ruleOut);
                    fwPolicy.Rules.Add(ruleIn);
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to add firewall rule: {ex.Message}", ex);
                }
            });
        }

        /// <summary>
        /// Adds TCP and UDP block rules (inbound and outbound) for a specific remote IP address.
        /// Legacy 4-rule scheme — creates rules with the caller-supplied name. Prefer
        /// AddIpBlockAsync for new blocks (2-rule v2 scheme, AS-BLOCK naming).
        /// </summary>
        public Task AddBlockRuleForIpAsync(string remoteIp, string ruleName)
        {
            return Task.Run(() =>
            {
                try
                {
                    Type ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                    dynamic fwPolicy = GetPolicy();
                    (int dir, string dirName)[] directions = new[] { (2, "Outbound"), (1, "Inbound") };
                    (int proto, string protoName)[] protocols = new[] { (6, "TCP"), (17, "UDP") };

                    foreach (var (dir, dirName) in directions)
                    {
                        foreach (var (proto, protoName) in protocols)
                        {
                            dynamic rule = Activator.CreateInstance(ruleType);
                            rule.Action = 0; // NET_FW_ACTION_BLOCK
                            rule.Description = "AutoScope Remote IP Block";
                            rule.Direction = dir;
                            rule.Enabled = true;
                            rule.InterfaceTypes = "All";
                            rule.Name = $"{ruleName} ({protoName} {dirName} Block)";
                            rule.RemoteAddresses = remoteIp;
                            rule.Protocol = proto;
                            fwPolicy.Rules.Add(rule);
                        }
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to add firewall rule: {ex.Message}", ex);
                }
            });
        }

        /// <summary>
        /// Removes the block rules previously created for a remote IP by
        /// AddBlockRuleForIpAsync (matched on the "AutoScope IP Block - &lt;ip&gt;" name prefix).
        /// Returns how many rules were removed.
        /// </summary>
        public Task<int> RemoveBlockRulesForIpAsync(string remoteIp)
        {
            return Task.Run(() =>
                RemoveRulesByNamePrefix($"AutoScope IP Block - {remoteIp} (") +
                RemoveRulesByNamePrefix($"{NewIpPrefix}{remoteIp} ("));
        }

        /// <summary>
        /// Removes the inbound/outbound block rules previously created for an
        /// application path (matched on the rule name prefix used by the
        /// monitor views plus the exact ApplicationName). Returns the removal count.
        /// </summary>
        public Task<int> RemoveBlockRulesForAppAsync(string appPath)
        {
            return Task.Run(() =>
            {
                int removed = 0;
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    var names = new List<string>();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        try
                        {
                            string name = rule.Name ?? "";
                            string app = rule.ApplicationName ?? "";
                            if ((name.StartsWith("AutoScope Process Block - ", StringComparison.OrdinalIgnoreCase) ||
                                 name.StartsWith(NewAppPrefix, StringComparison.OrdinalIgnoreCase)) &&
                                string.Equals(app, appPath, StringComparison.OrdinalIgnoreCase))
                            {
                                names.Add(name);
                            }
                        }
                        catch { }
                    }

                    foreach (string name in names)
                    {
                        try { fwPolicy.Rules.Remove(name); removed++; } catch { }
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to remove firewall rules: {ex.Message}", ex);
                }
                return removed;
            });
        }

        private int RemoveRulesByNamePrefix(string namePrefix)
        {
            int removed = 0;
            try
            {
                dynamic fwPolicy = GetPolicy();
                // Collect matches first — removing while enumerating the COM collection is unreliable
                var names = new List<string>();
                foreach (dynamic rule in fwPolicy.Rules)
                {
                    try
                    {
                        string name = rule.Name ?? "";
                        if (name.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase)) names.Add(name);
                    }
                    catch { }
                }

                foreach (string name in names)
                {
                    try { fwPolicy.Rules.Remove(name); removed++; } catch { }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to remove firewall rules: {ex.Message}", ex);
            }
            return removed;
        }

        // ── AutoScope-managed block fleet ────────────────────────────────
        //
        // v2 block rules are FEWER and SELF-DESCRIBING:
        //   IP:  2 rules (outbound TCP + UDP) — inbound blocks are redundant on
        //        a client; unsolicited inbound is already dropped by the
        //        firewall's stateful defaults.
        //   APP: 1 outbound rule.
        // Names are deterministic ("AS-BLOCK-IP <ip> (TCP Out)") which makes
        // creation idempotent and lets wf.msc users sort/filter by "AS-BLOCK".
        // The Description field carries full provenance (process, PID, host,
        // byte counts, UTC time) — that's the audit trail visible in wf.msc.

        public const string NewIpPrefix = "AS-BLOCK-IP ";
        public const string NewAppPrefix = "AS-BLOCK-APP ";
        private static readonly string[] LegacyIpPrefix = { "AutoScope IP Block - " };
        private static readonly string[] LegacyAppPrefix = { "AutoScope Process Block - " };

        public class BlockedTarget
        {
            public string Target;      // IP or exe name for display
            public string Kind;        // "ip" | "app"
            public string Key;         // grouping key (ip or lowercased full path)
            public string AppPath;
            public string Ip;
            public int Rules;
            public int EnabledRules;
            public string Description = "";
            public string Class;       // Microsoft/Azure, Akamai, Gcore, Windows component, Application, Unclassified
            public DateTime? Created;  // parsed from v2 description; null for legacy rules
        }

        public class FleetToggleResult { public int Matched; public int Changed; public int SkippedRisky; public string FirstError; }

        /// <summary>
        /// Shared parser: extracts the IP from a v2 or legacy IP-block rule name.
        /// ("AS-BLOCK-IP 1.2.3.4 (TCP Out)" / "AutoScope IP Block - 1.2.3.4 (…)")
        /// </summary>
        private static string ParseIpTarget(string name)
        {
            string prefix = name.StartsWith(NewIpPrefix, StringComparison.OrdinalIgnoreCase)
                ? NewIpPrefix : LegacyIpPrefix[0];
            int cut = name.IndexOf('(');
            return (cut > 0 ? name.Substring(prefix.Length, cut - prefix.Length)
                            : name.Substring(prefix.Length)).Trim();
        }

        /// <summary>
        /// A rule is "risky" when its target is Microsoft/CDN infrastructure or a
        /// Windows component — re-enabling those is what re-breaks internet,
        /// updates or notifications after a panic restore.
        /// </summary>
        private static bool IsRiskyRule(string name, dynamic rule)
        {
            try
            {
                if (name.StartsWith(NewIpPrefix, StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith(LegacyIpPrefix[0], StringComparison.OrdinalIgnoreCase))
                    return Services.IpClassifier.IsMicrosoftInfra(ParseIpTarget(name));
                string app = rule.ApplicationName ?? "";
                return app.Length > 0 && app.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        private static dynamic FindRule(dynamic fwPolicy, string name)
        {
            foreach (dynamic r in fwPolicy.Rules)
            {
                try { if ((string)r.Name == name) return r; } catch { }
            }
            return null;
        }

        private static bool IsOurBlock(dynamic rule, out string name)
        {
            name = null;
            try
            {
                name = (string)rule.Name ?? "";
                if ((int)rule.Action != 0) return false; // Block only
                return name.StartsWith(NewIpPrefix, StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith(NewAppPrefix, StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith(LegacyIpPrefix[0], StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith(LegacyAppPrefix[0], StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>Add a 2-rule (outbound TCP+UDP) idempotent IP block with full provenance.</summary>
        public Task<(int created, int updated)> AddIpBlockAsync(string ip, string description)
        {
            return Task.Run(() =>
            {
                int created = 0, updated = 0;
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    foreach (var (proto, suffix) in new[] { (6, "TCP Out"), (17, "UDP Out") })
                    {
                        string name = $"{NewIpPrefix}{ip} ({suffix})";
                        dynamic existing = FindRule(fwPolicy, name);
                        if (existing != null)
                        {
                            try { existing.Description = description; updated++; } catch { }
                            continue;
                        }
                        dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                        rule.Action = 0; rule.Direction = 2; rule.Enabled = true;
                        rule.InterfaceTypes = "All";
                        rule.Name = name; rule.RemoteAddresses = ip; rule.Protocol = proto;
                        rule.Description = description;
                        fwPolicy.Rules.Add(rule);
                        created++;
                    }
                }
                catch (Exception ex) { throw new Exception($"Failed to add IP block: {ex.Message}", ex); }
                return (created, updated);
            });
        }

        /// <summary>Add a 1-rule (outbound) idempotent app block with full provenance.</summary>
        public Task<(int created, int updated)> AddAppBlockAsync(string appPath, string description)
        {
            return Task.Run(() =>
            {
                int created = 0, updated = 0;
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    string name = $"{NewAppPrefix}{System.IO.Path.GetFileName(appPath)} (Out)";
                    dynamic existing = FindRule(fwPolicy, name);
                    if (existing != null)
                    {
                        try { existing.Description = description; updated++; } catch { }
                        return (0, 1);
                    }
                    dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                    rule.Action = 0; rule.Direction = 2; rule.Enabled = true;
                    rule.InterfaceTypes = "All";
                    rule.Name = name; rule.ApplicationName = appPath;
                    rule.Description = description;
                    fwPolicy.Rules.Add(rule);
                    created = 1;
                }
                catch (Exception ex) { throw new Exception($"Failed to add app block: {ex.Message}", ex); }
                return (created, updated);
            });
        }

        /// <summary>
        /// Emergency internet restore / re-enable. With skipRisky=true, rules
        /// targeting Microsoft/CDN infrastructure or Windows components are left
        /// in their current state — that's the "restore everything except the
        /// problematic ones" path after a panic disable.
        /// </summary>
        public Task<FleetToggleResult> SetAllAutoScopeBlocksEnabledAsync(bool enabled, bool skipRisky = false)
        {
            return Task.Run(() =>
            {
                var result = new FleetToggleResult();
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        if (!IsOurBlock(rule, out string name)) continue;
                        if (skipRisky && enabled && IsRiskyRule(name, rule))
                        {
                            result.SkippedRisky++;
                            continue;
                        }
                        result.Matched++;
                        try
                        {
                            bool was = (bool)rule.Enabled;
                            rule.Enabled = enabled;
                            if (was != enabled) result.Changed++;
                        }
                        catch (Exception ex) { if (result.FirstError == null) result.FirstError = ex.Message; }
                    }
                }
                catch (Exception ex) { result.FirstError = ex.Message; }
                return result;
            });
        }

        /// <summary>
        /// Per-target (and per-group, via a list) enable/disable — the toggle
        /// behind the Blocks tab. Matching mirrors removal: IP blocks by rule
        /// name prefix (new v2 + legacy), app blocks by name prefix plus exact
        /// ApplicationName. Returns (rules matched, rules actually flipped).
        /// </summary>
        public Task<(int matched, int changed)> SetTargetsEnabledAsync(
            IEnumerable<(string kind, string key)> targets, bool enabled)
        {
            return Task.Run(() =>
            {
                int matched = 0, changed = 0;
                try
                {
                    var list = targets.ToList();
                    var ipPrefixes = list.Where(t => t.kind == "ip")
                        .Select(t => new[]
                        {
                            $"{NewIpPrefix}{t.key} (",
                            $"{LegacyIpPrefix[0]}{t.key} ("
                        })
                        .SelectMany(p => p)
                        .ToList();
                    var appPaths = new HashSet<string>(
                        list.Where(t => t.kind != "ip").Select(t => t.key),
                        StringComparer.OrdinalIgnoreCase);

                    dynamic fwPolicy = GetPolicy();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        try
                        {
                            if (!IsOurBlock(rule, out string name)) continue;

                            bool isIpRule = name.StartsWith(NewIpPrefix, StringComparison.OrdinalIgnoreCase) ||
                                            name.StartsWith(LegacyIpPrefix[0], StringComparison.OrdinalIgnoreCase);
                            if (isIpRule)
                            {
                                if (!ipPrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                                    continue;
                            }
                            else
                            {
                                string app = rule.ApplicationName ?? "";
                                if (app.Length == 0 || !appPaths.Contains(app)) continue;
                            }

                            matched++;
                            bool was = (bool)rule.Enabled;
                            rule.Enabled = enabled;
                            if (was != enabled) changed++;
                        }
                        catch { /* per-rule best effort */ }
                    }
                }
                catch { /* caller surfaces the zero-change result */ }
                return (matched, changed);
            });
        }

        /// <summary>Inventory of all AutoScope block rules, grouped per target, classified.</summary>
        public Task<List<BlockedTarget>> GetBlockedInventoryAsync()
        {
            return Task.Run(() =>
            {
                var byKey = new Dictionary<string, BlockedTarget>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        if (!IsOurBlock(rule, out string name)) continue;
                        try
                        {
                            string desc = rule.Description ?? "";
                            bool enabled = (bool)rule.Enabled;
                            string app = rule.ApplicationName ?? "";

                            BlockedTarget t = null;
                            if (name.StartsWith(NewIpPrefix, StringComparison.OrdinalIgnoreCase) ||
                                name.StartsWith(LegacyIpPrefix[0], StringComparison.OrdinalIgnoreCase))
                            {
                                string ip = ParseIpTarget(name);
                                string key = "ip:" + ip;
                                if (!byKey.TryGetValue(key, out t))
                                    byKey[key] = t = new BlockedTarget
                                    {
                                        Kind = "ip", Key = key, Ip = ip, Target = ip,
                                        Class = Services.IpClassifier.Classify(ip),
                                    };
                            }
                            else
                            {
                                string path = !string.IsNullOrEmpty(app) ? app : name;
                                string key = "app:" + path.ToLowerInvariant();
                                if (!byKey.TryGetValue(key, out t))
                                    byKey[key] = t = new BlockedTarget
                                    {
                                        Kind = "app", Key = key, AppPath = path,
                                        Target = System.IO.Path.GetFileName(path),
                                        Class = IsWindowsComponent(path) ? "Windows component ⚠" : "Application",
                                    };
                            }
                            t.Rules++;
                            if (enabled) t.EnabledRules++;
                            if (string.IsNullOrEmpty(t.Description)) t.Description = desc;
                            if (!t.Created.HasValue) t.Created = ParseBlockedTime(desc);
                        }
                        catch { }
                    }
                }
                catch { }
                return byKey.Values.OrderByDescending(t => t.Class).ThenBy(t => t.Target).ToList();
            });
        }

        /// <summary>
        /// One-click cleanup of ALL legacy-name blocks: IP sets (4 rules) shrink
        /// to the v2 2-rule scheme, app blocks (2 rules) shrink to the v2 single
        /// outbound rule. Lossless — descriptions carry over with a migration
        /// marker, protection unchanged (inbound was covered by stateful filtering).
        /// Safe to run repeatedly; exits fast when nothing legacy remains.
        /// </summary>
        public Task<(int targets, int removedInbound, int migratedOutbound)> ConsolidateLegacyIpBlocksAsync()
        {
            return Task.Run(() =>
            {
                int targets = 0, removed = 0, migrated = 0;
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    var legacy = new List<(string name, dynamic rule, string ip)>();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        try
                        {
                            string name = (string)rule.Name ?? "";
                            if ((int)rule.Action != 0 || !name.StartsWith(LegacyIpPrefix[0], StringComparison.OrdinalIgnoreCase)) continue;
                            string ip = ParseIpTarget(name);
                            legacy.Add((name, rule, ip));
                        }
                        catch { }
                    }

                    foreach (var ipGroup in legacy.GroupBy(x => x.ip))
                    {
                        targets++;
                        foreach (var (name, rule, ip) in ipGroup)
                        {
                            if (name.Contains("Inbound"))
                            {
                                try { fwPolicy.Rules.Remove(name); removed++; } catch { }
                            }
                            else
                            {
                                // rewrite under v2 name: copy-create-remove (COM rename is unreliable)
                                try
                                {
                                    string proto = name.Contains("UDP") ? "UDP" : "TCP";
                                    string newName = $"{NewIpPrefix}{ip} ({proto} Out)";
                                    if (FindRule(fwPolicy, newName) == null)
                                    {
                                        dynamic nr = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                                        nr.Action = 0; nr.Direction = 2; nr.Enabled = true;
                                        nr.InterfaceTypes = "All";
                                        nr.Name = newName; nr.RemoteAddresses = ip;
                                        nr.Protocol = name.Contains("UDP") ? 17 : 6;
                                        nr.Description = (rule.Description ?? "") + " [migrated from AutoScope legacy rule]";
                                        fwPolicy.Rules.Add(nr);
                                    }
                                    fwPolicy.Rules.Remove(name);
                                    migrated++;
                                }
                                catch { }
                            }
                        }
                    }

                    // ── legacy app blocks: 2 rules → 1 outbound v2 rule ──
                    var legacyApps = new List<(string name, dynamic rule, string app)>();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        try
                        {
                            string name = (string)rule.Name ?? "";
                            if ((int)rule.Action != 0 || !name.StartsWith(LegacyAppPrefix[0], StringComparison.OrdinalIgnoreCase)) continue;
                            string app = rule.ApplicationName ?? "";
                            if (app.Length == 0) continue;
                            legacyApps.Add((name, rule, app));
                        }
                        catch { }
                    }

                    foreach (var appGroup in legacyApps.GroupBy(x => x.app, StringComparer.OrdinalIgnoreCase))
                    {
                        targets++;
                        foreach (var (name, rule, app) in appGroup)
                        {
                            if (name.Contains("Inbound"))
                            {
                                try { fwPolicy.Rules.Remove(name); removed++; } catch { }
                            }
                            else
                            {
                                try
                                {
                                    string newName = $"{NewAppPrefix}{System.IO.Path.GetFileName(app)} (Out)";
                                    if (FindRule(fwPolicy, newName) == null)
                                    {
                                        dynamic nr = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                                        nr.Action = 0; nr.Direction = 2; nr.Enabled = true;
                                        nr.InterfaceTypes = "All";
                                        nr.Name = newName; nr.ApplicationName = app;
                                        nr.Description = (rule.Description ?? "") + " [migrated from AutoScope legacy rule]";
                                        fwPolicy.Rules.Add(nr);
                                    }
                                    fwPolicy.Rules.Remove(name);
                                    migrated++;
                                }
                                catch { }
                            }
                        }
                    }
                }
                catch { }
                return (targets, removed, migrated);
            });
        }

        /// <summary>Count of legacy-name block rules still in the firewall (0 after migration).</summary>
        public Task<int> CountLegacyBlocksAsync()
        {
            return Task.Run(() =>
            {
                int count = 0;
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        try
                        {
                            if ((int)rule.Action != 0) continue;
                            string name = (string)rule.Name ?? "";
                            if (name.StartsWith(LegacyIpPrefix[0], StringComparison.OrdinalIgnoreCase) ||
                                name.StartsWith(LegacyAppPrefix[0], StringComparison.OrdinalIgnoreCase))
                                count++;
                        }
                        catch { }
                    }
                }
                catch { }
                return count;
            });
        }

        public sealed class FirewallLogHit
        {
            public int Count;
            public DateTime FirstSeen, LastSeen;
            public HashSet<string> Processes = new(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Recent DROP hits from the firewall log, per destination IP with first/last
        /// seen and the process paths the log carries. Empty when drop-logging is off
        /// (the default) — the process-attributed live source is BlockHitFeedService.
        /// pfirewall.log format: date time DROP proto src sport DST dport size … info PATH
        /// — the trailing token group starting at a "X:\\" marker is the program.
        /// </summary>
        public static Dictionary<string, FirewallLogHit> GetRecentLogHits(int minutes)
        {
            var hits = new Dictionary<string, FirewallLogHit>(StringComparer.OrdinalIgnoreCase);
            try
            {
                string log = Environment.SystemDirectory + @"\LogFiles\Firewall\pfirewall.log";
                if (!System.IO.File.Exists(log)) return hits;
                var cutoff = DateTime.Now.AddMinutes(-minutes);
                foreach (var line in System.IO.File.ReadLines(log))
                {
                    // 2026-10-10  14:22:31  DROP  TCP  src  port  dst  port ...
                    if (!line.Contains("DROP")) continue;
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 8) continue;
                    if (!DateTime.TryParse(parts[0] + " " + parts[1], out DateTime ts) || ts < cutoff) continue;
                    if (!System.Net.IPAddress.TryParse(parts[6], out var dst)) continue;

                    var h = hits.TryGetValue(parts[6], out var existing) ? existing
                        : hits[parts[6]] = new FirewallLogHit { FirstSeen = ts, LastSeen = ts };
                    h.Count++;
                    if (ts < h.FirstSeen) h.FirstSeen = ts;
                    if (ts > h.LastSeen) h.LastSeen = ts;

                    for (int i = 8; i < parts.Length; i++)
                    {
                        if (parts[i].Length > 3 && parts[i][1] == ':' && parts[i][2] == '\\')
                        {
                            h.Processes.Add(string.Join(' ', parts.Skip(i)));
                            break;
                        }
                    }
                }
            }
            catch { }
            return hits;
        }

        public static bool FirewallDropLoggingOn()
        {
            // INetFwPolicy2.FirewallProfile is a parameterized COM property — the
            // .NET dynamic binder cannot dispatch it (verified: RuntimeBinderException),
            // so detection reads the registry keys netsh/wf.msc write.
            try
            {
                const string baseKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
                foreach (string profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
                {
                    using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"{baseKey}\{profile}\Logging");
                    if (k?.GetValue("LogDroppedPackets") is int v && v == 1) return true;
                }
            }
            catch { }
            // A leftover file from a past enabled period is NOT evidence logging is
            // on — treating it as such hides the enable button while no rows accrue.
            try
            {
                string log = Environment.SystemDirectory + @"\LogFiles\Firewall\pfirewall.log";
                return System.IO.File.Exists(log) &&
                       System.IO.File.GetLastWriteTime(log) > DateTime.Now.AddDays(-1);
            }
            catch { return false; }
        }

        /// <summary>
        /// One-shot at startup: turn on "log dropped packets" so the firewall log
        /// feed works out of the box. Runs at most once EVER — a marker file is
        /// written either way, so a user who later disables logging is respected.
        /// </summary>
        public static void EnsureDropLoggingOnce()
        {
            try
            {
                string marker = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "AutoScope", "drop-log-autoenabled.marker");
                if (System.IO.File.Exists(marker)) return;
                string err = FirewallDropLoggingOn() ? null : SetDropLogging(true);
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(marker));
                System.IO.File.WriteAllText(marker,
                    $"{DateTime.UtcNow:yyyy-MM-dd HH:mm} ensured{(err == null ? "" : $" (netsh failed: {err})")}");
            }
            catch { }
        }

        /// <summary>
        /// Enable/disable "log dropped packets" on all profiles via the documented
        /// netsh CLI (needs the app's elevated context). Returns null on success,
        /// otherwise the netsh output/error.
        /// </summary>
        public static string SetDropLogging(bool enable)
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo("netsh",
                    $"advfirewall set allprofiles logging droppedconnections {(enable ? "enable" : "disable")}")
                {
                    CreateNoWindow = true, UseShellExecute = false,
                    RedirectStandardOutput = true, RedirectStandardError = true
                };
                using var p = System.Diagnostics.Process.Start(psi);
                string output = (p.StandardOutput.ReadToEnd() + " " + p.StandardError.ReadToEnd()).Trim();
                p.WaitForExit(10000);
                return p.ExitCode == 0 ? null : $"netsh exit {p.ExitCode}: {output}";
            }
            catch (Exception ex) { return ex.Message; }
        }

        private static DateTime? ParseBlockedTime(string desc)
        {
            // v2 descriptions embed "[blocked 2026-10-10 14:22 UTC]"
            int i = desc?.IndexOf("[blocked ") ?? -1;
            if (i < 0) return null;
            string s = desc.Substring(i + 9);
            int j = s.IndexOf(']');
            if (j > 0 && DateTime.TryParseExact(s.Substring(0, j).Replace(" UTC", ""), "yyyy-MM-dd HH:mm", null,
                    System.Globalization.DateTimeStyles.AssumeUniversal, out DateTime t))
                return t.ToLocalTime();
            return null;
        }

        private static bool IsWindowsComponent(string path) =>
            !string.IsNullOrEmpty(path) &&
            path.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase);

        private static string DecodeProfile(int profiles)
        {
            var parts = new List<string>();
            if ((profiles & 1) != 0) parts.Add("Domain");
            if ((profiles & 2) != 0) parts.Add("Private");
            if ((profiles & 4) != 0) parts.Add("Public");
            return parts.Count > 0 ? string.Join(", ", parts) : "All";
        }

        private static string DecodeProtocol(int protocol)
        {
            return protocol switch
            {
                6 => "TCP",
                17 => "UDP",
                1 => "ICMPv4",
                58 => "ICMPv6",
                256 => "Any",
                _ => protocol.ToString()
            };
        }
    }
}

