using System;
using AutoScope.Engines.Firewall;
using AutoScope.Engines.Core;
using System.Collections.Generic;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using AutoScope.Services;

namespace AutoScope.Views
{
    // ── view-models ───────────────────────────────────────────────────────

    public sealed class BlockRowVm
    {
        public BlockRecord Record;
        public bool HasRules;
        public bool RulesEnabled;      // any enabled rule → on
        public string StatusGlyph => !HasRules ? "⚠" : RulesEnabled ? "⛔" : "⏸";
        public string StatusToolTip => !HasRules
            ? "No firewall rules found for this target (removed elsewhere, or created by an older tool)"
            : RulesEnabled ? "Active — outbound traffic to this target is blocked"
            : "Paused — rules exist but are disabled; traffic flows";

        public string Target => Record.IsIp ? Record.Key
            : System.IO.Path.GetFileName(Record.Key);
        public string TargetToolTip => Record.Key;

        /// <summary>The service that made the blocked connection — the row's
        /// own answer to "which network service did I block?", independent of
        /// its group header.</summary>
        public string ServiceDisplay
        {
            get
            {
                string key = BlocksStore.ServiceGroupKey(Record);
                if (key == "svchost:unresolved") return "…attributing";
                return ServiceCatalog.DisplayNameFor(key, Record.SvcDisplayName) switch
                {
                    "Unattributed" => "…attributing",
                    var n => n,
                };
            }
        }
        public string ServiceToolTip
        {
            get
            {
                string key = BlocksStore.ServiceGroupKey(Record);
                if (ServiceCatalog.TryGet(key, out var c)) return c.Description;
                return key == "svchost:unresolved"
                    ? "Service identity not yet recovered — the Sysmon/SCM attribution pass fills this in."
                    : $"Service/exe identity: {key} (recovered via {Record.Attrib})";
            }
        }
        public string ClassDisplay => Record.IsIp ? Record.ClassAtBlock : Record.ClassAtBlock;
        public Brush ClassBrush;
        public string ClassToolTip => Record.IsIp
            ? $"Ownership classification captured at block time:\n{Record.ClassAtBlock}"
            : $"Target type: {Record.ClassAtBlock}";

        public string CreatedDisplay => Record.CreatedUtc.ToLocalTime().ToString("MMM d HH:mm");
        public string CreatedToolTip => $"Blocked {Record.CreatedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss local}\n" +
            $"({DateTime.UtcNow - Record.CreatedUtc:dd\\d\\ hh\\h\\ mm\\m} ago) · origin: {Record.Origin}\n" +
            $"identity: {(Record.Attrib == "none" ? "unresolved" : Record.Attrib)}";

        public string LastTraffic = "…";
        public string LastTrafficToolTip = "Resolving from live monitor and Sysmon archive…";
        public Brush LastTrafficBrush;
        /// <summary>Newest attempt time (live or archived) — the Restore
        /// guide's ranking signal; null when no traffic was ever found.</summary>
        public DateTime? LastTrafficUtc;

        public string RowActionLabel => RulesEnabled ? "⏸ Pause" : "▶ Resume";
    }

    public sealed class BlockGroupVm
    {
        public string ServiceKey;
        public string DisplayName;
        public string Description;
        public ServiceImpact Impact;
        public string Summary;          // "6 blocks · 4 Akamai · 2 Azure · 1 paused"
        public string ImpactGlyph => Impact switch
        {
            ServiceImpact.High => "🔴",
            ServiceImpact.Medium => "🟠",
            _ => "⚪",
        };
        public string ImpactToolTip => Impact switch
        {
            ServiceImpact.High => "High impact — blocking this breaks Windows security features, sign-in or updates",
            ServiceImpact.Medium => "Medium impact — blocking this degrades Windows features",
            _ => "Normal impact — routine blocking target",
        };
        public List<BlockRowVm> Rows = new();
        public bool Expanded;
        public bool AnyEnabled => Rows.Any(r => r.RulesEnabled);
        public string GroupActionLabel => AnyEnabled ? $"⏸ Pause all ({Rows.Count})" : $"▶ Resume all ({Rows.Count})";
        public string GroupActionToolTip => AnyEnabled
            ? "Disables every block rule in this group — traffic resumes for all of them. Fully reversible (nothing is deleted)."
            : "Re-enables every block rule in this group.";
    }

    // ── the tab ───────────────────────────────────────────────────────────

    /// <summary>
    /// Blocks tab ported from AutoCommand's WPF BlocksView. WinUI port
    /// notes: no IsVisibleChanged on a Page (the tab reloads on Refresh and
    /// after every action); Dispatcher calls go through DispatcherQueue;
    /// MessageBox → AutoScope.Dialogs.
    /// </summary>
    public partial class BlocksView : Page
    {
        private bool _loading;
        private readonly Dictionary<string, (DateTime utc, string source)?> _trafficCache =
            new(StringComparer.OrdinalIgnoreCase);

        // Restore-guide state: the symptom the user picked and its matched
        // ACTIVE rows, ranked by freshest attempt.
        private ServiceSymptom _restoreSymptom;
        private List<BlockRowVm> _restoreMatches = new();

        // One automatic attribution repair per session — nobody should have
        // to know the button exists to see service names.
        private bool _autoRepairStarted;

        public BlocksView()
        {
            InitializeComponent();
            Loaded += (s, e) => _ = ReloadAsync();
        }

        private static Brush Res(string key) => (Brush)Application.Current.Resources[key];

        private async System.Threading.Tasks.Task ReloadAsync()
        {
            if (_loading) return;
            _loading = true;
            try
            {
                StatusText.Text = "loading…";
                BlocksStore.Load();

                // Firewall truth (background): which targets have rules, and
                // are they enabled. The store carries identity/history; the
                // firewall carries effect.
                var inventory = await AutoScope.Services.Fw.Service.GetBlockedInventoryAsync();
                var byKey = inventory.ToDictionary(
                    t => t.Key, t => t, StringComparer.OrdinalIgnoreCase);

                // Records the firewall knows about but the store doesn't
                // (rules from an older version, or blocks AutoCommand made
                // since the migration snapshot) become store records so the
                // tab is complete.
                await BlocksStore.ReconcileWithFirewallAsync(inventory);

                var records = BlocksStore.Records.ToList();
                if (records.Count == 0 || BlocksStore.Records.Count != records.Count) records = BlocksStore.Records.ToList();

                var vms = new List<BlockRowVm>();
                foreach (var r in records)
                {
                    string invKey = (r.IsIp ? "ip:" : "app:") + r.Key.ToLowerInvariant();
                    byKey.TryGetValue(invKey, out var t);
                    int rules = t?.Rules ?? 0;
                    int enabled = t?.EnabledRules ?? 0;
                    vms.Add(new BlockRowVm
                    {
                        Record = r,
                        HasRules = rules > 0,
                        RulesEnabled = enabled > 0,
                        ClassBrush = BrushForClass(r),
                        LastTrafficBrush = Res("TextSecondaryBrush"),
                    });
                }

                // "last transmitted packets": freshest live row first, else the
                // newest archived connection attempt (Sysmon logs attempts
                // even when the firewall drops them — the block still shows).
                // One streaming archive pass for all rows, not a scan per row.
                await System.Threading.Tasks.Task.Run(() =>
                {
                    var unseenIps = vms.Where(v => v.Record.IsIp &&
                            !_trafficCache.ContainsKey(v.Record.Kind + v.Record.Key))
                        .Select(v => v.Record.Key).ToList();
                    var ipIndex = SysmonArchiveService.NewestConnectionPerIp(unseenIps);
                    var unseenImages = vms.Where(v => !v.Record.IsIp &&
                            !_trafficCache.ContainsKey(v.Record.Kind + v.Record.Key))
                        .Select(v => v.Record.Key).ToList();
                    var imageIndex = SysmonArchiveService.NewestConnectionPerImage(unseenImages);

                    foreach (var vm in vms)
                    {
                        try
                        {
                            var live = vm.Record.IsIp
                                ? SvchostMonitorView.Current?.LiveRowForIp(vm.Record.Key)
                                : SvchostMonitorView.Current?.LiveRowForPath(vm.Record.Key);
                            if (live != null)
                            {
                                vm.LastTraffic = $"live · {live.LastSeenDisplay}";
                                vm.LastTrafficToolTip = $"Currently tracked by the Process Monitor.\n" +
                                    $"rx {live.RxBytesDisplay} · tx {live.TxBytesDisplay} · last packet {live.LastSeenDisplay}";
                                vm.LastTrafficUtc = live.LastSeen;
                                continue;
                            }

                            if (_trafficCache.TryGetValue(vm.Record.Kind + vm.Record.Key, out var hit))
                            {
                                ApplyArchiveTraffic(vm, hit);
                                continue;
                            }
                            var net = vm.Record.IsIp
                                ? (ipIndex.TryGetValue(vm.Record.Key, out var e1) ? e1 : null)
                                : (imageIndex.TryGetValue(vm.Record.Key, out var e2) ? e2 : null);
                            hit = net != null ? (net.TsUtc, "Sysmon archive") : null;
                            _trafficCache[vm.Record.Kind + vm.Record.Key] = hit;
                            ApplyArchiveTraffic(vm, hit);
                        }
                        catch { vm.LastTraffic = "—"; }
                    }
                });

                Render(vms);
                StatusText.Text = $"synced {DateTime.Now:HH:mm:ss}" +
                    (BlocksStore.Unrecognized.Count > 0
                        ? $" · {BlocksStore.Unrecognized.Count} unrecognized line(s) preserved in blocks.txt" : "");

                // Auto-repair: nobody should have to know the button exists.
                // Once per session, when rows are still unattributed, run the
                // Sysmon/SCM pass in the background and re-render.
                int unresolved = vms.Count(v => BlocksStore.ServiceGroupKey(v.Record) == "svchost:unresolved");
                if (unresolved > 0 && !_autoRepairStarted)
                {
                    _autoRepairStarted = true;
                    StatusText.Text = $"attributing {unresolved} block(s) from the Sysmon archive…";
                    _ = System.Threading.Tasks.Task.Run(async () =>
                    {
                        try
                        {
                            var progress = new Progress<string>(m =>
                                DispatcherQueue.TryEnqueue(() => StatusText.Text = m));
                            await BlockAttributionService.RepairAllAsync(progress);
                        }
                        finally
                        {
                            DispatcherQueue.TryEnqueue(async () => { _loading = false; await ReloadAsync(); });
                        }
                    });
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "load failed";
                await Dialogs.ShowInfoAsync("Error", $"Failed to load blocks: {ex.Message}");
            }
            finally { _loading = false; }
        }

        private void ApplyArchiveTraffic(BlockRowVm vm, (DateTime utc, string source)? hit)
        {
            if (hit == null)
            {
                vm.LastTraffic = "no traffic found";
                vm.LastTrafficToolTip = "No connection attempt found in the live monitor or the Sysmon archive window.";
                return;
            }
            var age = DateTime.UtcNow - hit.Value.utc;
            vm.LastTrafficUtc = hit.Value.utc;
            vm.LastTraffic = $"{ShortAge(age)} ago · attempt ({hit.Value.source})";
            vm.LastTrafficToolTip = $"Last connection attempt: {hit.Value.utc.ToLocalTime():yyyy-MM-dd HH:mm:ss local}\n" +
                "Sysmon records attempts even when the firewall drops them —\n" +
                "'no traffic found' means this block may be dead weight (CDN edges rotate).";
        }

        private static string ShortAge(TimeSpan age) => age.TotalDays >= 1
            ? $"{(int)age.TotalDays}d"
            : age.TotalHours >= 1 ? $"{(int)age.TotalHours}h" : $"{(int)age.TotalMinutes}m";

        private Brush BrushForClass(BlockRecord r)
        {
            string c = r.ClassAtBlock ?? "";
            if (c.Contains("Defender")) return Res("AccentRedBrush");
            if (c.Contains("Windows component")) return Res("AccentRedBrush");
            if (c.Contains("Microsoft/Azure")) return Res("AccentBlueBrush");
            if (c.Contains("Akamai") || c.Contains("Gcore")) return Res("AccentAmberBrush");
            return Res("TextSecondaryBrush");
        }

        private void Render(List<BlockRowVm> vms)
        {
            var groups = vms.GroupBy(v => BlocksStore.ServiceGroupKey(v.Record))
                .Select(g =>
                {
                    string key = g.Key;
                    ServiceCatalog.TryGet(key, out var info);
                    // MS-infra IP groups inherit at least Medium impact even
                    // when the service itself is unknown.
                    var impact = info?.Impact ?? ServiceImpact.Normal;
                    if (impact < ServiceImpact.Medium && g.Any(v =>
                        v.Record.ClassAtBlock is string c &&
                        (c.Contains("Microsoft/Azure") || c.Contains("Akamai") || c.Contains("Gcore"))))
                        impact = ServiceImpact.Medium;

                    var classes = g.GroupBy(v => v.Record.ClassAtBlock ?? "?")
                        .OrderByDescending(x => x.Count())
                        .Select(x => $"{x.Count()} {x.Key}");
                    int paused = g.Count(v => v.HasRules && !v.RulesEnabled);

                    return new BlockGroupVm
                    {
                        ServiceKey = key,
                        DisplayName = ServiceCatalog.DisplayNameFor(key,
                            g.FirstOrDefault()?.Record.SvcDisplayName),
                        Description = info?.Description ??
                            "No catalog description for this service — it is grouped by its Windows service/exe identity. " +
                            "Repair attribution may recover more detail.",
                        Impact = impact,
                        Summary = $"{g.Count()} block{(g.Count() == 1 ? "" : "s")} · {string.Join(" · ", classes)}" +
                            (paused > 0 ? $" · {paused} paused" : ""),
                        Rows = g.OrderBy(v => v.Record.IsIp ? 0 : 1)
                                .ThenBy(v => v.Record.Key).ToList(),
                        Expanded = impact == ServiceImpact.High,
                    };
                })
                .OrderByDescending(g => (int)g.Impact)
                .ThenByDescending(g => g.Rows.Count)
                .ToList();

            GroupsList.ItemsSource = groups;

            int active = vms.Count(v => v.RulesEnabled);
            int pausedN = vms.Count(v => v.HasRules && !v.RulesEnabled);
            int high = groups.Where(g => g.Impact == ServiceImpact.High).Sum(g => g.Rows.Count);
            int msInfra = vms.Count(v => v.Record.ClassAtBlock is string c &&
                (c.Contains("Microsoft/Azure") || c.Contains("Akamai") || c.Contains("Gcore")));
            int unattr = vms.Count(v => BlocksStore.ServiceGroupKey(v.Record) == "svchost:unresolved");

            TotalChip.Text = $"{vms.Count} blocks · {groups.Count} groups";
            ActiveChip.Text = $"⛔ {active} active";
            PausedChip.Text = $"⏸ {pausedN} paused";
            HighImpactChip.Text = $"🔴 {high} high-impact";
            UnattributedChip.Text = $"❓ {unattr} unattributed";
            MsInfraChip.Text = $"⚠ {msInfra} on Microsoft infra";
            HighImpactChipBorder.Visibility = high > 0 ? Visibility.Visible : Visibility.Collapsed;
            UnattributedChipBorder.Visibility = unattr > 0 ? Visibility.Visible : Visibility.Collapsed;

            RebuildRestorePanel(vms, high, active);
        }

        // ── restore guide ─────────────────────────────────────────────────

        /// <summary>
        /// "A feature broke — which of my blocks is doing it?" The panel lists
        /// symptoms that have at least one ACTIVE matching block; picking one
        /// shows exactly which rules to lift, ranked by freshest attempt.
        /// </summary>
        private void RebuildRestorePanel(List<BlockRowVm> vms, int highImpactActive, int totalActive)
        {
            var bySymptom = ServiceOutageMap.Symptoms
                .Select(s => (sym: s, rows: vms.Where(v => v.RulesEnabled && ServiceOutageMap.Matches(s, v.Record)).ToList()))
                .Where(x => x.rows.Count > 0)
                .OrderByDescending(x => x.rows.Count)
                .ToList();

            RestorePanel.Visibility = bySymptom.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            if (bySymptom.Count == 0) return;

            RestoreBanner.Text = highImpactActive > 0
                ? $"🔴 {highImpactActive} of your {totalActive} active blocks sit on services Windows depends on (Defender, sign-in, updates…). " +
                  "If something stopped working, pick it below and pause exactly the rules that break it:"
                : "If something stopped working, pick it below and pause exactly the rules that break it:";

            string prev = (SymptomCombo.SelectedItem as ComboSymptom)?.Symptom.Id;
            SymptomCombo.SelectionChanged -= SymptomCombo_SelectionChanged;
            SymptomCombo.Items.Clear();
            foreach (var (sym, rows) in bySymptom)
                SymptomCombo.Items.Add(new ComboSymptom(sym, rows.Count));
            SymptomCombo.SelectionChanged += SymptomCombo_SelectionChanged;

            int restore = bySymptom.FindIndex(x => x.sym.Id == prev);
            SymptomCombo.SelectedIndex = restore >= 0 ? restore : 0;
        }

        private sealed class ComboSymptom
        {
            public readonly ServiceSymptom Symptom;
            private readonly int _n;
            public ComboSymptom(ServiceSymptom s, int n) { Symptom = s; _n = n; }
            public override string ToString() => $"{Symptom.Title}  ({_n} block{(_n == 1 ? "" : "s")})";
        }

        private void SymptomCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if ((SymptomCombo.SelectedItem as ComboSymptom)?.Symptom is not ServiceSymptom sym) return;
            _restoreSymptom = sym;

            // Rank by freshest connection attempt: the block still actively
            // swallowing traffic is the likely culprit, not a cold one.
            _restoreMatches = BlocksStore.Records
                .Where(r => r.Status != "off" && ServiceOutageMap.Matches(sym, r))
                .Select(r => (r, utc: _trafficCache.TryGetValue(r.Kind + r.Key, out var h) && h != null ? h.Value.utc : (DateTime?)null))
                .OrderByDescending(x => x.utc ?? DateTime.MinValue)
                .Select(x => new BlockRowVm
                {
                    Record = x.r,
                    HasRules = true,
                    RulesEnabled = true,
                    LastTrafficUtc = x.utc,
                    LastTraffic = x.utc != null ? $"{ShortAge(DateTime.UtcNow - x.utc.Value)} ago" : "no traffic found",
                })
                .ToList();

            MatchList.ItemsSource = _restoreMatches.Select(RestoreLine).ToList();

            PauseMatchedBtn.Content = $"⏸ Pause these {_restoreMatches.Count} block(s) — traffic resumes";
        }

        private static string GroupLabel(BlockRecord r)
        {
            string key = BlocksStore.ServiceGroupKey(r);
            return ServiceCatalog.TryGet(key, out var c) ? c.DisplayName : key;
        }

        /// <summary>One Restore-guide line: who is blocked, what it still
        /// tries, when it was blocked — the "which rule" answer at a glance.</summary>
        private static string RestoreLine(BlockRowVm v)
        {
            string group = GroupLabel(v.Record);
            string target = v.Record.IsIp ? v.Record.Key : System.IO.Path.GetFileName(v.Record.Key);
            string tried = v.LastTrafficUtc != null
                ? ShortAge(DateTime.UtcNow - v.LastTrafficUtc.Value) + " ago"
                : "no attempts since";
            string blocked = v.Record.CreatedUtc.ToLocalTime().ToString("MMM d HH:mm");
            return $"{group,-30} {target,-18} tried {tried,-16} blocked {blocked}";
        }

        private async void PauseMatchedBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_restoreSymptom == null || _restoreMatches.Count == 0) return;
            var sym = _restoreSymptom;

            string targets = string.Join("\n", _restoreMatches.Take(12).Select(v =>
                $"  {GroupLabel(v.Record)} · {(v.Record.IsIp ? v.Record.Key : System.IO.Path.GetFileName(v.Record.Key))}")) +
                (_restoreMatches.Count > 12 ? $"\n  … and {_restoreMatches.Count - 12} more" : "");
            bool proceed = await Dialogs.ConfirmAsync("Restore service",
                $"Restore '{sym.Title}' by pausing {_restoreMatches.Count} matching block(s)?\n\n" +
                $"{sym.Notice}\n\n{targets}\n\n" +
                "Traffic resumes immediately. Fully reversible — nothing is deleted; the Blocks list keeps every record for re-enabling.");
            if (!proceed) return;

            var list = _restoreMatches.Select(v => (v.Record.Kind, v.Record.Key)).ToList();
            var (matched, changed) = await AutoScope.Services.Fw.Service.SetTargetsEnabledAsync(list, false);
            foreach (var v in _restoreMatches)
                BlocksStore.SetStatus(v.Record.Kind, v.Record.Key, "off", "restore-guide");
            BlocksStore.AppendEvent("paused", "-", "-",
                $"restore '{sym.Title}': {changed}/{matched} rules", "restore-guide");
            await ReloadAsync();
        }

        // ── actions ────────────────────────────────────────────────────────

        private async void RowToggle_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.Tag is not BlockRowVm vm) return;
            bool enable = !vm.RulesEnabled;
            var (matched, changed) = await AutoScope.Services.Fw.Service.SetTargetsEnabledAsync(
                new[] { (vm.Record.Kind, vm.Record.Key) }, enable);
            BlocksStore.SetStatus(vm.Record.Kind, vm.Record.Key, enable ? "on" : "off");
            BlocksStore.AppendEvent(enable ? "resumed" : "paused", vm.Record.Kind, vm.Record.Key,
                $"{changed}/{matched} rules", "blocks-tab");
            await ReloadAsync();
        }

        private async void GroupToggle_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.Tag is not BlockGroupVm g) return;
            bool enable = !g.AnyEnabled;

            string impact = g.Impact switch
            {
                ServiceImpact.High => "\n\n⚠ HIGH IMPACT — this group keeps Windows security features, sign-in or updates working.",
                ServiceImpact.Medium => "\n\n⚠ These blocks sit on infrastructure Windows features depend on.",
                _ => "",
            };
            string targets = string.Join("\n", g.Rows.Take(12).Select(r => $"  {(enable ? "resume" : "pause")}  {r.Target}")) +
                (g.Rows.Count > 12 ? $"\n  … and {g.Rows.Count - 12} more" : "");
            bool proceed = await Dialogs.ConfirmAsync((enable ? "Resume" : "Pause") + " service group",
                $"{(enable ? "RESUME" : "PAUSE")} all {g.Rows.Count} block(s) for:\n{g.DisplayName}{impact}\n\n{targets}");
            if (!proceed) return;

            var targetsList = g.Rows.Select(r => (r.Record.Kind, r.Record.Key)).ToList();
            var (matched, changed) = await AutoScope.Services.Fw.Service.SetTargetsEnabledAsync(targetsList, enable);
            BlocksStore.SetStatusForGroup(g.ServiceKey, enable ? "on" : "off");
            BlocksStore.AppendEvent(enable ? "resumed" : "paused", "-", "-",
                $"{g.DisplayName}: {changed}/{matched} rules", "blocks-tab");
            await ReloadAsync();
        }

        private async void RowRemove_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.Tag is not BlockRowVm vm) return;
            bool proceed = await Dialogs.ConfirmAsync("Remove block",
                $"Permanently remove the block for\n{vm.Record.Key}?\n\nIts firewall rules are deleted and traffic resumes immediately. " +
                "This is recorded in the block history log.");
            if (!proceed) return;

            int removed = vm.Record.IsIp
                ? await AutoScope.Services.Fw.Service.RemoveBlockRulesForIpAsync(vm.Record.Key)
                : await AutoScope.Services.Fw.Service.RemoveBlockRulesForAppAsync(vm.Record.Key);
            BlocksStore.Remove(vm.Record.Kind, vm.Record.Key, "blocks-tab");
            _trafficCache.Remove(vm.Record.Kind + vm.Record.Key);
            await ReloadAsync();
        }

        private async void RepairBtn_Click(object sender, RoutedEventArgs e)
        {
            RepairBtn.IsEnabled = false;
            try
            {
                StatusText.Text = "repairing attribution from Sysmon archive…";
                var progress = new Progress<string>(msg => StatusText.Text = msg);
                var (repaired, unresolved) = await BlockAttributionService.RepairAllAsync(progress);
                StatusText.Text = $"repaired {repaired}, unresolved {unresolved}";
                await ReloadAsync();
            }
            finally { RepairBtn.IsEnabled = true; }
        }

        private async void RefreshBtn_Click(object sender, RoutedEventArgs e) => await ReloadAsync();
    }
}
