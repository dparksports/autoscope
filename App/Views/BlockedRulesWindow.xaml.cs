using System;
using AutoCommand.Engines.Firewall;
using AutoCommand.Engines.Core;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;
using AutoScope.Services;

namespace AutoScope.Views
{
    /// <summary>
    /// Fleet view over every AutoScope-created firewall block, ported from
    /// AutoCommand's WPF BlockedRulesWindow: risky rows highlighted, bulk
    /// unblock, legacy consolidation, CSV export and re-enable-all (undo for
    /// the status-bar panic button). WinUI port notes: flat class-sorted
    /// grid (no group headers), risky-row colors applied in LoadingRow,
    /// CSV export writes straight to Downloads (no SaveFileDialog).
    /// </summary>
    public partial class BlockedRulesWindow : Window
    {
        private class Row
        {
            public string Target, Kind, Key, Ip, AppPath, Class, Description;
            public int Rules, EnabledRules;
            public DateTime? Created;
            private int _hits;
            public int Hits
            {
                get => _hits;
                set => _hits = value;
            }
            public bool IsRisky => Class.Contains("Microsoft") || Class.Contains("Akamai") ||
                                   Class.Contains("Gcore") || Class.Contains("Windows component");
            public string RulesSummary => EnabledRules == Rules ? Rules.ToString() : $"{EnabledRules}/{Rules} on";
            public string CreatedDisplay => Created?.ToString("yyyy-MM-dd HH:mm") ?? "legacy";
            public string HitsDisplay => Hits > 0 ? Hits.ToString() : "·";
            public string OwnerDisplay { get; set; } = "";
            public string Note => Description.Length > 160 ? Description[..160] + "…" : Description;
        }

        /// <summary>One aggregated (process, destination) rollup in the live feed grid.</summary>
        private class HitRow
        {
            public string Process { get; set; }
            public int Pid { get; set; }
            public string Destination { get; set; }
            public string Match { get; set; }
            public int Attempts { get; set; }
            public string FirstSeen { get; set; }
            public string LastSeen { get; set; }
            public string Image { get; set; }
        }

        private readonly ObservableCollection<Row> _rows = new();
        private readonly DispatcherQueueTimer _hitsTimer =
            DispatcherQueue.GetForCurrentThread().CreateTimer();
        private string _migrationNote = "";
        private string _feedStatus = "live feed starting…";

        public BlockedRulesWindow()
        {
            InitializeComponent();

            try
            {
                // WPF Width/Height → AppWindow resize (980×640, best effort)
                AppWindow.Resize(new Windows.Graphics.SizeInt32
                {
                    Width = 980,
                    Height = 640,
                });
            }
            catch { /* cosmetic */ }

            _hitsTimer.Interval = TimeSpan.FromSeconds(15);
            _hitsTimer.Tick += async (_, _) => await RefreshHitsAsync();
            _hitsTimer.Start();
            Closed += (_, _) => _hitsTimer.Stop();
            Activated += async (_, _) =>
            {
                // auto-migrate legacy-name rules on open — lossless (provenance
                // carries over, protection unchanged), so users never have to
                // know or care about the old naming scheme
                int legacy = await AutoScope.Services.Fw.Service.CountLegacyBlocksAsync();
                if (legacy > 0)
                {
                    StatusText.Text = $"Migrating {legacy} legacy firewall rule(s) to the current naming scheme…";
                    var r = await AutoScope.Services.Fw.Service.ConsolidateLegacyIpBlocksAsync();
                    _migrationNote = $"Auto-migrated {r.Item3} legacy rule(s) ({r.Item2} redundant inbound rules removed) across {r.Item1} target(s). ";
                }
                await ReloadAsync();
            };
        }

        /// <summary>WPF-compat shim so callers written against the WPF
        /// window's Show() compile unchanged.</summary>
        public void Show() => Activate();

        private async Task ReloadAsync()
        {
            StatusText.Text = "Scanning firewall…";
            var inv = await AutoScope.Services.Fw.Service.GetBlockedInventoryAsync();
            var hits = await Task.Run(() => CollectHitsLastHour());

            _rows.Clear();
            foreach (var t in inv)
            {
                int h = 0;
                if (t.Kind == "ip" && hits.TryGetValue(t.Ip, out int v)) h = v;
                // app hits: the live feed attributes per process, the log per IP —
                // the aggregated feed grid below carries the process attribution
                string owner = "";
                if (t.Kind == "ip")
                {
                    var cached = RdapService.Instance.Cached(t.Ip);
                    if (cached != null)
                        owner = cached.IsNegative ? "lookup failed" :
                                $"{cached.Netname} · {(cached.Org ?? "?")} [{cached.Country}]";
                }
                _rows.Add(new Row
                {
                    Target = t.Target, Kind = t.Kind, Key = t.Key, Ip = t.Ip, AppPath = t.AppPath,
                    Class = t.Class, Rules = t.Rules, EnabledRules = t.EnabledRules, Hits = h,
                    Description = t.Description, Created = t.Created, OwnerDisplay = owner,
                });
            }

            RulesGrid.ItemsSource = _rows
                .OrderBy(r => r.IsRisky ? 0 : 1)   // WinUI port: no group headers —
                .ThenBy(r => r.Class)              // risky rows first, then class-sorted
                .ToList();

            await RefreshHitsAsync();
        }

        private void RulesGrid_LoadingRow(object sender, CommunityToolkit.WinUI.UI.Controls.DataGridRowEventArgs e)
        {
            if (e.Row.DataContext is Row r && r.IsRisky)
            {
                e.Row.Background = new SolidColorBrush(Color.FromArgb(255, 0x2A, 0x0F, 0x18));
                e.Row.Foreground = new SolidColorBrush(Color.FromArgb(255, 0xF2, 0xA0, 0xB4));
            }
        }

        /// <summary>Merged per-IP hit counts, last hour: live Sysmon-joined feed +
        /// (when enabled) the firewall's own drop log. Feed is ground truth —
        /// it works with default settings and carries process attribution.</summary>
        private static Dictionary<string, int> CollectHitsLastHour()
        {
            var merged = BlockHitFeedService.Instance.FeedHitsByIp(60);
            foreach (var kv in FirewallService.GetRecentLogHits(60))
                merged[kv.Key] = Math.Max(merged.TryGetValue(kv.Key, out int f) ? f : 0, kv.Value.Count);
            return merged;
        }

        /// <summary>Refreshes both hit surfaces without rebuilding the rules grid.</summary>
        private async Task RefreshHitsAsync()
        {
            try { BlockHitFeedService.Instance.Start(); } catch { }
            var feed = BlockHitFeedService.Instance;
            var hits = await Task.Run(() => CollectHitsLastHour());

            foreach (var row in _rows)
                if (row.Kind == "ip" && hits.TryGetValue(row.Ip, out int v))
                    row.Hits = v;
            // WinUI port: rows are plain — reassign the source so HitsDisplay refreshes
            if (RulesGrid.ItemsSource is List<Row> list)
            {
                RulesGrid.ItemsSource = null;
                RulesGrid.ItemsSource = list;
            }

            HitsGrid.ItemsSource = feed.Aggregates(60, 200).Select(x => new HitRow
            {
                Process = x.Process,
                Pid = x.Pid,
                Destination = $"{x.DestIp}:{x.DestPort}",
                Match = x.MatchKind == "ip" ? "IP block" : "app block",
                Attempts = x.Count,
                FirstSeen = x.FirstUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                LastSeen = x.LastUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                Image = x.Image,
            }).ToList();

            int liveCount = hits.Values.Sum();
            _feedStatus = feed.IsRunning
                ? $"live feed: {liveCount} blocked connect(s) in the last hour"
                : "live feed starting…";
            if (feed.WatcherError != null) _feedStatus += $" — {feed.WatcherError}";
            UpdateStatusText();
        }

        private void UpdateStatusText()
        {
            int risky = _rows.Count(r => r.IsRisky);
            int disabled = _rows.Count(r => r.EnabledRules == 0);
            StatusText.Text =
                _migrationNote +
                $"{_rows.Count} blocked targets · {risky} risky (Microsoft/Windows — likely breakage, not threats) · {disabled} fully disabled · {_feedStatus}" +
                (FirewallService.FirewallDropLoggingOn()
                    ? ""
                    : " · firewall drop-logging off (optional second hit source; the live feed works without it)");
            ConsolidateBtn.IsEnabled = _rows.Any(r => r.Rules > 2 && r.Kind == "ip");
            UnblockMsBtn.IsEnabled = risky > 0;
            EnableLogBtn.Visibility = FirewallService.FirewallDropLoggingOn()
                ? Visibility.Collapsed : Visibility.Visible;
        }

        private async void EnableLogBtn_Click(object sender, RoutedEventArgs e)
        {
            EnableLogBtn.IsEnabled = false;
            try
            {
                string err = await Task.Run(() => FirewallService.SetDropLogging(true));
                StatusText.Text = err == null
                    ? "Drop-logging enabled on all profiles — hit counts will appear as blocks fire."
                    : $"Drop-logging partially failed: {err}";
            }
            finally { EnableLogBtn.IsEnabled = true; }
            await ReloadAsync();
        }

        private async void RdapBtn_Click(object sender, RoutedEventArgs e)
        {
            var targets = _rows.Where(r => r.Kind == "ip" && r.Class == "Unclassified").ToList();
            if (targets.Count == 0)
            {
                StatusText.Text = "No unclassified IP targets — everything is already classified or verified.";
                return;
            }
            RdapBtn.IsEnabled = false;
            try
            {
                StatusText.Text = $"RDAP-verifying {targets.Count} target(s)… (cached results are instant)";
                int ok = 0, failed = 0, ms = 0, cached = 0;
                foreach (var r in targets)
                {
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    var entry = await RdapService.Instance.LookupAsync(r.Ip);
                    sw.Stop();
                    if (sw.ElapsedMilliseconds < 50) cached++;
                    if (entry.IsNegative) failed++;
                    else
                    {
                        ok++;
                        r.OwnerDisplay = $"{entry.Netname} · {(entry.Org ?? "?")} [{entry.Country}]";
                    }
                    ms += (int)sw.ElapsedMilliseconds;
                }
                StatusText.Text = $"RDAP: {ok} verified, {failed} failed · {cached} served from cache · " +
                                  $"total {ms} ms · cache: {RdapService.Instance.EntryCount} block(s) in {RdapService.Instance.CachePath}";
            }
            finally { RdapBtn.IsEnabled = true; }
            await ReloadAsync();
        }

        private async void RefreshBtn_Click(object sender, RoutedEventArgs e) => await ReloadAsync();

        private async void UnblockSelectedBtn_Click(object sender, RoutedEventArgs e)
        {
            var sel = RulesGrid.SelectedItems.Cast<Row>().ToList();
            if (sel.Count == 0) { await Dialogs.ShowInfoAsync("Unblock", "Select one or more rows first."); return; }
            if (!await Dialogs.ConfirmAsync("Confirm unblock",
                $"Permanently remove the block rules for {sel.Count} target(s)?\n" +
                string.Join("\n", sel.Select(r => $"  · {r.Target} ({r.Class}, {r.Rules} rules)")))) return;

            int removed = 0;
            foreach (var r in sel)
                removed += r.Kind == "ip"
                    ? await AutoScope.Services.Fw.Service.RemoveBlockRulesForIpAsync(r.Ip)
                    : await AutoScope.Services.Fw.Service.RemoveBlockRulesForAppAsync(r.AppPath);
            StatusText.Text = $"Removed {removed} firewall rule(s).";
            await ReloadAsync();
        }

        private async void UnblockMsBtn_Click(object sender, RoutedEventArgs e)
        {
            var risky = _rows.Where(r => r.IsRisky).ToList();
            if (risky.Count == 0) return;
            if (!await Dialogs.ConfirmAsync("Unblock Microsoft-owned ⚠",
                $"These {risky.Count} targets are Microsoft / Windows infrastructure — blocking them breaks\n" +
                "updates, notifications, sign-in or DNS rather than blocking threats.\n\n" +
                string.Join("\n", risky.Select(r => $"  · {r.Target} ({r.Class}, {r.Rules} rules)")) +
                "\n\nRemove ALL of them?")) return;

            int removed = 0;
            foreach (var r in risky)
                removed += r.Kind == "ip"
                    ? await AutoScope.Services.Fw.Service.RemoveBlockRulesForIpAsync(r.Ip)
                    : await AutoScope.Services.Fw.Service.RemoveBlockRulesForAppAsync(r.AppPath);
            StatusText.Text = $"Removed {removed} rule(s) blocking Microsoft/Windows infrastructure.";
            await ReloadAsync();
        }

        private async void ConsolidateBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!await Dialogs.ConfirmAsync("Consolidate legacy",
                "Legacy IP blocks created 4 rules each (TCP/UDP × in/out). This consolidates each set to the\n" +
                "current 2-rule scheme (outbound TCP+UDP): inbound pair deleted, outbound pair renamed with\n" +
                "provenance preserved. No protection is lost — inbound was already covered by stateful filtering.")) return;

            var (targets, removedIn, migratedOut) = await AutoScope.Services.Fw.Service.ConsolidateLegacyIpBlocksAsync();
            StatusText.Text = $"Consolidated {targets} target(s): {removedIn} redundant inbound rule(s) deleted, {migratedOut} migrated to v2 naming.";
            await ReloadAsync();
        }

        private async void ReenableBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!await Dialogs.ConfirmAsync("Re-enable",
                "Re-enable ALL AutoScope block rules? (Undoes 'Restore Internet'.)")) return;
            var res = await AutoScope.Services.Fw.Service.SetAllBlocksEnabledAsync(true);
            StatusText.Text = $"Re-enabled AutoScope blocks ({res.Changed} rule(s) changed).";
            await ReloadAsync();
        }

        private async void RestoreExceptRiskyBtn_Click(object sender, RoutedEventArgs e)
        {
            var risky = _rows.Where(r => r.IsRisky).ToList();
            var toRestore = _rows.Where(r => !r.IsRisky).ToList();
            if (toRestore.Count == 0) { await Dialogs.ShowInfoAsync("Restore", "Nothing to restore — no non-risky blocks."); return; }

            var preview = new System.Text.StringBuilder();
            preview.AppendLine($"Restore {toRestore.Count} target(s) — everything EXCEPT these {risky.Count}, which stay");
            preview.AppendLine("disabled because blocking them breaks Windows rather than threats:");
            foreach (var r in risky.Take(12)) preview.AppendLine($"  · {r.Target}  ({r.Class})");
            if (risky.Count > 12) preview.AppendLine($"  … and {risky.Count - 12} more");
            preview.AppendLine().AppendLine("Kept-disabled targets remain listed (red rows) — re-enable");
            preview.AppendLine("individually anytime if you truly want them blocked.");
            if (!await Dialogs.ConfirmAsync("Restore except Microsoft/Windows ⚠", preview.ToString())) return;

            var res = await AutoScope.Services.Fw.Service.SetAllBlocksEnabledAsync(true, skipRisky: true);
            StatusText.Text = $"Restored {res.Changed} rule(s); kept {res.SkippedRisky} risky rule(s) disabled.";
            await ReloadAsync();
        }

        private void ExportBtn_Click(object sender, RoutedEventArgs e)
        {
            // WinUI port: no SaveFileDialog — CSV lands in Downloads with a
            // timestamped name and the path is shown in the status line
            string path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads",
                $"blocked-rules-{DateTime.Now:yyyyMMdd-HHmm}.csv");
            try
            {
                var lines = new List<string> { "Target,Kind,Class,Rules,Enabled,Created,Hits10m,Description" };
                foreach (var r in _rows)
                    lines.Add($"{r.Target},{r.Kind},\"{r.Class}\",{r.Rules},{r.EnabledRules}," +
                              $"\"{r.CreatedDisplay}\",{r.Hits},\"{(r.Description ?? "").Replace("\"", "'")}\"");
                File.WriteAllLines(path, lines);
                StatusText.Text = $"Exported {_rows.Count} rows → {path}";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Export failed: {ex.Message}";
            }
        }
    }
}
