using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;
using AutoScope.Services;

namespace AutoScope.Views
{
    /// <summary>
    /// "Site Doctor" — the user-facing end of the site-diagnosis pipeline:
    /// SiteFingerprintService (what recorded traffic says) +
    /// DependencyBlockService (were the page's other hosts silently blocked
    /// during this browser's visits?) + SiteProbeService (a capped, itemized
    /// live check) + SiteVerdictService (one plain-English answer, with the
    /// math one expander away).
    ///
    /// House rules, same as every tab: looking changes nothing; the check's
    /// every operation is listed; suggestions are reversible and never
    /// applied by the app.
    /// </summary>
    public partial class SiteDoctorView : Page
    {
        private CancellationTokenSource _runCts;
        private List<string> _suggestions = new();
        /// <summary>All-traffic hosts — the control-site pool and the machine
        /// baseline must not move just because the picker is filtered.</summary>
        private List<string> _controlPool = new();
        private List<string> _browsers = new();
        private HashSet<string> _pinned = new(StringComparer.OrdinalIgnoreCase);
        private List<string> _unblockTargets;

        private static string PinsPath => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoScope", "site-doctor-pins.json");

        public SiteDoctorView()
        {
            InitializeComponent();
            LoadPins();
        }

        private void Page_Loaded(object sender, RoutedEventArgs e)
        {
            RefreshSuggestions();
            UpdatePinButton();
        }

        private void Page_Unloaded(object sender, RoutedEventArgs e)
        {
            _runCts?.Cancel();
        }

        /// <summary>
        /// Hosts this machine has actually been talking to (from the
        /// Transmissions archive), plus the passive "struggling" hint — the
        /// archive sometimes already shows the dice-roll pattern before any
        /// probe runs. The picker itself is user territory: pinned ★ sites
        /// first, then the selected source's (all apps / one browser) hosts.
        /// No built-in site list exists anywhere in this flow.
        /// </summary>
        private void RefreshSuggestions()
        {
            try
            {
                var rows = TransmissionsArchiveService.Read(max: 2000,
                    sinceUtc: DateTime.UtcNow - TimeSpan.FromHours(24));
                _controlPool = SiteFingerprintService.TopHosts(rows, 25);
                _browsers = SiteFingerprintService.BrowsersSeen(rows);

                BrowserFilterBox.SelectionChanged -= BrowserFilter_SelectionChanged; // rebuild, don't retrigger
                BrowserFilterBox.Items.Clear();
                BrowserFilterBox.Items.Add("All apps");
                if (_pinned.Count > 0) BrowserFilterBox.Items.Add("★ Pinned sites");
                foreach (string b in _browsers) BrowserFilterBox.Items.Add(b);
                BrowserFilterBox.SelectedIndex = 0;
                BrowserFilterBox.SelectionChanged += BrowserFilter_SelectionChanged;

                ApplySuggestions();

                var all = SiteFingerprintService.AllFingerprints(rows);
                int baseline = SiteFingerprintService.BaselineEdgeCount(all);
                var struggling = all.Values
                    .Where(f => f.Conversations >= SiteFingerprintService.MinConversations)
                    .Select(f => SiteFingerprintService.Fingerprint(
                        rows.Where(r => string.Equals(r.Sni, f.Host, StringComparison.OrdinalIgnoreCase)).ToList(),
                        baseline))
                    .Where(f => f.LooksStruggling)
                    .OrderByDescending(f => f.Conversations)
                    .Take(3)
                    .Select(f => f.Host)
                    .ToList();

                if (struggling.Count > 0)
                {
                    StruggleHintText.Text = "From your recorded traffic, this site behaves unevenly — bursts and address-hopping:";
                    StruggleHintHosts.ItemsSource = struggling;
                    StruggleHint.Visibility = Visibility.Visible;
                }
                else
                {
                    StruggleHint.Visibility = Visibility.Collapsed;
                }

                RefreshBlockHitHint();
            }
            catch { /* archive unreadable — the box just has no suggestions */ }
        }

        /// <summary>
        /// The signpost for users who don't know this tab is for them: a
        /// browser hitting blocked addresses is the fingerprint of "the site
        /// works but sign-in / parts of pages fail". One glance, data-driven
        /// (the browsers are the ones your traffic shows), no block named
        /// until a check anchors it to a site.
        /// </summary>
        private void RefreshBlockHitHint()
        {
            try
            {
                BlockHitFeedService.Instance.Start();
                var byBrowser = BlockHitFeedService.Instance.Aggregates(1440, 100)
                    .Where(a => a.MatchKind == "ip" && _browsers.Contains(
                        ((System.IO.Path.GetFileName(a.Image) ?? a.Process ?? "")
                            .Trim().ToLowerInvariant().Replace(".exe", ""))))
                    .GroupBy(a => a.Process, StringComparer.OrdinalIgnoreCase)
                    .ToList();
                if (byBrowser.Count == 0)
                {
                    BlockHitHint.Visibility = Visibility.Collapsed;
                    return;
                }

                var busiest = byBrowser.OrderByDescending(g => g.Sum(a => a.Count)).First();
                int total = busiest.Sum(a => a.Count);
                BlockHitHintText.Text =
                    $"{busiest.Key} hit blocked addresses {total} time(s) in the last day — if a page or " +
                    "sign-in failed, that's usually why. Check the site:";
                BlockHitHint.Visibility = Visibility.Visible;
            }
            catch { /* no feed → no hint; the tab works regardless */ }
        }

        private void BrowserFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (BrowserFilterBox.SelectedItem is string) ApplySuggestions();
        }

        /// <summary>Picker = pinned sites (★, in pin order) + the filtered
        /// source's hosts, pinned ones not duplicated.</summary>
        private void ApplySuggestions()
        {
            string filter = BrowserFilterBox.SelectedItem as string ?? "All apps";
            IEnumerable<string> tail;
            try
            {
                var rows = TransmissionsArchiveService.Read(max: 2000,
                    sinceUtc: DateTime.UtcNow - TimeSpan.FromHours(24));
                tail = filter == "★ Pinned sites"
                    ? Enumerable.Empty<string>()
                    : SiteFingerprintService.TopHosts(rows, 25,
                        filter == "All apps" ? null : filter);
            }
            catch { tail = Enumerable.Empty<string>(); }

            var list = _pinned.Select(p => "★ " + p).ToList();
            list.AddRange(tail.Where(h => !_pinned.Contains(h)));
            _suggestions = list;
            HostBox.ItemsSource = list;
        }

        private void PinBtn_Click(object sender, RoutedEventArgs e)
        {
            string host = (HostBox.Text ?? "").Trim();
            if (host.Length == 0) return;
            if (_pinned.Contains(host)) _pinned.Remove(host); else _pinned.Add(host);
            SavePins();
            UpdatePinButton();
            ApplySuggestions();
        }

        private void UpdatePinButton() =>
            PinBtn.Content = _pinned.Contains((HostBox.Text ?? "").Trim()) ? "★ Pinned" : "☆ Pin";

        private void LoadPins()
        {
            try
            {
                if (System.IO.File.Exists(PinsPath))
                    _pinned = new HashSet<string>(
                        System.IO.File.ReadAllLines(PinsPath).Where(l => l.Trim().Length > 0),
                        StringComparer.OrdinalIgnoreCase);
            }
            catch { /* unreadable pins — start empty, never block the tab */ }
        }

        private void SavePins()
        {
            try
            {
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(PinsPath));
                System.IO.File.WriteAllLines(PinsPath, _pinned);
            }
            catch { /* unwritable disk — pins live for this session */ }
        }

        private void StruggleHost_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button b && b.Content is string host)
            {
                HostBox.Text = host;
                RunBtn_Click(sender, e);
            }
        }

        private async void RunBtn_Click(object sender, RoutedEventArgs e)
        {
            string host = (HostBox.Text ?? "").Trim();
            if (host.Length == 0) return;

            _runCts?.Cancel();
            _runCts = new CancellationTokenSource();
            var ct = _runCts.Token;

            RunBtn.IsEnabled = false;
            VerdictPanel.Visibility = Visibility.Collapsed;
            MathExpander.Visibility = Visibility.Collapsed;
            OpsExpander.Visibility = Visibility.Collapsed;
            UnblockBtn.Visibility = Visibility.Collapsed;
            _unblockTargets = null;
            ProgressText.Text = "Reading recorded traffic…";

            try
            {
                // Passive half: everything the archive knows about this host.
                var rows = TransmissionsArchiveService.Read(max: 4000,
                    sinceUtc: DateTime.UtcNow - TimeSpan.FromHours(24));
                var siteRows = rows
                    .Where(r => string.Equals(r.Sni, host, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                var all = SiteFingerprintService.AllFingerprints(rows);
                var fingerprint = SiteFingerprintService.Fingerprint(siteRows,
                    SiteFingerprintService.BaselineEdgeCount(all));

                // Controls: two other hosts this machine actually uses —
                // apples-to-apples beats a hardcoded benchmark. Always from
                // the ALL-traffic pool so filtering the picker can't skew
                // the comparison.
                var controls = _controlPool
                    .Where(h => !string.Equals(h, host, StringComparison.OrdinalIgnoreCase))
                    .Take(2)
                    .ToList();
                if (controls.Count == 0) controls = new List<string> { "example.com" };

                // Extra edges: the archive's addresses for this host, so the
                // probes cover servers DNS may not hand back right now.
                var extraEdges = fingerprint.Edges.Select(ed => ed.Ip).ToList();

                // Dependency pass, in parallel with the probe: were any of
                // the page's other hosts silently blocked during this
                // browser's recorded visits? (The probe can't see this —
                // blocked connects carry no hostname.)
                var depTask = Task.Run(() =>
                    DependencyBlockService.AnalyzeLiveAsync(host, 1440, null, ct), ct);

                var progress = new Progress<string>(line => ProgressText.Text = line);
                var report = await Task.Run(() =>
                    SiteProbeService.Shared.RunAsync(host, extraEdges, controls, progress, ct), ct);

                var dependency = await depTask;
                var verdict = SiteVerdictService.Decide(fingerprint, report, dependency);
                MarkAutoCommandBlocked(verdict, report, dependency);
                ShowVerdict(verdict, report);
                ProgressText.Text =
                    $"Done in {(report.EndedUtc - report.StartedUtc).TotalSeconds:0}s · {report.Operations.Count} operations, all listed below.";
            }
            catch (OperationCanceledException)
            {
                ProgressText.Text = "Check cancelled.";
            }
            catch (ArgumentException ex)
            {
                ProgressText.Text = ex.Message;
            }
            catch (Exception ex)
            {
                ProgressText.Text = $"Check failed: {ex.Message}";
            }
            finally
            {
                RunBtn.IsEnabled = true;
            }
        }

        private void ShowVerdict(SiteVerdictService.Verdict verdict, SiteProbeService.SiteProbeReport report)
        {
            VerdictHeadline.Text = verdict.Headline;
            VerdictNextStep.Text = "→ " + verdict.NextStep;

            (Brush bg, Brush border, Brush fg) = verdict.Kind switch
            {
                SiteVerdictService.VerdictKind.Blocked =>
                    (Hex("#3A1414"), Hex("#E5534B"), Hex("#FF8A80")),
                SiteVerdictService.VerdictKind.DependencyBlocked =>
                    (Hex("#3A1414"), Hex("#E5534B"), Hex("#FF8A80")),
                SiteVerdictService.VerdictKind.LocalTlsBroken =>
                    (Hex("#3A1414"), Hex("#E5534B"), Hex("#FF8A80")),
                SiteVerdictService.VerdictKind.HandshakeDropping =>
                    (Hex("#3A2E14"), Hex("#E5A631"), Hex("#E5A631")),
                SiteVerdictService.VerdictKind.Steering =>
                    (Hex("#14243A"), Hex("#4A9EFF"), Hex("#7FB8FF")),
                SiteVerdictService.VerdictKind.FarAway =>
                    (Hex("#2E1A3A"), Hex("#B07CE5"), Hex("#CDA9F0")),
                _ => (Hex("#122A1A"), Hex("#3FB950"), Hex("#7EE2A8")),
            };
            VerdictPanel.Background = bg;
            VerdictPanel.BorderBrush = border;
            VerdictHeadline.Foreground = fg;
            VerdictPanel.Visibility = Visibility.Visible;

            EvidenceList.ItemsSource = verdict.Evidence;
            MathExpander.Visibility = Visibility.Visible;

            OpsList.ItemsSource = report.Operations
                .Select(op => $"{op.AtUtc.ToLocalTime():HH:mm:ss} [{op.Kind}] {op.Detail}")
                .ToList();
            OpsExpander.Visibility = Visibility.Visible;
        }

        /// <summary>
        /// Crosses the probe's failed addresses AND the dependency pass's
        /// in-window block hits against AutoScope's own blocked list (the
        /// BlockHitFeedService inventory cache). When something is blocked
        /// here, the evidence line says so and a one-click unblock appears —
        /// "go hunt for it in the firewall" is exactly the runaround this
        /// replaces. Two flavors: the site's own addresses failing TCP, and
        /// the login-failure shape where the site is fine but an address the
        /// page depends on was silently blocked mid-visit.
        /// </summary>
        private void MarkAutoCommandBlocked(SiteVerdictService.Verdict verdict,
            SiteProbeService.SiteProbeReport report,
            DependencyBlockService.Report dependency)
        {
            try
            {
                BlockHitFeedService.Instance.Start();   // idempotent; populates the cache
                bool IsBlocked(string ip) =>
                    BlockHitFeedService.Instance.BlockedIp(ip) != null;

                var direct = report.Edges
                    .Where(ed => ed.TcpConnectMs == null)
                    .Select(ed => ed.Ip)
                    .Where(ip => !string.IsNullOrEmpty(ip))
                    .Distinct()
                    .Where(IsBlocked)
                    .ToList();
                var deps = (dependency?.InWindow ?? new List<DependencyBlockService.Hit>())
                    .Select(h => h.Ip)
                    .Where(ip => !string.IsNullOrEmpty(ip))
                    .Distinct(System.StringComparer.OrdinalIgnoreCase)
                    .Where(IsBlocked)
                    .ToList();
                _unblockTargets = direct
                    .Union(deps, System.StringComparer.OrdinalIgnoreCase)
                    .ToList();
                if (_unblockTargets.Count == 0) { _unblockTargets = null; return; }

                var blockedSet = direct.ToHashSet(System.StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < verdict.Evidence.Count; i++)
                {
                    string line = verdict.Evidence[i];
                    foreach (string ip in blockedSet)
                    {
                        if (line.StartsWith(ip + ":", System.StringComparison.OrdinalIgnoreCase))
                        {
                            verdict.Evidence[i] = line + "  ← ON YOUR BLOCK LIST";
                            break;
                        }
                    }
                }

                if (direct.Count > 0)
                    verdict.NextStep =
                        $"{direct.Count} of this site's addresses are on AutoScope's block list — " +
                        "unblock them right here with the button below, then re-run the check. " +
                        verdict.NextStep;

                UnblockBtn.Content = deps.Count > 0 && direct.Count == 0
                    ? $"🚫 Unblock {deps.Count} address(es) this page depends on"
                    : $"🚫 Unblock {_unblockTargets.Count} blocked address(es) for this site";
                UnblockBtn.Visibility = Visibility.Visible;
            }
            catch { /* the verdict stands on its own if the lookup fails */ }
        }

        private async void UnblockBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_unblockTargets == null || _unblockTargets.Count == 0) return;
            var targets = _unblockTargets.ToList();

            var details = string.Join("\n", targets.Select(ip =>
            {
                var b = BlockHitFeedService.Instance.BlockedIp(ip);
                string since = b?.Created?.ToLocalTime().ToString("yyyy-MM-dd HH:mm") ?? "legacy rule";
                return $"  {ip}   (blocked since {since})";
            }));
            bool answer = await Dialogs.ConfirmAsync("Unblock these addresses?",
                $"Remove AutoScope's firewall block rules for:\n{details}\n\n" +
                "Only AutoScope's own rules are touched — nothing else on the firewall changes, " +
                "and you can re-block any address from the Blocks tab.");
            if (!answer) return;

            UnblockBtn.IsEnabled = false;
            try
            {
                int removed = 0;
                foreach (string ip in targets)
                    removed += await FirewallService.Instance.RemoveBlockRulesForIpAsync(ip);
                _unblockTargets = null;
                UnblockBtn.Visibility = Visibility.Collapsed;
                ProgressText.Text =
                    $"Unblocked — removed {removed} rule(s) across {targets.Count} address(es). " +
                    "Re-run the check to confirm the site is reachable.";
            }
            catch (Exception ex)
            {
                ProgressText.Text = $"Unblock failed: {ex.Message}";
            }
            finally
            {
                UnblockBtn.IsEnabled = true;
            }
        }

        // WinUI port: WPF BrushConverter does not exist — parse #RRGGBB directly
        private static Brush Hex(string hex)
        {
            hex = hex.TrimStart('#');
            byte r = Convert.ToByte(hex.Substring(0, 2), 16);
            byte g = Convert.ToByte(hex.Substring(2, 2), 16);
            byte b = Convert.ToByte(hex.Substring(4, 2), 16);
            return new SolidColorBrush(Color.FromArgb(255, r, g, b));
        }
    }
}
