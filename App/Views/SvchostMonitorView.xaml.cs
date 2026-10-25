using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.UI;
using AutoScope.Helpers;
using AutoScope.Models;
using AutoScope.Services;

namespace AutoScope.Views
{
    public partial class SvchostMonitorView : Page, IAiAuditable
    {
        private readonly ConcurrentDictionary<string, SvchostMonitorItem> _trackedIps = new();
        private readonly ObservableCollection<SvchostMonitorItem> _uiCollection = new();

        // WinUI port: WinUI has no CollectionViewSource — no live sorting and
        // no view-level Filter. The grid binds to this projection of
        // _uiCollection, kept sorted (high transmitters first, then newest
        // first, then remote IP) and TX-only-filtered by InsertInView /
        // RefreshView. _uiCollection stays the unfiltered master every other
        // loop in this view walks, exactly like the WPF default view did.
        private readonly ObservableCollection<SvchostMonitorItem> _viewCollection = new();
        private bool _txOnlyFilterOn;

        // WinUI port: the WPF Dispatcher/DispatcherTimer pair — obtained once
        private readonly DispatcherQueue _dispatcherQueue;

        private DnsResolutionService _dnsService;
        private SysmonWatcherService _sysmonService;
        private RawSocketSnifferService _snifferService;
        private readonly SysmonInstallerService _installerService = new();
        private bool _isMonitoring = false;
        private DispatcherQueueTimer _saveTimer;
        private DispatcherQueueTimer _lastSeenRefreshTimer;
        private readonly string _csvPath = "ultimate_autopilot_stats.csv";

        // Firewall blocks created from this monitor live in BlocksStore (v3
        // blocks.txt under %LOCALAPPDATA%\AutoCommand) — service identity is
        // captured at block time because the PID (and with it the identity)
        // dies with the process.

        // Live firewall truth for row marking: which remote IPs / executable
        // paths have block rules (any enabled rule = active, all disabled =
        // paused). Rebuilt from GetBlockedInventoryAsync after every
        // block/unblock, when the Blocked-rules window closes, and once a
        // minute to catch out-of-band changes (agent actions, wf.msc edits).
        private readonly HashSet<string> _activeIps = new();
        private readonly HashSet<string> _pausedIps = new();
        private readonly HashSet<string> _activeApps = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _pausedApps = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _blockNotes = new(StringComparer.OrdinalIgnoreCase);
        private DispatcherQueueTimer _blockStateTimer;
        private bool _blockStateSyncing;

        // Non-modal block feedback (message + Undo, auto-hides)
        private DispatcherQueueTimer _toastTimer;
        private string _toastUndoKind;
        private string _toastUndoKey;

        // High-transmitter threshold in bytes, persisted in tx_threshold.txt
        private long _txThreshold = 1024;
        private readonly string _txThresholdPath = "tx_threshold.txt";
        private bool _loadingThreshold = true;

        // Scheduled-task attribution for taskhostw rows (who/what/why launched)
        private readonly TaskAttributionService _taskAttribution = new();

        /// <summary>The live monitor instance — the Blocks tab reads current
        /// connections from it for its "last traffic" column.</summary>
        public static SvchostMonitorView Current { get; private set; }

        /// <summary>Newest live row still talking to this IP, or null — the
        /// Blocks tab's freshest "last traffic" source (beats the archive).</summary>
        public SvchostMonitorItem LiveRowForIp(string ip)
        {
            SvchostMonitorItem best = null;
            foreach (var item in _trackedIps.Values)
            {
                if (!string.Equals(item.RemoteIp, ip, StringComparison.OrdinalIgnoreCase)) continue;
                if (best == null || item.LastSeen > best.LastSeen) best = item;
            }
            return best;
        }

        /// <summary>Newest live row for an executable path, or null.</summary>
        public SvchostMonitorItem LiveRowForPath(string path)
        {
            SvchostMonitorItem best = null;
            foreach (var item in _trackedIps.Values)
            {
                if (!string.Equals(item.ImagePath, path, StringComparison.OrdinalIgnoreCase)) continue;
                if (best == null || item.LastSeen > best.LastSeen) best = item;
            }
            return best;
        }

        public SvchostMonitorView()
        {
            Current = this;
            InitializeComponent();

            // WinUI port: DispatcherQueue replaces the WPF Dispatcher
            _dispatcherQueue = DispatcherQueue.GetForCurrentThread();

            // WinUI port: the grid binds to the sorted/filtered projection
            SvchostGrid.ItemsSource = _viewCollection;

            // Most-recent-first order that keeps itself current: the LastSeen
            // setter raises PropertyChanged on every packet, and live sorting
            // repositions that row at the top. The Remote IP tiebreaker keeps
            // equal-timestamp rows in a stable order instead of reshuffling.
            // High transmitters sort ahead of everything (the red-pinned
            // heavy talkers), still most-recent-first within their group.
            // (WinUI has no ICollectionViewLiveShaping — the projection is
            // re-sorted/re-filtered by RefreshView() on the 10-second refresh
            // tick, when rows are added (InsertInView), and when the
            // threshold or the TX-only lens changes.)
        }

        private bool _isInitialized = false;

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            if (_isInitialized) return;
            _isInitialized = true;

            CheckSysmonStatus();

            _dnsService   = new DnsResolutionService();
            _sysmonService = new SysmonWatcherService(_trackedIps, _dnsService);
            _sysmonService.MonitorAllProcesses = true;
            _sysmonService.FilterKnownCloudIps = HideCloudCheck.IsChecked == true;
            _snifferService = new RawSocketSnifferService(_trackedIps);

            _sysmonService.OnError += ShowError;
            _sysmonService.OnNewConnectionTracked += AddToUi;

            _snifferService.OnError += ShowError;

            // Attribution errors are non-fatal (rows just lack task info)
            _taskAttribution.OnError += msg => { };
            _taskAttribution.Start();

            RefreshIgnoredUi();
            LoadBlockedEntries();
            RefreshBlockedUi();
            RefreshConfirmPrefsUi();
            LoadTxThreshold();

            // Mark rows whose IP/process already has firewall rules (includes
            // blocks created outside this monitor — the rules are the truth)
            _ = RefreshBlockStateFromFirewallAsync();
            // WinUI port: DispatcherTimer → DispatcherQueueTimer
            _blockStateTimer = _dispatcherQueue.CreateTimer();
            _blockStateTimer.Interval = TimeSpan.FromSeconds(60);
            _blockStateTimer.Tick += (s, args) => _ = RefreshBlockStateFromFirewallAsync();
            _blockStateTimer.Start();

            _toastTimer = _dispatcherQueue.CreateTimer();
            _toastTimer.Interval = TimeSpan.FromSeconds(6.5);
            _toastTimer.Tick += (s, args) => HideToast();

            // Setup auto-save every 1 hour
            _saveTimer = _dispatcherQueue.CreateTimer();
            _saveTimer.Interval = TimeSpan.FromHours(1);
            _saveTimer.Tick += (s, args) => SaveToCsv();

            // Refresh relative "Last Packet" column + DNS cache chip every 10 seconds
            _lastSeenRefreshTimer = _dispatcherQueue.CreateTimer();
            _lastSeenRefreshTimer.Interval = TimeSpan.FromSeconds(10);
            _lastSeenRefreshTimer.Tick += (s, args) =>
            {
                foreach (var item in _uiCollection)
                    item.RefreshLastSeenDisplay();

                // Rows outlive their processes — label the ones whose PID is
                // gone so a dead connection stops masquerading as a live one.
                MarkExitedProcesses();

                // Re-enqueue any rows still showing raw IPs (handles items loaded from CSV etc.)
                foreach (var item in _uiCollection)
                    _dnsService.EnqueueForResolution(item);

                // Fill in scheduled-task attribution as the event logs catch up
                foreach (var item in _uiCollection)
                    EnrichWithTaskInfo(item);

                // Resolve svchost rows' service identity (which -s service /
                // SCM tenant each instance is) — rows created mid-tick and
                // re-attributed rows land here on the next pass.
                foreach (var item in _uiCollection)
                    EnrichWithSvchostIdentity(item);

                // Rows whose name never resolved get one archive-backed
                // reveal attempt (one-shot per row — the day-file scan is
                // real disk work, and the archive does not grow backwards)
                foreach (var item in _uiCollection)
                    EnrichWithRevealedName(item);

                // WinUI port: WPF live sorting/filtering and the row-style
                // DataTriggers are approximated here on the refresh tick
                RefreshView();
                RefreshRowVisuals();

                DnsCacheChip.Text = $"DNS cache: {_dnsService.CacheCount} entries";
                UpdateHighTxChip();
                UpdateTxOnlyCheckLabel();
            };
            _lastSeenRefreshTimer.Start();

            // Start DNS service before Sysmon so first events can hit the cache
            _dnsService.Start();

            // Auto-start monitor on load
            ToggleMonitorBtn_Click(null, null);
        }

        private void CheckSysmonStatus()
        {
            if (!_installerService.IsSysmonInstalled())
            {
                SetupSysmonBtn.Visibility = Visibility.Visible;
                MonitorStatusText.Text = "Sysmon is not installed — install it from the Sysmon Audit tab. Network tracking will not work.";
            }
            else
            {
                SetupSysmonBtn.Visibility = Visibility.Collapsed;
            }
        }

        private async void SetupSysmonBtn_Click(object sender, RoutedEventArgs e)
        {
            SetupSysmonBtn.IsEnabled = false;

            // Inconsistent state = leftovers of a failed install (stale event
            // manifest registration / stray Sysmon64.exe) that make every
            // install attempt fail. Offer a guided repair instead.
            if (_installerService.DetectInstallState() == SysmonInstallState.Inconsistent)
            {
                await RepairSysmonFlowAsync();
                return;
            }

            MonitorStatusText.Text = "Downloading and configuring Sysmon... please wait.";

            var result = await _installerService.InstallAndConfigureAsync();
            if (result.Success)
            {
                await Dialogs.ShowInfoAsync("Success", "Sysmon has been successfully installed and configured for network tracking.");
                CheckSysmonStatus();
                MonitorStatusText.Text = "Sysmon ready. Click 'Start Monitor' to begin tracking.";
            }
            else
            {
                await Dialogs.ShowInfoAsync("Error", $"Failed to install Sysmon.\n\nDetails: {result.ErrorMessage}");
                SetupSysmonBtn.IsEnabled = true;
                MonitorStatusText.Text = "Sysmon is not installed — install it from the Sysmon Audit tab. Network tracking will not work.";
            }
        }

        private async Task RepairSysmonFlowAsync()
        {
            // WinUI port: MessageBox YesNo → Dialogs.ConfirmAsync (true = Yes)
            bool repair = await Dialogs.ConfirmAsync(
                "Sysmon repair",
                "Sysmon is in an inconsistent install state: leftovers of an earlier failed install " +
                "(a stale event-manifest registration and/or a stray Sysmon64.exe) make every install attempt fail.\n\n" +
                "Repair now? The leftovers will be removed and Sysmon reinstalled. " +
                "If Windows still holds the stale registration, a restart will be offered to finish the repair.");

            if (!repair)
            {
                SetupSysmonBtn.IsEnabled = true;
                MonitorStatusText.Text = "Sysmon repair cancelled. Network tracking will not work.";
                return;
            }

            MonitorStatusText.Text = "Repairing Sysmon... removing leftovers and reinstalling.";
            var repaired = await _installerService.RepairAsync();

            if (repaired.Success)
            {
                await Dialogs.ShowInfoAsync("Repair complete", "Sysmon repair completed and verified. No restart was needed.");
                CheckSysmonStatus();
                MonitorStatusText.Text = "Sysmon ready. Click 'Start Monitor' to begin tracking.";
                return;
            }

            if (repaired.RebootRequired)
            {
                bool restart = await Dialogs.ConfirmAsync(
                    "Sysmon repair — restart required",
                    "Windows still holds the stale Sysmon registration; it can only be cleared during a restart.\n\n" +
                    "Restart Windows now to finish the repair? Save your work first — the PC will reboot. " +
                    "After the restart AutoCommand will reinstall and verify Sysmon automatically.");

                if (restart)
                {
                    MonitorStatusText.Text = "Restarting Windows to complete the Sysmon repair...";
                    ProcessRunner.RunDetached("shutdown.exe",
                        "/r /t 10 /c \"AutoCommand: restarting to complete the Sysmon repair\"");
                    return;
                }

                await Dialogs.ShowInfoAsync("Repair pending restart",
                    "The repair will finish automatically after the next Windows restart: " +
                    "AutoCommand will reinstall and verify Sysmon on startup.");
                MonitorStatusText.Text = "Sysmon repair pending restart. Network tracking will not work until then.";
                return;
            }

            await Dialogs.ShowInfoAsync("Error", $"Sysmon repair failed.\n\nDetails: {repaired.ErrorMessage}");
            SetupSysmonBtn.IsEnabled = true;
            MonitorStatusText.Text = "Sysmon is not installed. Network tracking will not work.";
        }

        private void Filter_Changed(object sender, RoutedEventArgs e)
        {
            if (_sysmonService != null)
                _sysmonService.FilterKnownCloudIps = HideCloudCheck.IsChecked == true;
        }

        // -----------------------------------------------------------------------
        // TX-only view filter — off by default. When on, only one-way
        // transmitters (sent packets, never a reply) are shown. This is a
        // view lens only: unlike the cloud filter (ingestion-side), turning
        // it off restores the full grid, and rows keep accruing counters
        // either way.
        // -----------------------------------------------------------------------

        private void TxOnlyFilter_Changed(object sender, RoutedEventArgs e)
        {
            // Assigning Filter refreshes the view; with live filtering on
            // IsTxOnly, membership keeps itself current afterwards.
            // WinUI port: the WPF CollectionView Filter — flag + RefreshView
            _txOnlyFilterOn = TxOnlyCheck.IsChecked == true;
            RefreshView();
            UpdateTxOnlyCheckLabel();
        }

        private static bool TxOnlyPredicate(object o) =>
            o is SvchostMonitorItem m && m.IsTxOnly;

        /// <summary>
        /// Keeps the TX-only count in the checkbox label so users can see how
        /// many one-way transmitters are out there before switching the lens
        /// on (same cadence as the High TX chip).
        /// </summary>
        private void UpdateTxOnlyCheckLabel()
        {
            int count = 0;
            foreach (var item in _uiCollection)
                if (item.IsTxOnly) count++;
            TxOnlyCheck.Content = count == 0
                ? "TX-only (no reply)"
                : $"TX-only (no reply): {count}";
        }

        // -----------------------------------------------------------------------
        // High-transmitter threshold (pinned + tinted rows at/above it)
        // -----------------------------------------------------------------------

        private void LoadTxThreshold()
        {
            try
            {
                if (File.Exists(_txThresholdPath) &&
                    long.TryParse(File.ReadAllText(_txThresholdPath).Trim(), out long bytes) &&
                    bytes >= 0)
                {
                    _txThreshold = bytes;
                }
            }
            catch { /* first run or unreadable file — keep the 1 KB default */ }

            SvchostMonitorItem.TxThresholdBytes = _txThreshold;

            // Reflect the byte value in the number/unit controls
            long unit = _txThreshold >= 1048576 ? 1048576 : _txThreshold >= 1024 ? 1024 : 1;
            TxUnitCombo.SelectionChanged -= TxThreshold_Changed;
            foreach (var item in TxUnitCombo.Items.OfType<ComboBoxItem>())
                if (item.Tag is string tag && long.Parse(tag) == unit) item.IsSelected = true;
            TxUnitCombo.SelectionChanged += TxThreshold_Changed;
            TxThresholdBox.Text = (_txThreshold / unit).ToString();
            UpdateHighTxChip();
            _loadingThreshold = false;
        }

        private void TxThreshold_Changed(object sender, RoutedEventArgs e)
        {
            if (_loadingThreshold) return;

            if (!long.TryParse(TxThresholdBox.Text.Trim(), out long value) || value < 0)
                return; // mid-typing or invalid — keep the last valid threshold

            long unit = 1;
            if (TxUnitCombo.SelectedItem is ComboBoxItem unitItem && unitItem.Tag is string tag)
                long.TryParse(tag, out unit);

            _txThreshold = value * unit;
            SvchostMonitorItem.TxThresholdBytes = _txThreshold;
            try { File.WriteAllText(_txThresholdPath, _txThreshold.ToString()); }
            catch { /* persistence is best-effort — the live threshold still applies */ }

            // Re-sort immediately: live sorting reacts to per-row changes,
            // not to the shared threshold moving under them
            // WinUI port: CollectionView.Refresh() → RefreshView()
            RefreshView();
            UpdateHighTxChip();
        }

        private void UpdateHighTxChip()
        {
            int count = 0;
            foreach (var item in _uiCollection)
                if (item.IsHighTransmitter) count++;
            HighTxCountText.Text = $"High TX: {count} ≥ {FormatThreshold(_txThreshold)}";
        }

        private static string FormatThreshold(long bytes) =>
            bytes >= 1048576 ? $"{bytes / 1048576.0:0.#} MB" :
            bytes >= 1024 ? $"{bytes / 1024.0:0.#} KB" : $"{bytes} B";

        /// <summary>
        /// Labels rows whose process has exited. The PID snapshot is taken on
        /// a background thread (Process.GetProcesses is not free) and applied
        /// on the UI thread; the flag is sticky — only a Sysmon
        /// re-attribution (a new PID on the same remote IP) can clear it.
        /// </summary>
        private async void MarkExitedProcesses()
        {
            try
            {
                var alive = new HashSet<int>();
                await Task.Run(() =>
                {
                    foreach (var p in Process.GetProcesses())
                        alive.Add(p.Id);
                });

                foreach (var item in _uiCollection)
                {
                    if (item.ProcessId <= 0 || item.HasExited) continue; // System/Idle never exits
                    if (!alive.Contains(item.ProcessId))
                        item.MarkExited();
                }
            }
            catch { /* snapshot failed — retried on the next tick */ }
        }

        private void ShowError(string msg)
        {
            // WinUI port: Dispatcher.Invoke → DispatcherQueue.TryEnqueue
            _dispatcherQueue.TryEnqueue(async () =>
            {
                await Dialogs.ShowInfoAsync("Monitor Error", msg);
                if (_isMonitoring) ToggleMonitorBtn_Click(null, null); // Stop on critical error
            });
        }

        private void AddToUi(SvchostMonitorItem item)
        {
            // WinUI port: Dispatcher.Invoke → DispatcherQueue.TryEnqueue
            _dispatcherQueue.TryEnqueue(() =>
            {
                // The event may have raced with the user adding an ignore entry
                if (_sysmonService.IsProcessIgnored(item.ProcessName))
                {
                    _trackedIps.TryRemove(item.RemoteIp, out _);
                    return;
                }
                EnrichWithTaskInfo(item);
                EnrichWithSvchostIdentity(item);
                // A blocked IP reappearing as a fresh row shows ⛔ immediately,
                // not only after the next sync pass
                ApplyBlockState(item);
                _uiCollection.Add(item);
                // WinUI port: live sorting positioned new rows via the
                // collection view — insert into the sorted projection instead
                InsertInView(item);
            });
        }

        /// <summary>
        /// Stamps scheduled-task attribution (task path + user) onto taskhostw
        /// rows once the event logs have caught up with the launch.
        /// </summary>
        private void EnrichWithTaskInfo(SvchostMonitorItem item)
        {
            if (item.TaskName != null) return;
            var info = _taskAttribution.GetTaskForPid(item.ProcessId, item.ProcessStartedUtc);
            if (info == null || string.IsNullOrEmpty(info.TaskPath)) return;
            item.SetTaskInfo(info.TaskPath, info.UserContext);
        }

        /// <summary>
        /// Resolves a svchost row's service identity (SCM-hosted services +
        /// -k/-s command-line tokens) on a background thread and stamps it on
        /// the UI thread. One attempt per row at a time; the 10-second timer
        /// retries rows still unresolved (fresh spawns, re-attributed tenants).
        /// </summary>
        private async void EnrichWithSvchostIdentity(SvchostMonitorItem item)
        {
            if (!item.TryBeginIdentity()) return;
            int pid = item.ProcessId;
            try
            {
                var id = await Task.Run(() => Services.SvchostIdentityService.Resolve(pid));
                // The row may have been re-attributed while the WMI query ran —
                // the identity belongs to the old tenant, not the new one.
                if (item.ProcessId != pid) { item.AbandonIdentity(); return; }
                item.SetSvchostIdentity(id.ServicesCsv, id.ServicesDetail, id.Group, id.DeclaredService,
                                        id.CommandLineVisible, id.Mismatch || id.NoK);
            }
            catch
            {
                item.AbandonIdentity(); // retried on the next timer tick
            }
        }

        private void ToggleMonitorBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!_isMonitoring)
            {
                _sysmonService.Start();
                _snifferService.Start();
                _saveTimer.Start();

                ToggleMonitorBtn.Content = "Stop Monitor";
                MonitorStatusText.Text = "Monitor active: Sysmon event listening and Raw Socket sniffing enabled.";
                _isMonitoring = true;

                // Baseline: connections opened before Start never fire a
                // Sysmon ID 3 (svchost's boot-time WNS channel and other
                // long-lived sockets) — seed rows for everything established
                // right now, then let live events take over. Off the UI
                // thread: it does a PID/path lookup per connection.
                _ = Task.Run(() =>
                {
                    int seeded = _sysmonService.SeedBaseline();
                    // WinUI port: Dispatcher.BeginInvoke → TryEnqueue
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        if (_isMonitoring)
                            MonitorStatusText.Text =
                                $"Monitor active: Sysmon events + raw socket sniffing · {seeded} existing connection(s) seeded";
                    });
                });
            }
            else
            {
                _sysmonService.Stop();
                _snifferService.Stop();
                _saveTimer.Stop();

                ToggleMonitorBtn.Content = "Start Monitor";
                MonitorStatusText.Text = "Monitor is stopped.";
                _isMonitoring = false;
            }
        }

        // -----------------------------------------------------------------------
        // Process ignore list
        // -----------------------------------------------------------------------

        private void IgnoreProcessBox_KeyDown(object sender, KeyRoutedEventArgs e)
        {
            // WinUI port: WPF Key.Enter → VirtualKey.Enter
            if (e.Key == Windows.System.VirtualKey.Enter) IgnoreProcessBtn_Click(sender, e);
        }

        private void IgnoreProcessBtn_Click(object sender, RoutedEventArgs e)
        {
            string procName = IgnoreProcessBox.Text.Trim();
            if (string.IsNullOrEmpty(procName)) return;

            IgnoreProcess(procName);
            IgnoreProcessBox.Text = ""; // WinUI port: WPF TextBox.Clear() does not exist
        }

        private void IgnoreRowMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is SvchostMonitorItem item && !string.IsNullOrEmpty(item.ProcessName))
                IgnoreProcess(item.ProcessName);
        }

        // WinUI port: ContextMenu.Opened → MenuFlyout (FlyoutBase).Opened, and
        // MenuItem.Header → MenuFlyoutItem.Text
        private void RowMenu_Opened(object sender, object e)
        {
            var sel = SvchostGrid.SelectedItem as SvchostMonitorItem;

            bool traceable = sel != null && sel.ProcessId > 0;
            TracePidMenuItem.IsEnabled = traceable;
            TracePidMenuItem.Text = traceable
                ? $"🔎 Trace PID {sel.ProcessId} — how was it spawned?"
                : "🔎 Trace: how was this PID spawned?";

            bool revealable = sel != null && sel.ProcessId > 0;
            RevealNameMenuItem.IsEnabled = revealable;
            RevealNameMenuItem.Text = revealable
                ? $"🏷 Reveal real name of PID {sel.ProcessId} (Sysmon record)"
                : "🏷 Reveal real process name (Sysmon record)";

            IgnoreRowMenuItem.Text = sel != null && !string.IsNullOrEmpty(sel.ProcessName)
                ? $"🚫 Ignore process '{sel.ProcessName}'"
                : "🚫 Ignore process (no row selected)";

            // Block items tell the current state: flip to Unblock when a
            // block exists, and explain (disabled) when it is only paused —
            // re-blocking a paused target would silently not block anything.
            bool validIp = sel != null && System.Net.IPAddress.TryParse(sel.RemoteIp, out _);
            if (validIp && sel.IpBlockState == BlockRuleState.Active)
            {
                BlockIpMenuItem.IsEnabled = true;
                BlockIpMenuItem.Text = $"✅ Unblock remote IP {sel.RemoteIp} — traffic resumes";
            }
            else if (validIp && sel.IpBlockState == BlockRuleState.Paused)
            {
                BlockIpMenuItem.IsEnabled = false;
                BlockIpMenuItem.Text = $"⏸ IP block for {sel.RemoteIp} is paused — re-enable from 'Blocked' → Manage all";
            }
            else
            {
                BlockIpMenuItem.IsEnabled = validIp;
                BlockIpMenuItem.Text = validIp
                    ? $"⛔ Block remote IP {sel.RemoteIp} in Firewall"
                    : "⛔ Block Remote IP in Firewall";
            }

            bool blockableProcess = sel != null && sel.ProcessId > 0;
            if (blockableProcess && sel.ProcessBlockState == BlockRuleState.Active)
            {
                BlockProcessMenuItem.IsEnabled = true;
                BlockProcessMenuItem.Text = $"✅ Unblock process '{sel.ProcessName}' — traffic resumes";
            }
            else if (blockableProcess && sel.ProcessBlockState == BlockRuleState.Paused)
            {
                BlockProcessMenuItem.IsEnabled = false;
                BlockProcessMenuItem.Text = "⏸ Process block is paused — re-enable from 'Blocked' → Manage all";
            }
            else
            {
                BlockProcessMenuItem.IsEnabled = blockableProcess;
                BlockProcessMenuItem.Text = blockableProcess && !string.IsNullOrEmpty(sel.ProcessName)
                    ? $"⛔ Block process '{sel.ProcessName}' in Firewall"
                    : "⛔ Block Process in Firewall";
            }

            bool killable = sel != null && sel.ProcessId > 0;
            KillProcessMenuItem.IsEnabled = killable;
            KillProcessMenuItem.Text = killable && !string.IsNullOrEmpty(sel.ProcessName)
                ? $"💀 Kill process '{sel.ProcessName}' (PID {sel.ProcessId})"
                : "💀 Kill process";

            bool hasTask = sel != null && !string.IsNullOrEmpty(sel.TaskName);
            TaskDetailsMenuItem.IsEnabled = hasTask;
            TaskDetailsMenuItem.Text = hasTask
                ? $"📋 Scheduled task '{sel.TaskName}'"
                : "📋 Scheduled task details";
            DisableTaskMenuItem.IsEnabled = hasTask;
        }

        private void IgnoredListBtn_Click(object sender, RoutedEventArgs e)
        {
            RefreshIgnoredUi();
            // WinUI port: Popup placement under the button (see OpenPopupBelow)
            OpenPopupBelow(IgnoredListPopup, IgnoredListBtn);
        }

        private void RemoveIgnoredBtn_Click(object sender, RoutedEventArgs e)
        {
            if (IgnoredListBox.SelectedItem is string name)
            {
                _sysmonService.RemoveIgnoredProcess(name);
                RefreshIgnoredUi();
            }
        }

        /// <summary>
        /// Hides a process name from the list: adds it to the persisted ignore
        /// list, then removes any rows already on screen for it.
        /// </summary>
        private void IgnoreProcess(string procName)
        {
            _sysmonService.AddIgnoredProcess(procName);
            PruneIgnoredRows();
            RefreshIgnoredUi();
        }

        /// <summary>Drops rows whose process is now ignored (list + packet counters).</summary>
        private void PruneIgnoredRows()
        {
            foreach (var item in _uiCollection.Where(i => _sysmonService.IsProcessIgnored(i.ProcessName)).ToList())
            {
                _uiCollection.Remove(item);
                _viewCollection.Remove(item); // WinUI port: keep the projection in step
                _trackedIps.TryRemove(item.RemoteIp, out _);
            }
        }

        private void RefreshIgnoredUi()
        {
            var ignored = _sysmonService.IgnoredProcesses;
            IgnoredListBtn.Content = $"Ignored: {ignored.Count}";
            IgnoredListBox.ItemsSource = ignored.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
        }

        // WinUI port: the WPF PreviewMouseRightButtonDown (select row) and
        // MouseDoubleClick (open PID trace) handlers — the toolkit DataGrid
        // has neither, so both are wired per realized row in LoadingRow.
        private void SvchostGrid_LoadingRow(object sender, DataGridRowEventArgs e)
        {
            // Rows recycle, so detach first to avoid stacking handlers
            e.Row.DoubleTapped -= Row_DoubleTapped;
            e.Row.DoubleTapped += Row_DoubleTapped;
            e.Row.RightTapped -= Row_RightTapped;
            e.Row.RightTapped += Row_RightTapped;
            // Triggers are gone in WinUI — apply the tint/fade once the row's
            // cells exist (deferred one dispatcher pass past row realization)
            _ = _dispatcherQueue.TryEnqueue(() => ApplyRowVisuals(e.Row));
        }

        private void Row_RightTapped(object sender, RightTappedRoutedEventArgs e)
        {
            // Right-click selects the row under the cursor so the "Ignore
            // process" menu item knows which process was meant.
            if (sender is DataGridRow row)
            {
                SvchostGrid.SelectedItem = row.DataContext;
                // WinUI port: the WPF ContextMenu opened itself — show the
                // menu flyout at the pointer
                RowMenu.ShowAt(row, e.GetPosition(row));
                e.Handled = true;
            }
        }

        private void Row_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
        {
            // Double-clicking a row opens the spawn-chain trace — the same
            // PID inquiry as the context menu's "Trace" item. Clicks on
            // column headers or empty space fall through to nothing.
            if (sender is DataGridRow row && row.DataContext is SvchostMonitorItem item)
            {
                SvchostGrid.SelectedItem = item;
                OpenPidTrace(item.ProcessId, item);
            }
        }

        // -----------------------------------------------------------------------
        // PID inquiry — provenance tracing ("how was this spawned?")
        // -----------------------------------------------------------------------

        private void TracePidMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is SvchostMonitorItem item)
                OpenPidTrace(item.ProcessId, item);
        }

        /// <summary>
        /// Opens the read-only PID inquiry window. Row hints (name, Sysmon
        /// image path, task attribution) travel along so the report stays
        /// meaningful even when the process has already exited.
        /// </summary>
        // WinUI port: async for the ContentDialog; Owner dropped (WinUI has
        // no window ownership); Show() → Activate()
        private async void OpenPidTrace(int pid, SvchostMonitorItem item)
        {
            if (pid <= 0)
            {
                await Dialogs.ShowInfoAsync("PID Inquiry",
                    "The System/Idle process has no spawn chain to trace.");
                return;
            }
            var win = new ProcessTraceWindow(
                pid,
                item?.ProcessName,
                item?.ImagePath,
                item != null ? _taskAttribution.GetTaskForPid(pid, item.ProcessStartedUtc) : null,
                item?.LastSeen,          // hints are as-of the last traffic sighting (UTC)
                item?.ProcessStartedUtc); // capture-time process start — strongest tenant check
            // Trace→row loop: whatever the inquiry establishes about
            // identity flows back onto the row (RevealFromReport below) —
            // until now that finding died with the window.
            // WinUI port: Dispatcher.Invoke → DispatcherQueue.TryEnqueue
            win.ReportCollected += report => _dispatcherQueue.TryEnqueue(() => RevealFromReport(item, report));
            // WinUI port: Show() → Activate()
            win.Activate();
        }

        /// <summary>
        /// Writes a PID Inquiry's resolved identity back onto its row.
        /// Skipped when the report describes a different tenant of the PID
        /// than the row anchors (start times disagree by more than the
        /// 5-second capture tolerance) — then the finding belongs to some
        /// other process, not this row.
        /// </summary>
        private void RevealFromReport(SvchostMonitorItem item, ProvenanceReport report)
        {
            if (item == null || report == null || string.IsNullOrEmpty(report.ExePath)) return;
            if (item.ProcessStartedUtc.HasValue && report.Created.HasValue &&
                (report.Created.Value.ToUniversalTime() - item.ProcessStartedUtc.Value).Duration() > TimeSpan.FromSeconds(5))
                return;
            string parent = report.Chain.Count > 1
                ? (report.Chain[1].ExePath ?? report.Chain[1].Name)
                : null;
            item.RevealIdentity(report.ExePath, report.ExePath, parent);
        }

        /// <summary>
        /// Context-menu reveal: recovers the row's true identity from the
        /// Sysmon archive — the same anchored recovery the PID Inquiry
        /// performs — and corrects the row in place. For rows named by a
        /// recycled PID, never named at all, or just to learn the parent.
        /// </summary>
        private async void RevealNameMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item || item.ProcessId <= 0) return;

            var records = await Task.Run(() =>
                SysmonArchiveService.SearchCreateEvents(item.ProcessId, 12));
            var rec = PickBestCreateRecord(records, item);
            if (rec == null || !rec.Data.TryGetValue("Image", out string image) || string.IsNullOrEmpty(image))
            {
                ShowToast($"🏷 No Sysmon create-event found for PID {item.ProcessId} — nothing to reveal.\n" +
                          "The live-log attempt may still know more: '🔎 Trace: how was this PID spawned?'.");
                return;
            }

            rec.Data.TryGetValue("ParentImage", out string parent);
            string before = item.ProcessName;
            item.RevealIdentity(image, image, parent);

            string toast = string.Equals(before, item.ProcessName, StringComparison.OrdinalIgnoreCase)
                ? $"🏷 Confirmed '{item.ProcessName}' is the real name (Sysmon record)."
                : $"🏷 Real name revealed: '{item.ProcessName}'" +
                  (string.IsNullOrEmpty(before) ? "." : $" — the row previously showed '{before}'.");
            if (!string.IsNullOrEmpty(parent))
                toast += $"\nSpawned by {System.IO.Path.GetFileName(parent)}.";
            ShowToast(toast);
        }

        /// <summary>
        /// One archive-backed identity attempt for rows whose name never
        /// resolved (process gone before any lookup, event without an
        /// image). One-shot per row via TryBeginNameProbe: the day-file
        /// scan is real disk work, and the archive does not grow
        /// backwards — a miss will stay a miss.
        /// </summary>
        private async void EnrichWithRevealedName(SvchostMonitorItem item)
        {
            if (!item.NeedsNameReveal || !item.TryBeginNameProbe()) return;

            var records = await Task.Run(() =>
                SysmonArchiveService.SearchCreateEvents(item.ProcessId, 12));
            var rec = PickBestCreateRecord(records, item);
            if (rec == null) return;
            if (!rec.Data.TryGetValue("Image", out string image) || string.IsNullOrEmpty(image)) return;
            rec.Data.TryGetValue("ParentImage", out string parent);
            item.RevealIdentity(image, image, parent);
        }

        // -----------------------------------------------------------------------
        // Firewall blocking (remote IP / process)
        // -----------------------------------------------------------------------

        /// <summary>
        /// Builds the v3 block record from everything the monitor row knows
        /// RIGHT NOW — the moment identity is richest. The PID dies later;
        /// the record must not.
        /// </summary>
        private static BlockRecord BuildBlockRecord(SvchostMonitorItem item, string kind, string key)
        {
            string serviceKey = "", display = "";
            string attrib = "none";

            if (item != null && item.IsSvchost)
            {
                // Identity preference: the -s declared single tenant, then the
                // first SCM-resident service, then the -k group, then unknown.
                string csv = item.HostedServicesCsv;
                string declared = item.DeclaredService;
                if (!string.IsNullOrEmpty(declared))
                    serviceKey = declared.ToLowerInvariant();
                else if (!string.IsNullOrEmpty(csv))
                    serviceKey = csv.Split(',')[0].Trim().ToLowerInvariant();
                else if (!string.IsNullOrEmpty(item.SvchostGroup))
                    serviceKey = "svchost:" + item.SvchostGroup.ToLowerInvariant();
                if (serviceKey.Length > 0 && serviceKey != "svchost:unresolved")
                    attrib = "live";
                if (serviceKey.Length == 0) serviceKey = "svchost:unresolved";
            }
            else if (item != null && !string.IsNullOrEmpty(item.ProcessName) &&
                     !item.ProcessName.StartsWith("<", StringComparison.Ordinal))
            {
                serviceKey = System.IO.Path.GetFileNameWithoutExtension(item.ProcessName).ToLowerInvariant();
                attrib = "catalog";
            }

            if (serviceKey.Length > 0)
                display = ServiceCatalog.TryGet(serviceKey, out var c) ? c.DisplayName : "";

            return new BlockRecord
            {
                Kind = kind,
                Key = key,
                ProcessName = item?.ProcessName ?? "",
                CreatedUtc = DateTime.UtcNow,
                ServiceKey = serviceKey,
                SvcDisplayName = display,
                ClassAtBlock = kind == "ip"
                    ? IpClassifier.Classify(key)
                    : ClassForPath(key),
                Origin = "monitor",
                Attrib = attrib,
                Status = "on",
                StatusUtc = DateTime.UtcNow,
            };
        }

        // WinUI port: BlocksStore.ClassForPath is internal to the Core
        // assembly — local copy of its logic so the record stays identical
        private static string ClassForPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return "Application";
            string lower = path.ToLowerInvariant();
            if (lower.Contains("\\windows\\") || lower.StartsWith("c:\\windows")) return "Windows component";
            if (lower.Contains("\\programdata\\microsoft\\windows defender")) return "Windows Defender";
            return "Application";
        }

        private async void BlockRemoteIP_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item) return;

            string ip = item.RemoteIp;
            if (!System.Net.IPAddress.TryParse(ip, out _))
            {
                await Dialogs.ShowInfoAsync("Info", $"'{ip}' is not a valid IP address.");
                return;
            }

            // The menu flips to "Unblock" once a block exists — the same
            // item removes it again.
            if (item.IpBlockState == BlockRuleState.Active)
            {
                await ConfirmAndRemoveBlockAsync("ip", ip);
                return;
            }
            if (item.IpBlockState == BlockRuleState.Paused)
            {
                ShowToast($"⏸ The block for {ip} is paused (traffic flows). Re-enable it from 'Blocked' → Manage all.");
                return;
            }

            string msWarning = IpClassifier.WarningText(ip); // "" when not Microsoft infrastructure
            bool msApplies = msWarning.Length > 0;

            // Per-class suppression: the prompt is skipped only when the
            // generic confirm AND (if applicable) the Microsoft-infra warning
            // are both silenced — a silenced generic confirm still shows the
            // dialog when the infra warning itself is not silenced.
            bool confirmSuppressed =
                ConfirmPrefs.IsSuppressed(ConfirmPrefs.ConfirmIp) &&
                (!msApplies || ConfirmPrefs.IsSuppressed(ConfirmPrefs.WarnMsInfra));

            if (!confirmSuppressed)
            {
                string warning = msApplies && !ConfirmPrefs.IsSuppressed(ConfirmPrefs.WarnMsInfra)
                    ? msWarning + "\n\n⚠ Think twice: this IP is Microsoft infrastructure."
                    : "";
                string detail = $"Contacted by '{item.ProcessName}'.\n\n" +
                                "2 rules are created: outbound TCP and UDP — inbound is already covered by the\n" +
                                "firewall's stateful filtering.\n" +
                                "Undo anytime: the Undo button on the toast, right-click this row again,\nor 'Blocked' → Manage all.";
                // The checkbox silences the highest-severity thing on screen:
                // the infra warning when present, otherwise the plain confirm.
                string key = warning.Length > 0 ? ConfirmPrefs.WarnMsInfra : ConfirmPrefs.ConfirmIp;
                string label = warning.Length > 0
                    ? "Don't warn me about Microsoft-infrastructure IPs — I know what I'm doing"
                    : "Don't ask again before blocking remote IPs";
                if (!await ConfirmBlockWithDialog($"Block all outbound traffic to remote IP {ip}?", warning, detail, key, label))
                    return;
            }

            try
            {
                string note = BuildProvenance(item, $"→ {ip}", confirmSuppressed);
                var (created, updated) = await FirewallService.Instance.AddIpBlockAsync(ip, note);
                RecordBlockedEntry(item, "ip", ip);
                _ = RefreshBlockStateFromFirewallAsync();
                ShowToast(created > 0
                        ? $"⛔ Blocked remote IP {ip} — 2 rules (outbound TCP/UDP).\nProvenance written to the rule description (visible in wf.msc)."
                        : $"Block for {ip} already existed — refreshed its provenance (no duplicate rules).",
                    "ip", ip);
            }
            catch (Exception ex)
            {
                await Dialogs.ShowInfoAsync("Error", $"Failed to block remote IP: {ex.Message}");
            }
        }

        private async void BlockProcess_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item) return;

            if (item.ProcessId == 0)
            {
                await Dialogs.ShowInfoAsync("Info", "Cannot block System/Idle process.");
                return;
            }

            // A process that "ran away" (already exited) is still blockable:
            // the firewall rule matches the exe path and arms for the next
            // run. The only real problems are recovering that path and never
            // mistaking a recycled PID's new tenant for the suspect.
            var target = await ResolveBlockTargetAsync(item);
            string path = target.Path;
            if (string.IsNullOrEmpty(path))
            {
                await Dialogs.ShowInfoAsync("Process already exited — cannot block",
                    $"'{item.ProcessName}' (PID {item.ProcessId}) already exited, and its executable path could not be recovered:\n" +
                    "the row carries no Sysmon image path and the 30-day archive holds no create-event for this PID.\n\n" +
                    "Firewall rules match a full path, so there is nothing to arm the block on.\n" +
                    (string.IsNullOrEmpty(item.RemoteIp)
                        ? ""
                        : "You can still act on the infrastructure it used: right-click the row →\n" +
                      $"'⛔ Block Remote IP in Firewall' for {item.RemoteIp}.\n") +
                    "'🔎 Trace: how was this PID spawned?' shows everything recorded about the exited process.");
                return;
            }

            if (item.ProcessBlockState == BlockRuleState.Active)
            {
                await ConfirmAndRemoveBlockAsync("proc", path);
                return;
            }
            if (item.ProcessBlockState == BlockRuleState.Paused)
            {
                ShowToast($"⏸ The block for {path} is paused (traffic flows). Re-enable it from 'Blocked' → Manage all.");
                return;
            }

            string warning = "";
            if (string.Equals(item.ProcessName, "svchost.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(item.ProcessName, "taskhostw.exe", StringComparison.OrdinalIgnoreCase))
                warning = $"'{item.ProcessName}' hosts Windows SERVICES. One instance carries DNS (Dnscache),\n" +
                          "DHCP, diagnostics and more — blocking it is the #1 cause of 'I blocked something\n" +
                          "and lost my internet'. If a specific connection looks bad, block the IP, not this process.";
            else if (path.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase))
                warning = $"'{item.ProcessName}' is a Windows component. Blocking it can break shell features,\n" +
                          "widgets, or web content in Start/Settings.";

            bool coreApplies = warning.Length > 0;
            bool confirmSuppressed =
                ConfirmPrefs.IsSuppressed(ConfirmPrefs.ConfirmProcess) &&
                (!coreApplies || ConfirmPrefs.IsSuppressed(ConfirmPrefs.WarnWindowsCore));

            // The ran-away note is information, not a warning class: it rides
            // whichever surface the user sees (the dialog when a prompt is
            // due, otherwise the success toast) rather than adding a fifth
            // suppressible prompt.
            string exitedNote = target.SubjectExited
                ? "⚠ This process has already exited — the block is preventive:\n" +
                  "the rule takes effect on the exe's NEXT run. A copy of the exe at a\n" +
                  "different path is NOT covered." +
                  (target.ReuseNote != null ? $"\n⚠ {target.ReuseNote}." : "") +
                  (target.Source == BlockPathSource.Archive
                      ? "\nPath recovered from the Sysmon archive (create-event for this PID)."
                      : "") + "\n\n"
                : "";

            if (!confirmSuppressed)
            {
                string shownWarning = coreApplies && !ConfirmPrefs.IsSuppressed(ConfirmPrefs.WarnWindowsCore) ? warning : "";
                string detail = exitedNote + $"{path}\n\n(1 outbound rule)\n" +
                                "Undo anytime: the Undo button on the toast, right-click the row again,\nor 'Blocked' → Manage all.";
                string key = shownWarning.Length > 0 ? ConfirmPrefs.WarnWindowsCore : ConfirmPrefs.ConfirmProcess;
                string label = shownWarning.Length > 0
                    ? "Don't warn me about blocking Windows service hosts / components — I know what I'm doing"
                    : "Don't ask again before blocking processes";
                if (!await ConfirmBlockWithDialog(
                        target.SubjectExited
                            ? "Process already exited — block its executable for next time?"
                            : "Block all outbound network traffic for this process?",
                        shownWarning, detail, key, label))
                    return;
            }

            try
            {
                // Ran-away blocks say so in the rule description — auditable
                // in wf.msc that the rule was armed on an exited process and
                // where the path was recovered from.
                string tags = null;
                if (target.SubjectExited)
                {
                    if (target.ReuseNote != null) tags = "exited · pid-reused";
                    else if (target.Source == BlockPathSource.Archive) tags = "exited · path-from-archive";
                    else tags = "exited";
                }
                string note = BuildProvenance(item, $"app: {path}", confirmSuppressed, tags);
                var (created, updated) = await FirewallService.Instance.AddAppBlockAsync(path, note);
                RecordBlockedEntry(item, "proc", path);
                _ = RefreshBlockStateFromFirewallAsync();
                string toast = created > 0
                    ? $"⛔ Blocked application (1 outbound rule):\n{path}"
                    : $"Block for {System.IO.Path.GetFileName(path)} already existed — provenance refreshed.";
                if (target.SubjectExited)
                    toast += "\nThe process had already exited — the rule arms its next run.";
                ShowToast(toast, "proc", path);
            }
            catch (Exception ex)
            {
                await Dialogs.ShowInfoAsync("Error", $"Failed to block process: {ex.Message}");
            }
        }

        /// <summary>
        /// Shows the block confirmation window (warning + "don't ask again"
        /// check-off). MessageBox cannot host the checkbox, hence the dialog;
        /// a checked box persists the per-class suppression immediately.
        /// </summary>
        // WinUI port: WPF modal ShowDialog — WinUI windows are non-modal, so
        // await the window's Closed and read its Confirmed/Suppress state;
        // Owner dropped. The method became async and its call sites await it.
        private async Task<bool> ConfirmBlockWithDialog(string headline, string warning, string detail,
                                                        string suppressKey, string suppressLabel)
        {
            var win = new BlockConfirmWindow(headline, warning, detail, suppressKey, suppressLabel);
            var done = new TaskCompletionSource<bool>();
            win.Closed += (s, args) => done.TrySetResult(win.Confirmed);
            win.Activate();
            if (!await done.Task) return false;
            if (win.Suppress) ConfirmPrefs.Suppress(suppressKey);
            return true;
        }

        /// <summary>Full provenance embedded into the firewall rule Description.</summary>
        private static string BuildProvenance(SvchostMonitorItem item, string what, bool confirmSuppressed = false,
                                              string tags = null)
        {
            string host = "";
            try { host = item.HostnameDisplay is string h && h.Contains("…") == false && h != "resolving…" ? $" host {h}" : ""; } catch { }
            // svchost blocks say which service was actually blocked — the
            // identity survives in wf.msc even after the PID is recycled
            string svc = item.HasServiceIdentity ? $" [{item.IdentityLabel}]" : "";
            // Blocks made under a suppressed prompt say so — auditable later
            // in wf.msc that the standard confirmation was skipped
            return $"[blocked {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC] {item.ProcessName}{svc} PID {item.ProcessId} {what}{host} · " +
                   $"rx {item.RxBytesDisplay} tx {item.TxBytesDisplay}" +
                   $"{(string.IsNullOrEmpty(tags) ? "" : $" · {tags}")}" +
                   $"{(confirmSuppressed ? " · confirm-suppressed" : "")} · AutoCommand Process Monitor";
        }

        private void BlockedListBtn_Click(object sender, RoutedEventArgs e)
        {
            RefreshBlockedUi();
            // WinUI port: Popup placement under the button (see OpenPopupBelow)
            OpenPopupBelow(BlockedListPopup, BlockedListBtn);
        }

        private void ManageBlockedBtn_Click(object sender, RoutedEventArgs e)
        {
            BlockedListPopup.IsOpen = false;
            // WinUI port: Owner dropped; Show() → Activate()
            var win = new BlockedRulesWindow();
            // Unblock/re-enable there must be reflected in this grid's glyphs
            win.Closed += (s, args) => _ = RefreshBlockStateFromFirewallAsync();
            win.Activate();
        }

        private async void UnblockBtn_Click(object sender, RoutedEventArgs e)
        {
            if (BlockedListBox.SelectedItem is not BlockRecord entry) return;
            await ConfirmAndRemoveBlockAsync(entry.Kind, entry.Key);
        }

        /// <summary>Asks once, then removes the block (rules + monitor record) and toasts the outcome.</summary>
        private async Task ConfirmAndRemoveBlockAsync(string kind, string key)
        {
            // WinUI port: MessageBox YesNo → Dialogs.ConfirmAsync (true = Yes)
            if (!await Dialogs.ConfirmAsync("Confirm Unblock",
                $"Remove the firewall block for\n{key}?\n\nIts rules are deleted and traffic resumes immediately.")) return;
            await RemoveBlockCoreAsync(kind, key);
        }

        /// <summary>Removes the firewall rules and the blocked.txt record; reports via toast.</summary>
        private async Task RemoveBlockCoreAsync(string kind, string key)
        {
            try
            {
                int removed = kind == "ip"
                    ? await FirewallService.Instance.RemoveBlockRulesForIpAsync(key)
                    : await FirewallService.Instance.RemoveBlockRulesForAppAsync(key);

                BlocksStore.Remove(kind, key);
                RefreshBlockedUi();
                _ = RefreshBlockStateFromFirewallAsync();
                ShowToast(removed > 0
                        ? $"✅ Unblocked {key} — {removed} firewall rule(s) removed, traffic resumes."
                        : $"No matching firewall rules found for {key} (already removed?).");
            }
            catch (Exception ex)
            {
                await Dialogs.ShowInfoAsync("Error", $"Failed to unblock: {ex.Message}");
            }
        }

        private void ResetConfirmPrefsBtn_Click(object sender, RoutedEventArgs e)
        {
            ConfirmPrefs.ResetAll();
            RefreshConfirmPrefsUi();
            ShowToast("↩ Confirmation prompts restored — blocks will ask again (each warning class, until re-suppressed).");
        }

        private async void KillProcess_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item) return;

            if (item.ProcessId == 0)
            {
                await Dialogs.ShowInfoAsync("Info", "Cannot kill System/Idle process.");
                return;
            }

            try
            {
                var proc = Process.GetProcessById(item.ProcessId);

                // PID reuse guard: the row may be stale — the original process
                // exited and Windows recycled the PID to something else.
                // Verify the live identity before pulling the trigger.
                string liveName = string.Empty;
                try { liveName = proc.ProcessName; } catch { }

                string knownName = Path.GetFileNameWithoutExtension(item.ProcessName ?? string.Empty);
                string confirmName = item.ProcessName;
                if (knownName.Length > 0 && !liveName.Equals(knownName, StringComparison.OrdinalIgnoreCase))
                {
                    confirmName = liveName;
                    // WinUI port: MessageBox YesNo → Dialogs.ConfirmAsync
                    bool stale = await Dialogs.ConfirmAsync(
                        "PID reused — confirm kill",
                        $"This row is stale: PID {item.ProcessId} now runs '{liveName}', not '{item.ProcessName}'.\n\n" +
                        $"Kill the running process '{liveName}' (PID {item.ProcessId}) anyway?\n" +
                        "This forcefully terminates the application.");
                    if (!stale) return;
                }
                else if (!await Dialogs.ConfirmAsync(
                    "Confirm Kill",
                    $"Kill process '{confirmName}' (PID {item.ProcessId})?\nThis forcefully terminates the application."))
                {
                    return;
                }

                proc.Kill();
                await Task.Delay(500); // Give it a moment to release ports
            }
            catch (ArgumentException)
            {
                await Dialogs.ShowInfoAsync("Info", $"Process {item.ProcessId} is no longer running (it already exited).");
            }
            catch (Exception ex)
            {
                await Dialogs.ShowInfoAsync("Error", $"Failed to kill process: {ex.Message}");
            }
        }

        private async void TaskDetails_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item || string.IsNullOrEmpty(item.TaskName)) return;

            var (summary, error) = await TaskSchedulerService.Instance.GetTaskSummaryAsync(item.TaskName);

            // What code the task actually executes (COM-handler DLL), when
            // attribution has it — DLL tasks have no command line of their own
            var launch = _taskAttribution.GetTaskForPid(item.ProcessId, item.ProcessStartedUtc);
            if (launch?.HandlerClassId != null)
            {
                string handler = launch.HandlerDllExists == true
                    ? $"Handler DLL: {launch.HandlerDll} (CLSID {launch.HandlerClassId})"
                    : $"Handler CLSID {launch.HandlerClassId} is not registered — the task's DLL is gone (leftover of uninstalled software)";
                summary = string.IsNullOrEmpty(summary) ? handler : $"{handler}\n\n{summary}";
                error = null;
            }

            await Dialogs.ShowInfoAsync("Scheduled task",
                string.IsNullOrEmpty(error)
                    ? summary
                    : $"Could not read task '{item.TaskName}': {error}");
        }

        private async void DisableTask_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item || string.IsNullOrEmpty(item.TaskName)) return;

            // WinUI port: MessageBox YesNo → Dialogs.ConfirmAsync (true = Yes)
            if (!await Dialogs.ConfirmAsync("Confirm Disable Task",
                $"Disable scheduled task '{item.TaskName}'?\n\n" +
                "The task will not run again until it is re-enabled (Tasks tab, or:\n" +
                $"schtasks /Change /TN \"{item.TaskName}\" /ENABLE).\n\n" +
                "The running instance keeps going — use 'Kill process' to end it now.")) return;

            try
            {
                await TaskSchedulerService.Instance.SetTaskEnabledAsync(item.TaskName, false);
                await Dialogs.ShowInfoAsync("Task Disabled", $"Scheduled task disabled:\n{item.TaskName}");
            }
            catch (Exception ex)
            {
                await Dialogs.ShowInfoAsync("Error", $"Failed to disable task: {ex.Message}");
            }
        }

        /// <summary>
        /// Resolves an executable path for a PID; falls back to WMI when the
        /// process module cannot be read (bitness mismatch) or the process exited.
        /// </summary>
        private static string GetProcessPath(int processId)
        {
            try
            {
                using var proc = Process.GetProcessById(processId);
                string path = proc.MainModule?.FileName;
                if (!string.IsNullOrEmpty(path)) return path;
            }
            catch { }

            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}");
                using var results = searcher.Get();
                foreach (System.Management.ManagementObject obj in results)
                {
                    return obj["ExecutablePath"]?.ToString();
                }
            }
            catch { }
            return null;
        }

        // -----------------------------------------------------------------------
        // Block-target resolution — "the suspect ran away" support
        // -----------------------------------------------------------------------

        private enum BlockPathSource { Live, Row, Archive }

        /// <summary>What BlockProcess_Click will arm the firewall rule on.</summary>
        private sealed class BlockTarget
        {
            /// <summary>Full exe path; null when unrecoverable (nothing to arm a rule on).</summary>
            public string Path;
            /// <summary>Where the path came from: live process, the row's Sysmon capture, or the archive.</summary>
            public BlockPathSource Source;
            /// <summary>True when the row's process is known dead (sticky exit flag, or a recycled PID proved it).</summary>
            public bool SubjectExited;
            /// <summary>Non-null when PID reuse was detected (the live tenant contradicts the row).</summary>
            public string ReuseNote;
        }

        /// <summary>
        /// Resolves the executable to block for a row, exited or not. Order:
        /// corroborated live lookup → the row's Sysmon image path → the
        /// 30-day archive's create-event. The live lookup is skipped
        /// entirely for exited rows and name-checked otherwise, so a
        /// recycled PID's new tenant can never end up blocked.
        /// </summary>
        private async Task<BlockTarget> ResolveBlockTargetAsync(SvchostMonitorItem item)
        {
            var t = new BlockTarget();

            if (item.HasExited)
            {
                t.SubjectExited = true;
            }
            else
            {
                string live = GetProcessPath(item.ProcessId);
                if (!string.IsNullOrEmpty(live))
                {
                    // Name cross-check — the kill flow's reuse guard, applied
                    // to blocking: the row can be up to one refresh tick
                    // (10 s) behind reality.
                    string liveName = System.IO.Path.GetFileName(live);
                    if (string.IsNullOrEmpty(item.ProcessName) ||
                        liveName.Equals(item.ProcessName, StringComparison.OrdinalIgnoreCase))
                    {
                        t.Path = live;
                        t.Source = BlockPathSource.Live;
                        return t;
                    }
                    t.SubjectExited = true;
                    t.ReuseNote = $"PID {item.ProcessId} now runs '{liveName}', not '{item.ProcessName}' — " +
                                  "the row's process exited and Windows recycled the number";
                }
                else if (string.IsNullOrEmpty(item.ImagePath))
                {
                    // Live lookup empty and no row path: the process most
                    // likely died between refresh ticks (HasExited lags) —
                    // let the archive decide before declaring it lost.
                    t.SubjectExited = true;
                }
            }

            // The row's identity survives exit — Sysmon captured the image
            // path at row creation exactly so dead rows stay blockable.
            if (!string.IsNullOrEmpty(item.ImagePath))
            {
                t.Path = item.ImagePath;
                t.Source = BlockPathSource.Row;
                return t;
            }

            // Last resort: the archive. A dead process's create-event IS its
            // identity — the same recovery the PID Inquiry performs.
            var records = await Task.Run(() =>
                SysmonArchiveService.SearchCreateEvents(item.ProcessId, 12));
            var best = PickBestCreateRecord(records, item);
            if (best != null && best.Data.TryGetValue("Image", out string image) &&
                !string.IsNullOrEmpty(image))
            {
                t.Path = image;
                t.Source = BlockPathSource.Archive;
            }
            return t;
        }

        /// <summary>
        /// Picks the create-record that belongs to the row's process when the
        /// archive holds several for the same (recycled) PID. Preference:
        /// start-time window ±5 s AND image match &gt; window &gt; image —
        /// ties keep the newest record (the list comes newest-first).
        /// </summary>
        private static SysmonArchiveService.ArchiveEvent PickBestCreateRecord(
            List<SysmonArchiveService.ArchiveEvent> records, SvchostMonitorItem item)
        {
            if (records == null || records.Count == 0) return null;
            SysmonArchiveService.ArchiveEvent best = null;
            int bestScore = -1;
            foreach (var rec in records)
            {
                bool imageMatch = !string.IsNullOrEmpty(item.ProcessName) &&
                                  rec.Data.TryGetValue("Image", out string img) &&
                                  System.IO.Path.GetFileName(img).Equals(item.ProcessName, StringComparison.OrdinalIgnoreCase);
                bool inWindow = item.ProcessStartedUtc.HasValue &&
                                (rec.TsUtc - item.ProcessStartedUtc.Value).Duration() <= TimeSpan.FromSeconds(5);
                int score = inWindow && imageMatch ? 3 : inWindow ? 2 : imageMatch ? 1 : 0;
                if (score > bestScore) { bestScore = score; best = rec; }
            }
            return best;
        }

        // -----------------------------------------------------------------------
        // Blocked-state marking — the firewall rules are the source of truth
        // -----------------------------------------------------------------------

        /// <summary>
        /// Rebuilds the blocked-IP / blocked-app sets from the live firewall
        /// inventory (agent- and wf.msc-created blocks included, not just
        /// this monitor's), then re-marks every row. A failed inventory read
        /// returns an empty list — marks just clear until the next sync.
        /// </summary>
        private async Task RefreshBlockStateFromFirewallAsync()
        {
            if (_blockStateSyncing) return;
            _blockStateSyncing = true;
            try
            {
                var inventory = await FirewallService.Instance.GetBlockedInventoryAsync();

                _activeIps.Clear(); _pausedIps.Clear();
                _activeApps.Clear(); _pausedApps.Clear();
                _blockNotes.Clear();
                foreach (var t in inventory)
                {
                    if (t.Kind == "ip")
                    {
                        if (string.IsNullOrEmpty(t.Ip)) continue;
                        if (t.EnabledRules > 0) _activeIps.Add(t.Ip); else _pausedIps.Add(t.Ip);
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(t.AppPath)) continue;
                        if (t.EnabledRules > 0) _activeApps.Add(t.AppPath); else _pausedApps.Add(t.AppPath);
                    }
                    if (!string.IsNullOrEmpty(t.Description))
                        _blockNotes[t.Key] = t.Description;
                }

                // WinUI port: Dispatcher.InvokeAsync → TryEnqueue
                _ = _dispatcherQueue.TryEnqueue(() =>
                {
                    foreach (var item in _uiCollection)
                        ApplyBlockState(item);
                    // WinUI port: blocked-mark cell visuals re-applied in code
                    RefreshRowVisuals();
                });
            }
            finally
            {
                _blockStateSyncing = false;
            }
        }

        /// <summary>Stamps one row's IP / process block state from the cached sets.</summary>
        private void ApplyBlockState(SvchostMonitorItem item)
        {
            string ip = item.RemoteIp ?? "";
            var ipState = _activeIps.Contains(ip) ? BlockRuleState.Active
                        : _pausedIps.Contains(ip) ? BlockRuleState.Paused
                        : BlockRuleState.None;
            _blockNotes.TryGetValue("ip:" + ip, out string ipNote);

            // Sysmon's image path is the stable identity; the live module
            // lookup covers rows created before Sysmon stamped one.
            string appPath = !string.IsNullOrEmpty(item.ImagePath) ? item.ImagePath : LiveProcessPath(item.ProcessId);
            var appState = BlockRuleState.None;
            string appNote = null;
            if (!string.IsNullOrEmpty(appPath))
            {
                appState = _activeApps.Contains(appPath) ? BlockRuleState.Active
                         : _pausedApps.Contains(appPath) ? BlockRuleState.Paused
                         : BlockRuleState.None;
                if (_blockNotes.TryGetValue("app:" + appPath.ToLowerInvariant(), out string note))
                    appNote = note;
            }

            item.SetBlockState(ipState, ipNote, appState, appNote);
        }

        /// <summary>Cheap live module path (no WMI fallback — the periodic sync must stay fast).</summary>
        private static string LiveProcessPath(int pid)
        {
            if (pid <= 0) return null;
            try
            {
                using var p = Process.GetProcessById(pid);
                return p.MainModule?.FileName;
            }
            catch { return null; }
        }

        // -----------------------------------------------------------------------
        // Non-modal block feedback (message + Undo, auto-hides)
        // -----------------------------------------------------------------------

        private void ShowToast(string message, string undoKind = null, string undoKey = null)
        {
            BlockToastText.Text = message;
            _toastUndoKind = undoKind;
            _toastUndoKey = undoKey;
            BlockToastUndoBtn.Visibility = undoKind != null ? Visibility.Visible : Visibility.Collapsed;
            BlockToast.Visibility = Visibility.Visible;
            _toastTimer.Stop();
            _toastTimer.Start();
        }

        private void HideToast()
        {
            _toastTimer.Stop();
            BlockToast.Visibility = Visibility.Collapsed;
            _toastUndoKind = null;
            _toastUndoKey = null;
        }

        private async void BlockToastUndo_Click(object sender, RoutedEventArgs e)
        {
            if (_toastUndoKind == null || _toastUndoKey == null) return;
            string kind = _toastUndoKind, key = _toastUndoKey;
            HideToast();
            await RemoveBlockCoreAsync(kind, key);
        }

        // -----------------------------------------------------------------------
        // Block records — BlocksStore v3 persistence (see BlocksStore.cs)
        // -----------------------------------------------------------------------

        private void RecordBlockedEntry(SvchostMonitorItem item, string kind, string key)
        {
            BlocksStore.AddOrUpdate(BuildBlockRecord(item, kind, key));
            RefreshBlockedUi();
        }

        private void LoadBlockedEntries()
        {
            BlocksStore.Load(); // migrates legacy blocked.txt files once, in place
            RefreshBlockedUi();
        }

        private void RefreshBlockedUi()
        {
            var records = BlocksStore.Records;
            BlockedListBtn.Content = $"Blocked: {records.Count}";
            BlockedListBox.ItemsSource = records
                .OrderBy(b => b.Kind).ThenBy(b => b.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();
            RefreshConfirmPrefsUi();
        }

        /// <summary>Keeps the Blocked popup's suppression indicator honest.</summary>
        private void RefreshConfirmPrefsUi()
        {
            int n = ConfirmPrefs.SuppressedCount;
            SuppressedPromptsText.Text = n > 0
                ? $"{n} of 4 confirmation prompt(s) suppressed"
                : "All confirmation prompts active";
        }

        private async void SaveCsvBtn_Click(object sender, RoutedEventArgs e)
        {
            SaveToCsv();
            await Dialogs.ShowInfoAsync("Saved", $"Data saved to {_csvPath}");
        }

        private void SaveToCsv()
        {
            try
            {
                bool writeHeader = !File.Exists(_csvPath);
                using var writer = new StreamWriter(_csvPath, true);

                if (writeHeader)
                {
                    writer.WriteLine("Timestamp,PID,ProcessName,RemoteIP,Host,RxPackets,TxPackets,RxBytes,TxBytes,LastSeen");
                }

                string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                var snap = _trackedIps.Values.ToList();

                foreach (var item in snap)
                {
                    writer.WriteLine($"{ts},{item.ProcessId},{item.ProcessName},{item.RemoteIp},{item.Hostname},{item.RxPackets},{item.TxPackets},{item.RxBytes},{item.TxBytes},{item.LastSeen:u}");
                }
            }
            catch (Exception ex)
            {
                // WinUI port: Dispatcher.Invoke → TryEnqueue; the WPF
                // single-caption MessageBox maps to an empty dialog title
                _ = _dispatcherQueue.TryEnqueue(() => Dialogs.ShowInfoAsync("", $"Failed to save CSV: {ex.Message}"));
            }
        }

        public string GetAuditContext()
        {
            var items = _uiCollection.ToList();
            if (items.Count == 0) return "Process Monitor is currently empty. No active connections tracked.";

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Currently Tracked Processes and Connections:");
            foreach (var item in items)
            {
                sb.AppendLine($"- Process: {item.ProcessName}{(item.HasServiceIdentity ? $" [{item.IdentityLabel}]" : "")} (PID: {item.ProcessId}{(item.HasExited ? ", exited" : "")}) | Remote IP: {item.RemoteIp} ({item.Hostname}) | Packets: {item.TxPackets} sent, {item.RxPackets} received | Last Seen: {item.LastSeen:u}");
            }
            return sb.ToString();
        }

        // -----------------------------------------------------------------------
        // WinUI port: view projection — replaces WPF's CollectionViewSource
        // live sorting (IsHighTransmitter ↓, LastSeen ↓, RemoteIp ↑) and the
        // TX-only view Filter, neither of which WinUI has.
        // -----------------------------------------------------------------------

        private static int CompareRows(SvchostMonitorItem a, SvchostMonitorItem b)
        {
            int c = b.IsHighTransmitter.CompareTo(a.IsHighTransmitter);
            if (c != 0) return c;
            c = b.LastSeen.CompareTo(a.LastSeen);
            if (c != 0) return c;
            return string.CompareOrdinal(a.RemoteIp, b.RemoteIp);
        }

        private bool PassesTxOnlyFilter(object o) => !_txOnlyFilterOn || TxOnlyPredicate(o);

        private void InsertInView(SvchostMonitorItem item)
        {
            if (!PassesTxOnlyFilter(item)) return;
            int i = _viewCollection.Count;
            while (i > 0 && CompareRows(item, _viewCollection[i - 1]) < 0) i--;
            _viewCollection.Insert(i, item);
        }

        private void RefreshView()
        {
            var desired = new List<SvchostMonitorItem>();
            foreach (var item in _uiCollection)
                if (PassesTxOnlyFilter(item))
                    desired.Add(item);
            desired.Sort(CompareRows);

            // Diff onto the bound collection — Move/Insert/Remove keep the
            // grid's selection and scroll position stable instead of a reset
            var keep = new HashSet<SvchostMonitorItem>(desired);
            for (int i = _viewCollection.Count - 1; i >= 0; i--)
                if (!keep.Contains(_viewCollection[i]))
                    _viewCollection.RemoveAt(i);
            for (int i = 0; i < desired.Count; i++)
            {
                int cur = _viewCollection.IndexOf(desired[i]);
                if (cur == -1) _viewCollection.Insert(i, desired[i]);
                else if (cur != i) _viewCollection.Move(cur, i);
            }
        }

        // -----------------------------------------------------------------------
        // WinUI port: row/cell visuals — WinUI styles have no DataTrigger, so
        // the WPF RowStyle tints and the Process/Remote-IP/Host cell
        // variations are applied in code (when rows realize, on the 10-second
        // refresh tick and after block-state syncs). Cells are addressed in
        // column order: 1 = Process, 5 = Remote IP, 6 = Host.
        // -----------------------------------------------------------------------

        private void RefreshRowVisuals()
        {
            foreach (var row in FindDescendants<DataGridRow>(SvchostGrid))
                ApplyRowVisuals(row);
        }

        private void ApplyRowVisuals(DataGridRow row)
        {
            if (row.DataContext is not SvchostMonitorItem it) return;

            // High transmitters tint red (was a RowStyle DataTrigger)
            row.Background = it.IsHighTransmitter
                ? new SolidColorBrush(Color.FromArgb(0x33, 0xE5, 0x53, 0x4B))
                : null;
            // Rows with no traffic for 5+ minutes fade into the background
            // (was a RowStyle DataTrigger)
            row.Opacity = it.IsStale ? 0.45 : 1.0;

            var cells = new List<DataGridCell>(FindDescendants<DataGridCell>(row));
            if (cells.Count == 0) return;

            // Process cell: blocked processes turn red + strikethrough, and
            // the tooltip only exists when there is content (were cell
            // DataTriggers)
            var proc = CellText(cells, 1);
            if (proc != null)
            {
                if (it.IsProcessBlocked)
                {
                    proc.Foreground = new SolidColorBrush(Color.FromArgb(255, 0xE5, 0x53, 0x4B));
                    proc.TextDecorations = Windows.UI.Text.TextDecorations.Strikethrough;
                }
                else
                {
                    proc.Foreground = null; // back to the inherited default
                    proc.TextDecorations = Windows.UI.Text.TextDecorations.None;
                }
                ToolTipService.SetToolTip(proc, it.HasToolTip ? it.ProcessToolTip : null);
            }

            // Remote IP cell: blocked IPs turn red + strikethrough, hover
            // shows the block rule's provenance
            var ip = CellText(cells, 5);
            if (ip != null)
            {
                if (it.IsIpBlocked)
                {
                    ip.Foreground = new SolidColorBrush(Color.FromArgb(255, 0xE5, 0x53, 0x4B));
                    ip.TextDecorations = Windows.UI.Text.TextDecorations.Strikethrough;
                    ToolTipService.SetToolTip(ip, it.IpBlockToolTip);
                }
                else
                {
                    ip.Foreground = AppBrush("TextPrimaryBrush");
                    ip.TextDecorations = Windows.UI.Text.TextDecorations.None;
                    ToolTipService.SetToolTip(ip, null);
                }
            }

            // Host cell: cells that are still resolving dim + italicise
            var host = CellText(cells, 6);
            if (host != null)
            {
                if (it.IsResolved)
                {
                    host.Foreground = AppBrush("TextPrimaryBrush");
                    host.FontStyle = Windows.UI.Text.FontStyle.Normal;
                }
                else
                {
                    host.Foreground = AppBrush("TextSecondaryBrush");
                    host.FontStyle = Windows.UI.Text.FontStyle.Italic;
                }
            }
        }

        private static Brush AppBrush(string key) => (Brush)Application.Current.Resources[key];

        private static TextBlock CellText(IReadOnlyList<DataGridCell> cells, int index) =>
            index < cells.Count ? FirstTextBlock(cells[index]) : null;

        private static TextBlock FirstTextBlock(DependencyObject root)
        {
            int n = VisualTreeHelper.GetChildrenCount(root);
            for (int i = 0; i < n; i++)
            {
                var child = VisualTreeHelper.GetChild(root, i);
                if (child is TextBlock tb) return tb;
                var deeper = FirstTextBlock(child);
                if (deeper != null) return deeper;
            }
            return null;
        }

        private static IEnumerable<T> FindDescendants<T>(DependencyObject root)
            where T : DependencyObject
        {
            int n = VisualTreeHelper.GetChildrenCount(root);
            for (int i = 0; i < n; i++)
            {
                var child = VisualTreeHelper.GetChild(root, i);
                if (child is T t) yield return t;
                foreach (var d in FindDescendants<T>(child))
                    yield return d;
            }
        }

        // -----------------------------------------------------------------------
        // WinUI port: popup helpers — WinUI's Popup has no Placement /
        // PlacementTarget / StaysOpen
        // -----------------------------------------------------------------------

        // Positions the popup under the invoking button (offsets are relative
        // to the Popup's XAML parent)
        private void OpenPopupBelow(Popup popup, FrameworkElement target)
        {
            try
            {
                var origin = target.TransformToVisual((UIElement)popup.Parent);
                var pos = origin.TransformPoint(new Windows.Foundation.Point(0, target.ActualHeight));
                popup.HorizontalOffset = pos.X;
                popup.VerticalOffset = pos.Y;
            }
            catch { /* transforms unavailable — keep the last position */ }
            popup.IsOpen = true;
        }

        // WPF StaysOpen="False" — close on any click outside the popups
        // (popup content clicks never reach the page, so they survive)
        private void LayoutRoot_PointerPressed(object sender, PointerRoutedEventArgs e)
        {
            if (BlockedListPopup.IsOpen) BlockedListPopup.IsOpen = false;
            if (IgnoredListPopup.IsOpen) IgnoredListPopup.IsOpen = false;
        }
    }
}
