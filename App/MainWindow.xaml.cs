using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;
using AutoScope.Services;

namespace AutoScope
{
    /// <summary>
    /// Shell ported from AutoCommand's WPF MainWindow: NavigationView replaces
    /// the left TabControl, ContentDialog replaces MessageBox, DispatcherQueue
    /// replaces Dispatcher. The tray toast notifier is not ported (WinUI uses
    /// a different notification API); everything else — Security Enforcer
    /// status, threat alerts, Restore Internet panic button, capture
    /// lifecycle — behaves as before.
    /// </summary>
    public partial class MainWindow : Window
    {
        private SecurityEnforcer _enforcer;

        private static string AppVersion =>
            FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion ?? "unknown";

        public MainWindow()
        {
            InitializeComponent();

            // Live version from the assembly instead of a hardcoded string
            VersionText.Text = $"AutoScope v{AppVersion}";

            // Dark title bar to match the fixed dark palette
            try
            {
                var tb = AppWindow.TitleBar;
                tb.ButtonForegroundColor = Color.FromArgb(255, 0xD3, 0xD3, 0xD3);
                tb.ButtonBackgroundColor = Windows.UI.Color.FromArgb(255, 0x17, 0x1B, 0x22);
                tb.ButtonInactiveBackgroundColor = Color.FromArgb(255, 0x17, 0x1B, 0x22);
            }
            catch { /* title bar interop unavailable — cosmetic only */ }

            // Layer-3 crash safety: if a previous run died mid-intercept, the
            // journal on disk still describes the hooks it installed — undo
            // them (proxy, firewall rule, CA) before anything else runs.
            InterceptSystemHooks.RecoverAfterCrash();

            this.Closed += Window_Closed;

            InitializeEnforcer();

            // App-level TCP capture + traffic aggregation: the shared raw
            // socket the Process Monitor and Site Doctor views read; the
            // aggregator runs whenever capture runs and persists its
            // (process → destination → bytes) history across sessions.
            TrafficAggregationService.Shared.Attach(TcpStreamCaptureService.Shared);
            TrafficAggregationService.Shared.Start();

            // First tab visible at launch
            Nav.SelectedItem = ProcessMonitorNavItem;
        }

        // ── navigation ─────────────────────────────────────────────────────

        private static readonly Dictionary<string, Type> Pages = new()
        {
            ["ProcessMonitor"] = typeof(Views.SvchostMonitorView),
            ["SiteDoctor"] = typeof(Views.SiteDoctorView),
            ["Firewall"] = typeof(Views.FirewallSettingsView),
            ["Blocks"] = typeof(Views.BlocksView),
            ["BeMyGuest"] = typeof(Views.BeMyGuestView),
            ["Settings"] = typeof(Views.SettingsView),
        };

        private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            if (args.SelectedItemContainer?.Tag is string tag && Pages.TryGetValue(tag, out var page))
                ContentFrame.Navigate(page);
        }

        // ── Security Enforcer + status bar ─────────────────────────────────

        private void InitializeEnforcer()
        {
            _enforcer = new SecurityEnforcer(OnThreatDetected);
            _enforcer.StatusChanged += OnEnforcerStatusChanged;
            _enforcer.ConfigurationDriftDetected += OnDriftDetected;
            _enforcer.Start();
        }

        private string _currentThreatType;
        private string _currentThreatDetails;

        /// <summary>
        /// Lets tabs surface a finding on the app-level threat status bar
        /// (amber text + Review button) through the same path the Security
        /// Enforcer uses.
        /// </summary>
        public void RaiseExternalThreat(string type, string details) => OnThreatDetected(type, details);

        private void OnThreatDetected(string type, string details)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                _currentThreatType = type;
                _currentThreatDetails = details;
                ThreatAlertText.Text = $"⚠ {type}: {details}";
                ThreatAlertText.Foreground = new SolidColorBrush(Color.FromArgb(255, 0xE5, 0xA6, 0x31));
                ReviewAlertBtn.Visibility = Visibility.Visible;
            });
        }

        private async void ReviewAlertBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_currentThreatType == "Privileged Task")
            {
                string msg = $"{_currentThreatDetails}\n\n" +
                             "This task is running with the highest system privileges. While some third-party updaters (like Edge or Chrome) do this legitimately, malware often uses it for persistence.\n\n" +
                             "Would you like to ignore this task permanently (Whitelist)?\n" +
                             "Click 'No' to keep alerting.";
                int result = await Dialogs.ThreeWayAsync("Review Threat", msg);
                if (result == 1)
                {
                    string taskName = _currentThreatDetails.Replace("High Risk Task detected: ", "").Trim();
                    SecurityEnforcer.WhitelistTask(taskName);
                    ThreatAlertText.Text = "✓ Task added to whitelist.";
                    ThreatAlertText.Foreground = new SolidColorBrush(Color.FromArgb(255, 0x4E, 0xC9, 0x6F));
                    ReviewAlertBtn.Visibility = Visibility.Collapsed;
                }
            }
            else if (_currentThreatType == "Network Adapter")
            {
                string msg = $"Active Adapter Detected: {_currentThreatDetails}\n\n" +
                             "This adapter might be used for unauthorized tunneling or kernel debugging.\n\n" +
                             "Click 'Yes' to Block & Delete (removes device and service).\n" +
                             "Click 'No' to Whitelist (ignore this adapter permanently).\n" +
                             "Click 'Cancel' to ignore for now.";
                int result = await Dialogs.ThreeWayAsync("Review Network Adapter", msg);
                if (result == 1)
                {
                    _enforcer.MitigateAdapter(_currentThreatDetails);
                    ThreatAlertText.Text = "✓ Adapter mitigated.";
                    ThreatAlertText.Foreground = new SolidColorBrush(Color.FromArgb(255, 0x4E, 0xC9, 0x6F));
                    ReviewAlertBtn.Visibility = Visibility.Collapsed;
                }
                else if (result == 0)
                {
                    if (_currentThreatDetails.Contains("SSTP")) SecurityEnforcer.IsSstpAllowed = true;
                    if (_currentThreatDetails.Contains("Kernel Debug")) SecurityEnforcer.IsKernelDebugAllowed = true;
                    ThreatAlertText.Text = "✓ Adapter whitelisted.";
                    ThreatAlertText.Foreground = new SolidColorBrush(Color.FromArgb(255, 0x4E, 0xC9, 0x6F));
                    ReviewAlertBtn.Visibility = Visibility.Collapsed;
                }
            }
            else
            {
                await Dialogs.ShowInfoAsync("Security Alert", $"{_currentThreatType}\n\n{_currentThreatDetails}");
                ReviewAlertBtn.Visibility = Visibility.Collapsed;
            }
        }

        private void OnEnforcerStatusChanged(string status, string colorType)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                EnforcerStatusText.Text = $"Security Enforcer: {status}";
                EnforcerDot.Fill = colorType switch
                {
                    "Red" => new SolidColorBrush(Color.FromArgb(255, 0xE5, 0x53, 0x4B)),
                    "Amber" => new SolidColorBrush(Color.FromArgb(255, 0xE5, 0xA6, 0x31)),
                    _ => new SolidColorBrush(Color.FromArgb(255, 0x4E, 0xC9, 0x6F)),
                };
            });
        }

        private void OnDriftDetected(List<string> driftItems)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                ThreatAlertText.Text = $"⚠ Firewall drift detected: {driftItems.Count} rule(s) changed";
                ThreatAlertText.Foreground = new SolidColorBrush(Color.FromArgb(255, 0xE5, 0xA6, 0x31));
            });
        }

        // ── shutdown: mirrors AutoCommand's OnClosed ordering ──────────────

        private void Window_Closed(object sender, WindowEventArgs args)
        {
            _enforcer?.Stop();

            // Stop the shared capture FIRST so live flows finalize into the
            // aggregator, then persist that final state.
            TcpStreamCaptureService.Shared.Stop();
            TrafficAggregationService.Shared.Shutdown();
            // Transmissions pipeline drains what the capture flush finalized
            // (up to its 3s budget), then releases its capture reference.
            TransmissionsPipelineService.Shared.Stop();

            // Layer 3 must never outlive the app: stop restores the system
            // proxy, removes the QUIC block rule and untrusts the CA.
            InterceptProxyService.Shared.StopSession("app exit");

            TlsKeylogService.CleanupAtExit(); // drop the rotated TLS keylog leftover
        }

        // ── Emergency internet restore (panic button) ───────────────────────
        //
        // The #1 self-inflicted outage from Process Monitor blocking is blocking
        // svchost/DNS or a Microsoft endpoint. This disables every AutoScope-
        // created block rule in one click — reversible, nothing deleted.

        private async void RestoreInternetBtn_Click(object sender, RoutedEventArgs e)
        {
            bool confirm = await Dialogs.ConfirmAsync("🚑 Restore Internet",
                "Restore internet access?\n\n" +
                "This DISABLES every firewall block rule AutoScope created (IP and process\n" +
                "blocks — including legacy ones). Nothing is deleted; re-enable all of them\n" +
                "from Process Monitor → Blocked → Manage all.\n\n" +
                "If this does not restore connectivity, the block came from another tool\n" +
                "or a proxy/VPN — this button only touches AutoScope rules.");
            if (!confirm) return;

            RestoreInternetBtn.IsEnabled = false;
            try
            {
                var result = await FirewallService.Instance
                    .SetAllAutoScopeBlocksEnabledAsync(false);

                // A stale DNS cache keeps sites dead even after the block is
                // lifted — flush it automatically so recovery is one click.
                string dnsNote;
                try
                {
                    var psi = new ProcessStartInfo("ipconfig", "/flushdns")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true
                    };
                    using var p = Process.Start(psi);
                    p.StandardOutput.ReadToEnd();
                    p.WaitForExit(5000);
                    dnsNote = p.ExitCode == 0
                        ? "The DNS cache was flushed automatically — no further steps needed."
                        : $"ipconfig /flushdns returned exit code {p.ExitCode}; run it manually if sites still fail.";
                }
                catch (Exception ex)
                {
                    dnsNote = $"Could not flush DNS automatically ({ex.Message}); run  ipconfig /flushdns  manually.";
                }

                string extra = result.FirstError != null ? $"\nFirst error: {result.FirstError}" : "";
                await Dialogs.ShowInfoAsync("🚑 Restore Internet",
                    $"Disabled {result.Changed} of {result.Matched} AutoScope block rule(s).{extra}\n\n" +
                    $"{dnsNote}\n\n" +
                    "Restore options in Process Monitor → Blocked → Manage all:\n" +
                    "  · 'Restore except Microsoft/Windows' — recommended: brings back your\n" +
                    "    real blocks, leaves the breakage-causing ones (red rows) off\n" +
                    "  · 'Re-enable all' — everything back on");
            }
            finally { RestoreInternetBtn.IsEnabled = true; }
        }
    }
}
