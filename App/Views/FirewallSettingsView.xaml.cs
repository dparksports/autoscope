using System;
using AutoCommand.Engines.Firewall;
using AutoCommand.Engines.Core;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using AutoScope.Helpers;
using AutoScope.Models;
using AutoScope.Services;

namespace AutoScope.Views
{
    /// <summary>
    /// Firewall tab ported from AutoCommand's WPF FirewallSettingsView.
    /// WinUI port notes: grouping (CollectionViewSource + expander headers)
    /// is dropped — the toolkit DataGrid shows the same sorted flat list;
    /// the row context menu is a MenuFlyout opened on RightTapped;
    /// MessageBox calls go through AutoScope.Dialogs.
    /// </summary>
    public partial class FirewallSettingsView : Page, IAiAuditable
    {
        private List<RuleInfo> _currentRules = new();

        public FirewallSettingsView()
        {
            InitializeComponent();
        }

        private async void Page_Loaded(object sender, RoutedEventArgs e)
        {
            await LoadRules();
            await UpdateBaselineStatusAsync();
        }

        private async void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            await LoadRules();
            await UpdateBaselineStatusAsync();
        }

        private async Task UpdateBaselineStatusAsync()
        {
            var info = AutoScope.Services.Fw.Baseline.BaselineInfo;
            if (AutoScope.Services.Fw.Baseline.IsPaused)
            {
                BaselineStatusText.Text = $"Baseline auto-fix PAUSED until {AutoScope.Services.Fw.Baseline.PausedUntilUtc.ToLocalTime():HH:mm}"
                                          + (info == null ? "" : $" — baseline has {info.Value.Item2} rules");
            }
            else
            {
                BaselineStatusText.Text = info == null
                    ? "No baseline — apply a profile or click Re-baseline to capture one"
                    : $"Baseline: {info.Value.Item2} rules (captured {info.Value.Item1:yyyy-MM-dd HH:mm})";
            }
        }

        private async void RebaselineBtn_Click(object sender, RoutedEventArgs e)
        {
            RebaselineBtn.IsEnabled = false;
            try
            {
                var (count, at) = await AutoScope.Services.Fw.Baseline.CaptureBaselineAsync();
                BaselineStatusText.Text = $"Baseline: {count} rules (captured {at:yyyy-MM-dd HH:mm})";
            }
            finally
            {
                RebaselineBtn.IsEnabled = true;
            }
        }

        private async void PauseEnforcementBtn_Click(object sender, RoutedEventArgs e)
        {
            AutoScope.Services.Fw.Baseline.PauseForMinutes(15);
            await UpdateBaselineStatusAsync();
        }

        private async void RenameLegacyBtn_Click(object sender, RoutedEventArgs e)
        {
            bool proceed = await Dialogs.ConfirmAsync("Rename legacy blocks",
                "Block rules still using the legacy \"AutoScope IP Block / Process Block\" names will be\n" +
                "recreated under the current AS-BLOCK naming scheme.\n\n" +
                "• Lossless — descriptions (provenance) carry over\n" +
                "• Redundant inbound duplicates are removed (covered by stateful filtering)\n" +
                "• Protection is unchanged\n" +
                "• The baseline is re-captured afterwards so the enforcer doesn't flag the new names");
            if (!proceed) return;

            RenameLegacyBtn.IsEnabled = false;
            ProfileStatusText.Text = "Renaming legacy block rules…";
            try
            {
                var (targets, removedIn, migrated) = await AutoScope.Services.Fw.Service.ConsolidateLegacyIpBlocksAsync();

                // Names changed — re-capture so the enforcer doesn't report the new
                // AS-BLOCK names as drift (the baseline is keyed by rule name)
                var (count, at) = await AutoScope.Services.Fw.Baseline.CaptureBaselineAsync();
                BaselineStatusText.Text = $"Baseline: {count} rules (captured {at:yyyy-MM-dd HH:mm})";

                ProfileStatusText.Text = $"Renamed legacy rules across {targets} target(s): "
                                         + $"{migrated} migrated to AS-BLOCK naming, {removedIn} redundant inbound rule(s) removed.";
            }
            catch (Exception ex)
            {
                ProfileStatusText.Text = $"Rename failed: {ex.Message}";
                await Dialogs.ShowInfoAsync("Error", $"Failed to rename legacy block rules: {ex.Message}");
            }
            finally
            {
                await LoadRules(); // refresh the grid and the button's enabled state
            }
        }

        private async void FilterChanged(object sender, RoutedEventArgs e)
        {
            if (RulesGrid == null) return; // WinUI port: fires during InitializeComponent
            await LoadRules();
        }

        private async Task LoadRules()
        {
            int direction = InboundRadio.IsChecked == true ? 1 : 2;
            _currentRules = await AutoScope.Services.Fw.Service.LoadRulesAsync(direction);

            // Enabled rules first (then alphabetical) so the refreshed list reads top-down
            _currentRules = _currentRules.OrderByDescending(r => r.Enabled)
                                         .ThenBy(r => r.DisplayName, StringComparer.OrdinalIgnoreCase)
                                         .ToList();

            RulesGrid.ItemsSource = _currentRules;

            int enabled = _currentRules.Count(r => r.Enabled);
            string dir = direction == 1 ? "Inbound" : "Outbound";
            RuleCountText.Text = $"{_currentRules.Count} {dir} rules ({enabled} enabled)";

            int legacy = await AutoScope.Services.Fw.Service.CountLegacyBlocksAsync();
            RenameLegacyBtn.IsEnabled = legacy > 0;
            ToolTipService.SetToolTip(RenameLegacyBtn, legacy == 0
                ? "No legacy-named AutoScope block rules — nothing to rename."
                : $"{legacy} legacy-named AutoScope block rule(s) found. Click to rename them to the current AS-BLOCK scheme.");
        }

        // WinUI port: WPF ContextMenu → MenuFlyout on right-click; the row
        // under the pointer becomes the SelectedItem first so the menu
        // handlers read the same state they did in WPF.
        private void RulesGrid_RightTapped(object sender, RightTappedRoutedEventArgs e)
        {
            if (e.OriginalSource is DependencyObject src)
            {
                var element = src as FrameworkElement;
                while (element != null && element is not DataGridRow)
                    element = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(element) as FrameworkElement;
                if (element is DataGridRow row && row.DataContext is RuleInfo rule)
                {
                    RulesGrid.SelectedItem = rule;
                    RuleMenu.ShowAt(RulesGrid, e.GetPosition(RulesGrid));
                    e.Handled = true;
                }
            }
        }

        private async void ToggleRule_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not RuleInfo rule) return;
            bool newState = !rule.Enabled;
            await AutoScope.Services.Fw.Service.ToggleRuleAsync(rule.Name, newState);
            rule.Enabled = newState;
            // Adopt the change into the baseline so the enforcer doesn't revert it
            AutoScope.Services.Fw.Baseline.UpdateRuleState(rule.Name, newState);
            RulesGrid.ItemsSource = null;
            RulesGrid.ItemsSource = _currentRules; // WinUI port: no INotifyPropertyChanged on the model
        }

        private async void EnableGroup_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not RuleInfo rule) return;
            ProfileStatusText.Text = $"Enabling group '{rule.DisplayGroup}'…";
            var r = await AutoScope.Services.Fw.Service.ToggleGroupAsync(rule.DisplayGroup, true);
            ProfileStatusText.Text = $"Group '{rule.DisplayGroup}': {r.Matched} matched, {r.Changed} changed, {r.Failed} failed"
                                     + (r.FirstError != null ? $" — {r.FirstError}" : "");
            await AutoScope.Services.Fw.Baseline.UpdateGroupStateAsync(rule.DisplayGroup, true);
            await LoadRules();
        }

        private async void DisableGroup_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not RuleInfo rule) return;
            ProfileStatusText.Text = $"Disabling group '{rule.DisplayGroup}'…";
            var r = await AutoScope.Services.Fw.Service.ToggleGroupAsync(rule.DisplayGroup, false);
            ProfileStatusText.Text = $"Group '{rule.DisplayGroup}': {r.Matched} matched, {r.Changed} changed, {r.Failed} failed"
                                     + (r.FirstError != null ? $" — {r.FirstError}" : "");
            await AutoScope.Services.Fw.Baseline.UpdateGroupStateAsync(rule.DisplayGroup, false);
            await LoadRules();
        }

        private async void SaveToConfig_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not RuleInfo rule) return;
            AutoScope.Services.Fw.Config.SetOverride(rule.Name, rule.Enabled);
            await Dialogs.ShowInfoAsync("Config Saved",
                $"Saved: {rule.DisplayName} = {(rule.Enabled ? "Enabled" : "Disabled")}");
        }

        private async void ProfileCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ProfileCombo == null || ProfileCombo.SelectedIndex <= 0) return;

            string profileName = ((ComboBoxItem)ProfileCombo.SelectedItem).Content.ToString();

            if (profileName == "Shields Up")
            {
                // Far more destructive than the other profiles — spell out both steps
                const string warning =
                    "Shields Up performs two destructive steps:\n\n" +
                    "1. RESET TO DEFAULTS — every non-default rule is deleted, including\n" +
                    "    custom rules and AutoScope's own AS-BLOCK rules.\n" +
                    "2. LOCKDOWN — every inbound and outbound rule is then disabled: all\n" +
                    "    unsolicited incoming traffic is blocked. Outbound traffic may still\n" +
                    "    flow depending on your firewall profile's default actions.\n\n" +
                    "Apply this profile?";
                if (!await Dialogs.ConfirmAsync("Confirm Shields Up", warning))
                {
                    ProfileCombo.SelectedIndex = 0; // Reset to Custom
                    return;
                }
            }
            else if (!await Dialogs.ConfirmAsync("Confirm Firewall Profile",
                $"Apply '{profileName}' profile?\n\nThis will modify your Windows Defender Firewall rules."))
            {
                ProfileCombo.SelectedIndex = 0; // Reset to Custom
                return;
            }

            ProfileType type;
            switch (profileName)
            {
                case "Shields Up + mDNS": type = ProfileType.ShieldsUpMdns; break;
                case "Allow Discovery + Cast": type = ProfileType.AllowDiscoveryCast; break;
                case "Allow Sharing + Discovery + Remote Desktop": type = ProfileType.AllowSharingDiscoveryRemoteDesktop; break;
                case "Allow Sharing + Discovery": type = ProfileType.AllowSharingDiscovery; break;
                case "Block Sharing + Discovery + Remote Desktop": type = ProfileType.BlockSharingDiscoveryRemoteDesktop; break;
                case "Shields Up": type = ProfileType.ShieldsUp; break;
                default:
                    ProfileCombo.SelectedIndex = 0;
                    return;
            }

            ProfileCombo.IsEnabled = false;
            RefreshBtn.IsEnabled = false;
            ProfileProgress.Visibility = Visibility.Visible;
            ProfileStatusText.Text = $"Applying '{profileName}' profile…";
            var progress = new Progress<string>(msg => ProfileStatusText.Text = msg);

            try
            {
                ProfileApplyResult result = await AutoScope.Services.Fw.Profiles.ApplyProfile(type, progress);

                await LoadRules(); // Auto-refresh the grid so the new state is shown immediately

                // The profile's end state is now the expected state — capture it as the
                // baseline the Security Enforcer will enforce against future drift
                int baselineCount = 0;
                try
                {
                    var (count, at) = await AutoScope.Services.Fw.Baseline.CaptureBaselineAsync();
                    baselineCount = count;
                    BaselineStatusText.Text = $"Baseline: {count} rules (captured {at:yyyy-MM-dd HH:mm})";
                }
                catch { }

                var sb = new StringBuilder();
                sb.AppendLine($"Profile '{profileName}' applied.");
                if (!string.IsNullOrEmpty(result.Notes)) sb.AppendLine(result.Notes);
                foreach (var g in result.Groups)
                {
                    if (g.GroupName == "Shields Up + mDNS (block all)" || g.GroupName == "Lockdown (reset to defaults)")
                        continue; // Covered by the Notes line
                    sb.AppendLine($"• {g.GroupName}: {g.Matched} matched, {g.Changed} changed"
                                  + (g.Failed > 0 ? $", {g.Failed} FAILED" : ""));
                }
                sb.AppendLine($"Total: {result.TotalChanged} rule(s) changed, {result.TotalFailed} failed.");
                if (baselineCount > 0)
                    sb.AppendLine($"Baseline captured with {baselineCount} rules — drift from this state will now be detected and fixed automatically.");
                if (result.TotalMatched == 0) sb.AppendLine("No matching rules were found — no changes were made.");
                if (result.FirstError != null) sb.AppendLine($"First error: {result.FirstError}");

                ProfileStatusText.Text = $"Profile '{profileName}': {result.TotalChanged} rule(s) changed, "
                                         + $"{result.TotalFailed} failed. Rules list refreshed.";

                await Dialogs.ShowInfoAsync("Firewall Profile Complete", sb.ToString());
            }
            catch (Exception ex)
            {
                ProfileStatusText.Text = $"Failed to apply '{profileName}': {ex.Message}";
                await Dialogs.ShowInfoAsync("Error", $"Failed to apply profile: {ex.Message}");
            }
            finally
            {
                ProfileProgress.Visibility = Visibility.Collapsed;
                RefreshBtn.IsEnabled = true;
                // Reset combobox back to custom to allow re-selection later
                ProfileCombo.IsEnabled = true;
                ProfileCombo.SelectedIndex = 0;
            }
        }

        public string GetAuditContext()
        {
            if (_currentRules.Count == 0) return "No firewall rules loaded. Click Refresh first.";
            var sb = new StringBuilder();
            string dir = InboundRadio.IsChecked == true ? "Inbound" : "Outbound";
            sb.AppendLine($"Firewall Rules ({dir}) — {_currentRules.Count} total:");
            foreach (var rule in _currentRules.Where(r => r.Enabled).Take(80))
            {
                sb.AppendLine($"- [{(rule.Enabled ? "ENABLED" : "disabled")}] {rule.DisplayName} | Group: {rule.DisplayGroup} | Action: {rule.Action}");
            }
            if (_currentRules.Count(r => !r.Enabled) > 0)
                sb.AppendLine($"... plus {_currentRules.Count(r => !r.Enabled)} disabled rules omitted.");
            return sb.ToString();
        }
    }
}
