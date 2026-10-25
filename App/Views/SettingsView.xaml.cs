using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using AutoScope.Services;
using AutoScope.Helpers;

namespace AutoScope.Views
{
    /// <summary>
    /// Settings ported from AutoCommand's WPF SettingsView, scoped to the
    /// six-tab app: the Appearance card (this port is fixed dark), the
    /// Advanced-investigation card (no hidden tabs exist here) and the
    /// community/share buttons (AutoCommand endpoints) are not ported.
    /// WinUI notes: FolderPicker replaces OpenFolderDialog, the WinUI
    /// clipboard replaces Clipboard.SetText.
    /// </summary>
    public partial class SettingsView : Page
    {
        private const string TaskName = FreshSetupService.StartupTaskName;

        public SettingsView()
        {
            InitializeComponent();

            // Live version from the assembly instead of a hardcoded string
            // (same source as the status bar)
            VersionValueText.Text =
                FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion ?? "unknown";
        }

        private async void Page_Loaded(object sender, RoutedEventArgs e)
        {
            await CheckStartupTask();

            // Load Auto-Mitigate Adapters preference
            AutoMitigateAdaptersCheck.Checked -= AutoMitigateAdaptersCheck_Checked;
            AutoMitigateAdaptersCheck.Unchecked -= AutoMitigateAdaptersCheck_Unchecked;
            AutoMitigateAdaptersCheck.IsChecked = SecurityEnforcer.AutoMitigateAdapters;
            AutoMitigateAdaptersCheck.Checked += AutoMitigateAdaptersCheck_Checked;
            AutoMitigateAdaptersCheck.Unchecked += AutoMitigateAdaptersCheck_Unchecked;

            // Load the security check rate (fast-check tick interval)
            CheckRateCombo.SelectionChanged -= CheckRateCombo_SelectionChanged;
            foreach (var item in CheckRateCombo.Items.OfType<ComboBoxItem>())
            {
                if (item.Tag is string tag && tag == SecurityEnforcer.CheckIntervalSeconds.ToString())
                {
                    item.IsSelected = true;
                    break;
                }
            }
            CheckRateCombo.SelectionChanged += CheckRateCombo_SelectionChanged;
        }

        private void CheckRateCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CheckRateCombo.SelectedItem is ComboBoxItem item
                && item.Tag is string tag && int.TryParse(tag, out int seconds))
            {
                SecurityEnforcer.CheckIntervalSeconds = seconds;
            }
        }

        private void AutoMitigateAdaptersCheck_Checked(object sender, RoutedEventArgs e)
        {
            SecurityEnforcer.AutoMitigateAdapters = true;
        }

        private void AutoMitigateAdaptersCheck_Unchecked(object sender, RoutedEventArgs e)
        {
            SecurityEnforcer.AutoMitigateAdapters = false;
        }

        private async Task CheckStartupTask()
        {
            bool exists = false;
            await Task.Run(() =>
            {
                try
                {
                    Type tsType = Type.GetTypeFromProgID("Schedule.Service");
                    dynamic ts = Activator.CreateInstance(tsType);
                    ts.Connect();
                    dynamic rootFolder = ts.GetFolder("\\");
                    dynamic task = rootFolder.GetTask(TaskName);
                    exists = task != null;
                }
                catch
                {
                    exists = false;
                }
            });

            // Detach events to avoid infinite loop
            LaunchOnStartupCheck.Checked -= LaunchOnStartupCheck_Checked;
            LaunchOnStartupCheck.Unchecked -= LaunchOnStartupCheck_Unchecked;

            LaunchOnStartupCheck.IsChecked = exists;

            LaunchOnStartupCheck.Checked += LaunchOnStartupCheck_Checked;
            LaunchOnStartupCheck.Unchecked += LaunchOnStartupCheck_Unchecked;
        }

        private async void LaunchOnStartupCheck_Checked(object sender, RoutedEventArgs e)
        {
            bool ok = await FreshSetupService.EnableLaunchAtLogon();
            if (!ok)
                await Dialogs.ShowInfoAsync("Error", "Failed to create startup task.");
            await CheckStartupTask();
        }

        private async void LaunchOnStartupCheck_Unchecked(object sender, RoutedEventArgs e)
        {
            await FreshSetupService.DisableLaunchAtLogon();
            await CheckStartupTask();
        }

        // -----------------------------------------------------------------------
        // Unblock (Mark-of-the-Web removal) — see Core Helpers/MotwUnblocker.cs
        // -----------------------------------------------------------------------

        private async void UnblockAppBtn_Click(object sender, RoutedEventArgs e)
        {
            string dir = AppDomain.CurrentDomain.BaseDirectory;
            UnblockAppBtn.IsEnabled = false;
            UnblockStatusText.Text = $"Scanning {dir} …";
            try
            {
                var result = await System.Threading.Tasks.Task.Run(() => MotwUnblocker.UnblockFolder(dir));
                UnblockStatusText.Text = result.Summary;
                if (result.Unblocked > 0)
                    await Dialogs.ShowInfoAsync("Unblocked",
                        $"Removed the download mark from {result.Unblocked} file(s) in this app's folder.\n\n" +
                        "SmartScreen / Smart App Control will no longer treat them as downloaded\n" +
                        "files — taskbar pins and direct launches work normally now.");
            }
            finally
            {
                UnblockAppBtn.IsEnabled = true;
            }
        }

        private async void UnblockFolderBtn_Click(object sender, RoutedEventArgs e)
        {
            // WinUI port: FolderPicker needs the window handle on unpackaged apps
            string folder = null;
            try
            {
                var picker = new Windows.Storage.Pickers.FolderPicker();
                WinRT.Interop.InitializeWithWindow.Initialize(
                    picker, WinRT.Interop.WindowNative.GetWindowHandle(App.MainWin));
                picker.SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.Downloads;
                picker.FileTypeFilter.Add("*");
                var picked = await picker.PickSingleFolderAsync();
                folder = picked?.Path;
            }
            catch { /* picker unavailable — treated as cancel */ }
            if (folder == null) return;

            UnblockFolderBtn.IsEnabled = false;
            UnblockStatusText.Text = $"Scanning {folder} …";
            try
            {
                var result = await System.Threading.Tasks.Task.Run(() => MotwUnblocker.UnblockFolder(folder));
                UnblockStatusText.Text = result.Summary;
                if (result.Failures.Count > 0)
                    await Dialogs.ShowInfoAsync("Unblock",
                        $"{result.Summary}\n\nFiles in use or in admin-only locations could not be updated —\n" +
                        "close the apps using them, or re-run AutoScope as Administrator and try again.");
            }
            finally
            {
                UnblockFolderBtn.IsEnabled = true;
            }
        }
    }
}
