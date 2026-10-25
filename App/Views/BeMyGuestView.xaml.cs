using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using AutoScope.Services;

namespace AutoScope.Views
{
    /// <summary>
    /// Be My Guest tab ported from AutoCommand's WPF BeMyGuestView. WinUI
    /// port notes: DispatcherTimer → DispatcherQueueTimer, MessageBox →
    /// Dialogs, Clipboard.SetText → the WinUI clipboard; paths and the MCP
    /// entry id carry the AutoScope identity so this app and AutoCommand
    /// can run side by side.
    /// </summary>
    public partial class BeMyGuestView : Page
    {
        private void Page_Loaded(object sender, RoutedEventArgs e)
        {
            // AI access: mutating preference + live session status
            try
            {
                AgentMutatingCheck.IsChecked = File.Exists(MutatingPrefPath) && File.ReadAllText(MutatingPrefPath).Trim() == "on";
            }
            catch { AgentMutatingCheck.IsChecked = false; }
            PopulateClientButtons();
            StartAgentRefresh();
        }

        // -----------------------------------------------------------------------
        // AI access (agent bridge) — see Core Services/AgentBridgeService.cs
        // -----------------------------------------------------------------------

        private readonly Microsoft.UI.Dispatching.DispatcherQueueTimer _agentRefresh;

        public BeMyGuestView()
        {
            InitializeComponent();
            _agentRefresh = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread().CreateTimer();
        }

        private static string MutatingPrefPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoScope", "agent", "mutating_pref.txt");

        private void Page_Unloaded(object sender, RoutedEventArgs e) => _agentRefresh.Stop();

        private void StartAgentRefresh()
        {
            RefreshAgentUi();
            _agentRefresh.Tick -= (_, _) => RefreshAgentUi();
            _agentRefresh.Tick += (_, _) => RefreshAgentUi();
            _agentRefresh.Interval = TimeSpan.FromSeconds(2);
            _agentRefresh.Start();
        }

        private void RefreshAgentUi()
        {
            var bridge = AgentBridgeService.Instance;
            bool running = bridge.IsRunning;
            StartAgentBtn.IsEnabled = !running;
            StopAgentBtn.IsEnabled = running;
            AgentStatusText.Text = running
                ? $"Session ACTIVE · 127.0.0.1:{bridge.Port} · client: {bridge.ClientName} · {bridge.ConnectedCalls} call(s)"
                : "Session off. The assistant can connect but every tool answers 'start the session'.";

            AgentActivityList.ItemsSource = AgentBridgeService.RecentActivity(30)
                .Select(l => l.Length > 160 ? l[..160] + "…" : l)
                .ToList();
        }

        private async void StartAgentBtn_Click(object sender, RoutedEventArgs e)
        {
            // Tier-1 consent: this is the moment the user decides what an AI
            // assistant may read — state it plainly, in one dialog.
            bool answer = await Dialogs.ConfirmAsync("Be My Guest — consent",
                "Start an AI access session?\n\n" +
                "An AI assistant (e.g. ZCode) will be able to READ this machine's security telemetry:\n" +
                "live connections and their processes, svchost identities, PID provenance reports,\n" +
                "Sysmon events and trace analysis. What it reads can be repeated by the assistant.\n\n" +
                "• Read-only tools answer immediately while the session is on.\n" +
                "• Mutating actions (block/kill/disable) ask you again on every single call\n" +
                "  (and only exist at all if you tick them on below).\n" +
                "• The session ends when you stop it or close AutoScope.\n\n" +
                "Start the session?");
            if (!answer) return;

            var (ok, message) = AgentBridgeService.Instance.Start(AgentMutatingCheck.IsChecked == true);
            if (!ok) await Dialogs.ShowInfoAsync("Be My Guest", message);
            RefreshAgentUi();
        }

        private void StopAgentBtn_Click(object sender, RoutedEventArgs e)
        {
            AgentBridgeService.Instance.Stop();
            RefreshAgentUi();
        }

        private async void AgentMutatingCheck_Changed(object sender, RoutedEventArgs e)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(MutatingPrefPath));
                File.WriteAllText(MutatingPrefPath, AgentMutatingCheck.IsChecked == true ? "on" : "off");
            }
            catch { /* persistence best-effort */ }

            // a running session keeps its launch-time setting; say so plainly
            if (AgentBridgeService.Instance.IsRunning)
                await Dialogs.ShowInfoAsync("Be My Guest",
                    "Takes effect for NEW sessions. Stop and restart the session to apply it now.");
        }

        /// <summary>
        /// One Register button per known MCP client, enabled when the client
        /// is detected on this machine. Anything undetected stays visible but
        /// disabled — and 'Copy MCP config' remains the universal fallback.
        /// </summary>
        private void PopulateClientButtons()
        {
            AgentClientsPanel.Children.Clear();
            foreach (var client in McpClientCatalog.Catalog)
            {
                bool detected = McpClientCatalog.IsDetected(client);
                var btn = new Button
                {
                    Content = "Register in " + client.DisplayName,
                    Tag = client,
                    Padding = new Thickness(10, 2, 10, 2),
                    Margin = new Thickness(0, 0, 8, 0),
                    IsEnabled = detected,
                };
                ToolTipService.SetToolTip(btn, detected
                    ? client.ConfigPath
                    : client.DisplayName + " not detected on this machine — install it first, or use Copy MCP config.");
                btn.Click += ClientRegisterBtn_Click;
                AgentClientsPanel.Children.Add(btn);
            }
        }

        private async void ClientRegisterBtn_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: McpClientRegistration client }) return;

            var (proxy, installNote) = McpClientCatalog.ResolveAndInstallProxy();
            if (proxy == null)
            {
                await Dialogs.ShowInfoAsync("Be My Guest",
                    "AutoScope.AgentProxy.exe was not found next to the app.\n" +
                    "Reinstall AutoScope (or rebuild from source) and try again.\n\n" + installNote);
                return;
            }

            // never point a client config at a proxy that cannot start: prove
            // it answers an MCP handshake here first, including under the
            // hostile DOTNET_ROOT that desktop MCP clients are known to export
            var (preOk, preMsg) = McpClientCatalog.PreflightProxy(proxy);
            if (!preOk)
            {
                await Dialogs.ShowInfoAsync("Be My Guest",
                    "The proxy is installed but failed its startup preflight — it was NOT registered:\n\n" +
                    preMsg + "\n\n" + installNote);
                return;
            }

            var (ok, message) = McpClientCatalog.Register(client, proxy);
            if (ok) message += "\n\nPreflight passed: the installed proxy answered an MCP handshake, " +
                               "including with a hostile DOTNET_ROOT.";
            await Dialogs.ShowInfoAsync(ok ? "Registered" : "AI access", message);
        }

        private async void CopyAgentConfigBtn_Click(object sender, RoutedEventArgs e)
        {
            string proxy = McpClientCatalog.ResolveAndInstallProxy().ProxyPath
                ?? "%LOCALAPPDATA%\\AutoScope\\tools\\AutoScope.AgentProxy.exe";
            string config =
                "{\n  \"mcp\": {\n    \"servers\": {\n      \"autoscope\": {\n" +
                "        \"command\": \"" + proxy.Replace("\\", "\\\\") + "\",\n" +
                "        \"args\": []\n" +
                "      }\n    }\n  }\n}";
            try
            {
                var pkg = new Windows.ApplicationModel.DataTransfer.DataPackage();
                pkg.SetText(config);
                Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(pkg);
            }
            catch { /* clipboard unavailable — nothing to do */ }
            await Dialogs.ShowInfoAsync("Copied",
                "MCP config copied — paste it into the client's mcp.servers config " +
                "(ZCode: ~/.zcode/cli/config.json or <repo>/.zcode/config.json).");
        }

        private void OpenAgentLogBtn_Click(object sender, RoutedEventArgs e)
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AutoScope", "agent");
            Directory.CreateDirectory(dir);
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true });
        }
    }
}
