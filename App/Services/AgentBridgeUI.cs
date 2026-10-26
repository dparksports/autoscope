using System;
using AutoScope.Engines.Bridge;
using AutoScope.Engines.Watch;
using System.Threading.Tasks;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using AutoScope.Services;

namespace AutoScope.Services
{
    /// <summary>
    /// The WinUI implementation of the bridge's UI hooks (the port of
    /// AutoCommand's WPF AgentConfirmWindow flow): marshals to the UI
    /// thread via DispatcherQueue and asks for tier-3 consent with a
    /// ContentDialog that carries the "always for this session" checkbox.
    /// Installed once at startup (App.OnLaunched sets AgentBridgeService.Ui).
    /// </summary>
    public sealed class AgentBridgeUI : IAgentBridgeUI
    {
        private readonly DispatcherQueue _dq = DispatcherQueue.GetForCurrentThread();

        public bool IsUiAvailable => App.MainWin?.Content != null;

        public void BeginInvokeOnUI(Action action)
        {
            if (_dq.HasThreadAccess) action();
            else _dq.TryEnqueue(() => action());
        }

        // F# engine interface signature: F# tuples surface as Tuple<_,_>
        public async Task<System.Tuple<bool, bool>> ShowConfirmAsync(string tool, string detail)
        {
            var alwaysCheck = new CheckBox
            {
                Content = "Always allow this tool for this session only",
                FontSize = 12,
                Margin = new Thickness(0, 12, 0, 0),
            };
            var panel = new StackPanel
            {
                Margin = new Thickness(4),
                Spacing = 10,
                Children =
                {
                    new TextBlock
                    {
                        Text = $"An AI assistant asks to run: {tool}",
                        TextWrapping = TextWrapping.Wrap,
                        FontSize = 14,
                        FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                        Foreground = (Brush)Application.Current.Resources["TextPrimaryBrush"],
                    },
                    new TextBlock
                    {
                        Text = detail,
                        TextWrapping = TextWrapping.Wrap,
                        FontSize = 12,
                        Foreground = (Brush)Application.Current.Resources["TextSecondaryBrush"],
                    },
                    alwaysCheck,
                },
            };

            var dlg = new ContentDialog
            {
                Title = "Be My Guest — allow this action?",
                Content = panel,
                PrimaryButtonText = "Allow",
                SecondaryButtonText = "Deny",
                DefaultButton = ContentDialogButton.Secondary,
                XamlRoot = App.MainWin?.Content?.XamlRoot,
            };

            // The bridge waits on this answer for up to 90 s, then answers
            // 'denied (timeout)' on its own (same timing contract as WPF).
            var result = await dlg.ShowAsync();
            return System.Tuple.Create(result == ContentDialogResult.Primary, alwaysCheck.IsChecked == true);
        }
    }
}
