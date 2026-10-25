using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace AutoScope.Views
{
    /// <summary>
    /// Confirmation for firewall blocks from the Process Monitor, ported
    /// from AutoCommand's WPF BlockConfirmWindow. A plain dialog cannot host
    /// a checkbox, so this window carries the class-specific warning plus
    /// the "don't ask again" check-off (a ConfirmPrefs key) — same rules as
    /// the original: the choice is per warning class and reversible from the
    /// Blocked popup's reset button.
    ///
    /// WinUI port: windows are non-modal here, so callers await the Closed
    /// event and then read Confirmed/Suppress (same flow the WPF version's
    /// DialogResult drove).
    /// </summary>
    public sealed class BlockConfirmWindow : Window
    {
        public bool Confirmed { get; private set; }
        public bool Suppress => _suppressCheck != null && _suppressCheck.IsChecked == true;

        /// <summary>ConfirmPrefs key the checkbox silences (null → no checkbox shown).</summary>
        public string SuppressKey { get; }

        private readonly CheckBox _suppressCheck = new() { FontSize = 12 };

        public BlockConfirmWindow(string headline, string warning, string detail,
                                  string suppressKey, string suppressLabel)
        {
            Title = "Confirm block";
            SuppressKey = suppressKey;

            var panel = new StackPanel { Margin = new Thickness(20), Spacing = 12 };

            panel.Children.Add(new TextBlock
            {
                Text = headline,
                TextWrapping = TextWrapping.Wrap,
                FontSize = 14,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                Foreground = (Brush)Application.Current.Resources["TextPrimaryBrush"],
            });

            if (!string.IsNullOrEmpty(warning))
            {
                panel.Children.Add(new Border
                {
                    Background = new SolidColorBrush(Color.FromArgb(0x26, 0xFB, 0xBF, 0x24)),
                    BorderBrush = new SolidColorBrush(Color.FromArgb(0xFF, 0xFB, 0xBF, 0x24)),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(4),
                    Padding = new Thickness(10, 6, 10, 6),
                    Child = new TextBlock
                    {
                        Text = warning,
                        TextWrapping = TextWrapping.Wrap,
                        FontSize = 12,
                        Foreground = new SolidColorBrush(Color.FromArgb(0xFF, 0xFB, 0xBF, 0x24)),
                    },
                });
            }

            panel.Children.Add(new TextBlock
            {
                Text = detail,
                TextWrapping = TextWrapping.Wrap,
                FontSize = 12,
                Foreground = (Brush)Application.Current.Resources["TextSecondaryBrush"],
            });

            if (!string.IsNullOrEmpty(suppressLabel))
            {
                _suppressCheck.Content = suppressLabel;
                ToolTipService.SetToolTip(_suppressCheck,
                    "Applies to this class of block only. Undo anytime: 'Blocked' popup → 'Reset don't-ask-again choices'.");
                panel.Children.Add(_suppressCheck);
            }

            var buttons = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 6, 0, 0),
                Spacing = 8,
            };
            var cancel = new Button { Content = "Cancel", Padding = new Thickness(16, 4, 16, 4) };
            cancel.Click += (_, _) => Close();
            var block = new Button
            {
                Content = "⛔ Block",
                Padding = new Thickness(16, 4, 16, 4),
                Style = (Style)Application.Current.Resources["PrimaryButton"],
            };
            block.Click += (_, _) => { Confirmed = true; Close(); };
            buttons.Children.Add(cancel);
            buttons.Children.Add(block);
            panel.Children.Add(buttons);

            Content = panel;

            try { AppWindow.Resize(new Windows.Graphics.SizeInt32 { Width = 520, Height = 470 }); }
            catch { /* cosmetic */ }
        }
    }
}
