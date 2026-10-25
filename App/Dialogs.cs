using Microsoft.UI.Xaml.Controls;

namespace AutoScope
{
    /// <summary>
    /// ContentDialog helpers — the WinUI replacement for the WPF MessageBox
    /// calls sprinkled through AutoCommand's shell and views.
    /// </summary>
    public static class Dialogs
    {
        private static ContentDialog Build(string title, string message,
            string primary, string secondary, string close)
        {
            var dlg = new ContentDialog
            {
                Title = title,
                Content = message,
                PrimaryButtonText = primary ?? "OK",
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = App.MainWin?.Content?.XamlRoot,
            };
            if (secondary != null) dlg.SecondaryButtonText = secondary;
            if (close != null) dlg.CloseButtonText = close;
            return dlg;
        }

        /// <summary>OK-only informational dialog (MessageBox.OK).</summary>
        public static System.Threading.Tasks.Task ShowInfoAsync(string title, string message)
            => Build(title, message, "OK", null, null).ShowAsync().AsTask();

        /// <summary>Yes/No question (MessageBox.YesNo). True = Yes.</summary>
        public static async System.Threading.Tasks.Task<bool> ConfirmAsync(string title, string message)
            => await Build(title, message, "Yes", "No", null).ShowAsync() == ContentDialogResult.Primary;

        /// <summary>Three-way (Yes/No/Cancel): 1=Yes, 0=No, -1=Cancel/dismiss.</summary>
        public static async System.Threading.Tasks.Task<int> ThreeWayAsync(string title, string message)
        {
            var r = await Build(title, message, "Yes", "No", "Cancel").ShowAsync();
            return r == ContentDialogResult.Primary ? 1 : r == ContentDialogResult.Secondary ? 0 : -1;
        }
    }
}
