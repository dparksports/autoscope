using System;
using System.Diagnostics;
using Windows.UI.Notifications;
using Windows.Data.Xml.Dom;

namespace AutoScope.Helpers
{
    /// <summary>
    /// Displays Windows 10/11 Toast Notifications (Action Center) for security alerts.
    /// Uses the WinRT ToastNotification API — requires no extra NuGet packages and 
    /// works on net10.0-windows10.0.19041.0+.
    /// Notifications appear in the Action Center even when AutoScope is minimized.
    /// </summary>
    public sealed class TrayNotifier : IDisposable
    {
        private const string AppId = "AutoScope.SecurityTool";
        private bool _disposed;

        // Fired when user interaction with a toast is needed (e.g. bring window forward)
        public event Action ToastActivated;

        public TrayNotifier(string iconPath = null)
        {
            // No tray icon needed — WinRT toasts handle their own presentation.
            // iconPath is accepted for API compatibility but unused.
        }

        /// <summary>
        /// Shows a Windows Toast notification with a security warning.
        /// Appears in the Action Center even if the app is minimized.
        /// </summary>
        public void ShowSecurityAlert(string title, string message, int durationMs = 10000) =>
            ShowSecurityAlert(title, message, durationMs, null);

        /// <summary>
        /// Same toast, with a per-toast activation callback (fired alongside
        /// the global ToastActivated event) so a specific toast can do more
        /// than bring the window forward — e.g. select the tab it came from.
        /// The callback may fire on a WinRT thread: marshal to the UI thread
        /// inside it.
        /// </summary>
        public void ShowSecurityAlert(string title, string message, int durationMs, Action onActivated)
        {
            if (_disposed) return;
            try
            {
                // Build the Toast XML template
                string xmlPayload = $@"
<toast>
  <visual>
    <binding template=""ToastGeneric"">
      <text>{EscapeXml(title)}</text>
      <text>{EscapeXml(message)}</text>
    </binding>
  </visual>
  <actions>
    <action content=""Review"" arguments=""review"" activationType=""foreground""/>
    <action content=""Dismiss"" arguments=""dismiss"" activationType=""background""/>
  </actions>
</toast>";

                var toastXml = new XmlDocument();
                toastXml.LoadXml(xmlPayload);

                var toast = new ToastNotification(toastXml);
                toast.Activated += (s, e) =>
                {
                    ToastActivated?.Invoke();
                    try { onActivated?.Invoke(); } catch { /* a toast handler must never crash the app */ }
                };

                var notifier = ToastNotificationManager.CreateToastNotifier(AppId);
                notifier.Show(toast);
            }
            catch (Exception ex)
            {
                // Toast may fail if no app identity is registered — fall back silently.
                Debug.WriteLine($"TrayNotifier.ShowSecurityAlert: {ex.Message}");
                FallbackAlert(title, message);
            }
        }

        /// <summary>
        /// Fallback: if the WinRT toast API fails (no app registration),
        /// writes the alert to the debug log so it's not silently lost.
        /// </summary>
        private void FallbackAlert(string title, string message)
        {
            Debug.WriteLine($"[SECURITY ALERT] {title}: {message}");
        }

        /// <summary>Updates tray tooltip — no-op for toast-only implementation.</summary>
        public void SetStatus(string status) { }

        private static string EscapeXml(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            return s.Replace("&", "&amp;")
                    .Replace("<", "&lt;")
                    .Replace(">", "&gt;")
                    .Replace("\"", "&quot;")
                    .Replace("'", "&apos;");
        }

        public void Dispose()
        {
            _disposed = true;
        }
    }
}
