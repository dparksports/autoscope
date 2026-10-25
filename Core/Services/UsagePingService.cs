using System;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AutoScope.Services
{
    /// <summary>
    /// Anonymous daily usage count — the only thing AutoScope ever sends.
    /// Counts active installs so the project can show real usage numbers;
    /// there is no other telemetry of any kind.
    ///
    /// Consent model: OFF by default. A one-time dialog (max 3 offers) asks
    /// the user to opt in; "no" is permanent and respected immediately.
    /// State lives in HKCU\Software\AutoScope\UsagePing (Consent = ask|yes|no,
    /// LastSentDay, Asks) — readable registry policy, same as every other
    /// app setting.
    ///
    /// Payload — the whole thing, nothing else, ever:
    ///   { "a": "autocommand",
    ///     "v": build date, compact (e.g. 261015),  "o": Windows build }
    /// NO identifier of any kind is included — not even a random install id.
    /// The app sends at most once per UTC day (LastSentDay below), so each
    /// consenting install adds 1 to a daily aggregate counter on the server.
    /// The server derives country at the network edge and never stores an IP
    /// address; it keeps only daily totals (see telemetry/ in the repository
    /// for the spec, the worker code, and the one-table schema). Deleting the
    /// registry key withdraws consent.
    ///
    /// Endpoint stays empty until the receiver is deployed (telemetry/server);
    /// while empty this whole service is inert — no dialog, no network.
    /// </summary>
    public static class UsagePingService
    {
        // Receiver deployed 2026-10-15 (worker + D1; deploy/hardening notes in
        // telemetry/server/DEPLOY.md, spec in telemetry/USAGE_PING_SPEC.md).
        private const string Endpoint = "https://autocommand-usage-ping.dpark-sports.workers.dev/v1/ping";
        private const string AppName = "autocommand";
        private const int MaxAsks = 3;

        private const string RegKey = @"Software\AutoScope\UsagePing";

        /// <summary>Root of the public community graph page (served by the same
        /// worker — daily actives, countries, download + share links). Null while
        /// Endpoint is unset, so callers fall back to the releases page.</summary>
        public static string GraphPageUrl
        {
            get
            {
                if (string.IsNullOrWhiteSpace(Endpoint) || !Endpoint.StartsWith("https://")) return null;
                int cut = Endpoint.IndexOf('/', "https://".Length);
                return cut < 0 ? Endpoint : Endpoint.Substring(0, cut);
            }
        }

        /// <summary>Stable public download link — what the Share button copies
        /// when the graph page isn't deployed yet.</summary>
        public const string ReleasesUrl = "https://github.com/dparksports/autocommand-windows/releases/latest";

        /// <summary>Installed by the WinUI app: shows the consent dialog and
        /// returns true when it was shown and answered (the dialog writes the
        /// consent value itself). Null (default) disables asking entirely —
        /// the service stays fully inert, as it is without an endpoint.</summary>
        public static System.Func<System.Threading.Tasks.Task<bool>> ShowConsentPrompt { get; set; }

        /// <summary>Startup entry point — call once from App.OnStartup (UI thread).</summary>
        public static async Task RunStartupFlowAsync()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(Endpoint) || !Endpoint.StartsWith("https://"))
                    return; // not configured → fully inert, including the consent dialog

                string consent = ReadString("Consent", "ask");

                if (consent == "yes")
                {
                    _ = SendDailyPingAsync(); // fire-and-forget; never blocks startup
                    return;
                }

                if (consent == "ask" && ReadInt("Asks", 0) < MaxAsks)
                {
                    // Let the main window settle first so the dialog isn't the
                    // first thing a user sees.
                    await Task.Delay(4000);
                    if (ShowConsentPrompt == null) return; // no UI installed → don't ask

                    WriteInt("Asks", ReadInt("Asks", 0) + 1);
                    bool answered = await ShowConsentPrompt();
                    var answer = answered
                        ? ReadString("Consent", "ask")   // dialog wrote the answer itself
                        : "no";

                    if (answer == "yes")
                        _ = SendDailyPingAsync();
                }
            }
            catch { /* never let counting break the app */ }
        }

        /// <summary>Writes the consent answer (yes|no|ask). Public for the
        /// consent dialog and a future Settings toggle.</summary>
        public static void SetConsent(string value)
        {
            if (value != "yes" && value != "no" && value != "ask") return;
            WriteString("Consent", value);
        }

        /// <summary>Sends today's ping unless one was already sent (UTC day).
        /// The daily check is client-side — the server never sees anything
        /// that could identify this install, so "once per day" is all we
        /// can and need to enforce.</summary>
        public static async Task SendDailyPingAsync()
        {
            try
            {
                string today = DateTime.UtcNow.ToString("yyyy-MM-dd");
                if (ReadString("LastSentDay", "") == today) return;

                var payload = JsonSerializer.Serialize(new
                {
                    a = AppName,
                    v = CompactBuildDate(),
                    o = Environment.OSVersion.Version.ToString()
                });

                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var response = await client.PostAsync(Endpoint, content);
                if (response.IsSuccessStatusCode)
                    WriteString("LastSentDay", today);
                // On failure: no state change — retried on a later launch, never spammed.
            }
            catch { /* offline / DNS blocked / endpoint down — silently fine */ }
        }

        /// <summary>The count tracks builds by day, so the ping sends the
        /// version's date in compact form (2026.10.15[.2] → 261015) rather than
        /// the full app version — same-day revisions fold to the same day, by
        /// design. Anything unparseable passes through unchanged.</summary>
        private static string CompactBuildDate()
        {
            string v = Assembly.GetEntryAssembly()?
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                .InformationalVersion ?? "unknown";
            var m = System.Text.RegularExpressions.Regex.Match(v, @"^(\d{4})\.(\d{2})\.(\d{2})");
            return m.Success
                ? m.Groups[1].Value.Substring(2) + m.Groups[2].Value + m.Groups[3].Value
                : v;
        }

        // ── HKCU persistence (same store and style as ThemeService) ──

        private static Microsoft.Win32.RegistryKey OpenKey(bool writable = true)
        {
            using var root = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\AutoScope", writable);
            return root?.CreateSubKey("UsagePing", writable: writable);
        }

        private static string ReadString(string name, string fallback)
        {
            try { using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegKey);
                  return (string)k?.GetValue(name) ?? fallback; }
            catch { return fallback; }
        }

        private static int ReadInt(string name, int fallback)
        {
            return int.TryParse(ReadString(name, null), out var v) ? v : fallback;
        }

        private static void WriteString(string name, string value)
        {
            try { using var k = OpenKey(); k?.SetValue(name, value); } catch { }
        }

        private static void WriteInt(string name, int value) => WriteString(name, value.ToString());
    }
}
