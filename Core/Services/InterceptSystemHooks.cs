using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace AutoScope.Services
{
    /// <summary>
    /// The driverless system hooks an intercept session installs, and their
    /// exact undo:
    ///
    ///   - WinHTTP proxy (netsh) — how Windows SERVICES (svchost, BITS,
    ///     Delivery Optimization, telemetry hosts) are routed into the local
    ///     proxy with zero drivers. Works on 26H2 regardless of HVCI or
    ///     Smart App Control, unlike the WinDivert transparent-redirect
    ///     route the open-source tools take.
    ///   - WinINET per-user proxy (registry + refresh broadcast) — user-side
    ///     apps, same effect.
    ///   - One outbound UDP/443 block rule per target program — QUIC cannot
    ///     be MITM'd by an HTTP proxy; the block makes QUIC-using clients
    ///     fall back to TCP/TLS for the session's duration. Standard WFP
    ///     rule via netsh, no driver.
    ///
    /// Every change is journaled to session-active.json BEFORE it is made
    /// and the journal deleted after a clean stop, so a crash never leaves
    /// the machine proxied: RecoverAfterCrash() runs at every app start and
    /// undoes whatever the journal still describes.
    /// </summary>
    public static class InterceptSystemHooks
    {
        internal const string FirewallRulePrefix = "AutoScope Intercept QUIC block";

        private static string JournalPath => Path.Combine(InterceptCaService.Dir, "session-active.json");

        internal sealed class Journal
        {
            public string WinHttpProxyBefore { get; set; }   // null = direct (netsh reset proxy restores this)
            public int? WininetEnableBefore { get; set; }
            public string WininetServerBefore { get; set; }
            public string CaThumbprint { get; set; }
            public int ProxyPort { get; set; }
            public string[] FirewallRules { get; set; } = Array.Empty<string>();
        }

        // ── journal ───────────────────────────────────────────────────────

        private static void WriteJournal(Journal journal)
        {
            Directory.CreateDirectory(InterceptCaService.Dir);
            File.WriteAllText(JournalPath, System.Text.Json.JsonSerializer.Serialize(journal,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        }

        private static Journal ReadJournal()
        {
            try
            {
                if (File.Exists(JournalPath))
                    return System.Text.Json.JsonSerializer.Deserialize<Journal>(File.ReadAllText(JournalPath));
            }
            catch { /* unreadable journal — best-effort recovery below still runs */ }
            return null;
        }

        // ── WinHTTP (services) ────────────────────────────────────────────

        private static string RunNetsh(string arguments)
        {
            var psi = new ProcessStartInfo("netsh", arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var process = Process.Start(psi);
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(10000);
            return output;
        }

        /// <summary>The proxy line netsh reports ("127.0.0.1:8888" or the
        /// string "direct"), plus whether it is ours to restore.</summary>
        private static (string Proxy, bool IsDirect) CurrentWinHttpProxy()
        {
            string show = RunNetsh("winhttp show proxy");
            foreach (var line in show.Split('\n'))
            {
                string trimmed = line.Trim();
                if (trimmed.StartsWith("Proxy Server(s)", StringComparison.OrdinalIgnoreCase))
                {
                    string value = trimmed.Substring(trimmed.IndexOf(':') + 1).Trim();
                    if (value.Length == 0 || value.Equals("direct", StringComparison.OrdinalIgnoreCase) ||
                        value.Contains("directly accessing", StringComparison.OrdinalIgnoreCase))
                        return (null, true);
                    return (value, false);
                }
            }
            return (null, true);
        }

        internal static string InstallWinHttpProxy(int port)
        {
            var (before, wasDirect) = CurrentWinHttpProxy();
            RunNetsh($"winhttp set proxy 127.0.0.1:{port} \"<local>\"");
            return wasDirect ? null : before;
        }

        internal static void RestoreWinHttpProxy(string before)
        {
            if (before == null)
                RunNetsh("winhttp reset proxy");
            else
                RunNetsh($"winhttp set proxy \"{before}\" \"<local>\"");
        }

        // ── WinINET (user apps) ───────────────────────────────────────────

        private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        [DllImport("wininet.dll", SetLastError = true)]
        private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
        private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
        private const int INTERNET_OPTION_REFRESH = 37;

        internal static (int? EnableBefore, string ServerBefore) InstallWininetProxy(int port)
        {
            int? enableBefore = null;
            string serverBefore = null;
            using (var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true))
            {
                if (key != null)
                {
                    if (key.GetValue("ProxyEnable") is int enable) enableBefore = enable;
                    serverBefore = key.GetValue("ProxyServer") as string;
                    key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                    key.SetValue("ProxyServer", $"127.0.0.1:{port}", RegistryValueKind.String);
                }
            }
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
            return (enableBefore, serverBefore);
        }

        internal static void RestoreWininetProxy(int? enableBefore, string serverBefore)
        {
            using (var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true))
            {
                if (key != null)
                {
                    if (enableBefore.HasValue)
                        key.SetValue("ProxyEnable", enableBefore.Value, RegistryValueKind.DWord);
                    else
                        key.DeleteValue("ProxyEnable", throwOnMissingValue: false);

                    if (serverBefore != null)
                        key.SetValue("ProxyServer", serverBefore, RegistryValueKind.String);
                    else
                        key.DeleteValue("ProxyServer", throwOnMissingValue: false);
                }
            }
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }

        // ── QUIC block rule ───────────────────────────────────────────────

        internal static string AddQuicBlock(string image, int pid)
        {
            string rule = $"{FirewallRulePrefix} ({pid})";
            RunNetsh($"advfirewall firewall add rule name=\"{rule}\" dir=out action=block " +
                     $"program=\"{image}\" protocol=UDP remoteport=443");
            return rule;
        }

        internal static void RemoveRule(string ruleName) =>
            RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}\"");

        // ── session open/close + crash recovery ───────────────────────────

        /// <summary>Installs all three hooks, journaling the undo data
        /// first. Returns the journal the caller keeps for StopSession.</summary>
        internal static Journal InstallAll(int port, int pid, string image, string caThumbprint)
        {
            var (wininetEnable, wininetServer) = InstallWininetProxy(port);
            string winHttpBefore = InstallWinHttpProxy(port);
            string rule = AddQuicBlock(image, pid);

            var journal = new Journal
            {
                ProxyPort = port,
                CaThumbprint = caThumbprint,
                WinHttpProxyBefore = winHttpBefore,
                WininetEnableBefore = wininetEnable,
                WininetServerBefore = wininetServer,
                FirewallRules = new[] { rule },
            };
            WriteJournal(journal);
            return journal;
        }

        internal static void UndoAll(Journal journal)
        {
            if (journal == null) return;
            foreach (var rule in journal.FirewallRules ?? Array.Empty<string>())
                RemoveRule(rule);
            RestoreWinHttpProxy(journal.WinHttpProxyBefore);
            RestoreWininetProxy(journal.WininetEnableBefore, journal.WininetServerBefore);
            if (!string.IsNullOrEmpty(journal.CaThumbprint))
                InterceptCaService.RemoveFromRoot(journal.CaThumbprint);
            try { File.Delete(JournalPath); } catch { }
        }

        /// <summary>
        /// App-start safety net: a crash mid-session leaves the journal on
        /// disk — undo everything it describes. No journal, no action.
        /// </summary>
        public static void RecoverAfterCrash()
        {
            var journal = ReadJournal();
            if (journal != null)
                UndoAll(journal);
        }
    }
}
