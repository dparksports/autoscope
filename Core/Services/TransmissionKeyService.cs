using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace AutoScope.Services
{
    /// <summary>
    /// Key acquisition for the Transmissions tab: getting apps that honor
    /// the de-facto SSLKEYLOGFILE convention to write their TLS session
    /// secrets where TlsKeylogService already tails them (pytrace\
    /// sslkeys.log, current-user-only ACL, rotated at 5 MB).
    ///
    /// Two mechanisms, both strictly local:
    ///   - System-wide capture: writes SSLKEYLOGFILE into the user's
    ///     environment (HKCU\Environment) and broadcasts the change so
    ///     freshly launched apps inherit it. Chromium/Electron, curl, wget,
    ///     git, OpenSSL- and Python-based tools pick it up. Schannel-based
    ///     system components ignore the variable — those flows stay
    ///     "encrypted (no keys)" in the tab, which is the honest coverage
    ///     answer, not a gap to paper over.
    ///   - Launch under watch: starts one chosen program with the variable
    ///     set in its environment only — the precise instrument when the
    ///     user wants one app observed without changing anything global.
    /// </summary>
    public static class TransmissionKeyService
    {
        private const string EnvVarName = "SSLKEYLOGFILE";
        private const string EnvKey = "Environment";

        public static string KeylogTarget => TlsKeylogService.KeylogPath;

        // ── system-wide toggle ────────────────────────────────────────────

        /// <summary>True when the user environment currently points
        /// SSLKEYLOGFILE at AutoScope's keylog.</summary>
        public static bool IsSystemKeylogEnabled()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(EnvKey, writable: false);
                var value = key?.GetValue(EnvVarName) as string;
                return string.Equals(value, KeylogTarget, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>Sets SSLKEYLOGFILE in the user environment and notifies
        /// running processes that the environment changed (newly launched
        /// apps inherit it; nothing running is touched).</summary>
        public static void EnableSystemKeylog()
        {
            TlsKeylogService.EnsureHygiene(); // the target must exist with its ACL before children append
            using var key = Registry.CurrentUser.CreateSubKey(EnvKey);
            key.SetValue(EnvVarName, KeylogTarget);
            BroadcastEnvironmentChange();
        }

        /// <summary>Removes SSLKEYLOGFILE from the user environment. The
        /// key file itself is wiped too: without the variable no new app
        /// writes keys, and stale secrets should not linger either.</summary>
        public static void DisableSystemKeylog()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(EnvKey, writable: true))
            {
                key?.DeleteValue(EnvVarName, throwOnMissingValue: false);
            }
            BroadcastEnvironmentChange();
            try { TlsKeylogService.DisableKeylogging(); } catch { /* flag wipe is best-effort */ }
            TlsKeylogService.EnableKeylogging(); // recreate the empty ACL'd file + clear the hook's no-keylog flag
        }

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr SendMessageTimeout(
            IntPtr hWnd, uint msg, UIntPtr wParam, string lParam,
            uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);

        private const uint WM_SETTINGCHANGE = 0x001A;
        private const uint SMTO_ABORTIFHUNG = 0x0002;
        private static readonly IntPtr HWND_BROADCAST = (IntPtr)0xFFFF;

        /// <summary>
        /// Explorer (and other long-running parents) build a child's
        /// environment from their own copy of the registry values; without
        /// this broadcast a toggle appears to "not work" until logoff.
        /// </summary>
        private static void BroadcastEnvironmentChange()
        {
            try
            {
                SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, UIntPtr.Zero,
                    "Environment", SMTO_ABORTIFHUNG, 1000, out _);
            }
            catch { /* best-effort notification */ }
        }

        // ── launch under watch ────────────────────────────────────────────

        /// <summary>
        /// Starts a program with SSLKEYLOGFILE pointing at AutoScope's
        /// keylog (its own environment only). AutoScope runs elevated, so
        /// the child inherits admin — flag that in the UI when it matters.
        /// </summary>
        public static Process LaunchUnderWatch(string exePath, string arguments, string workingDirectory)
        {
            if (string.IsNullOrWhiteSpace(exePath))
                throw new ArgumentException("No program selected.");

            TlsKeylogService.EnsureHygiene();
            TlsKeylogService.EnableKeylogging(); // clears any stale no-keylog flag

            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = arguments ?? "",
                WorkingDirectory = string.IsNullOrEmpty(workingDirectory)
                    ? System.IO.Path.GetDirectoryName(exePath)
                    : workingDirectory,
                UseShellExecute = false, // required to touch the env block
            };
            psi.EnvironmentVariables[EnvVarName] = KeylogTarget;
            return Process.Start(psi);
        }

        /// <summary>Programs known to honor SSLKEYLOGFILE, for the launch
        /// dialog's hint text and the tab's coverage note.</summary>
        public static string CoverageNote =>
            "Apps that honor SSLKEYLOGFILE (Chromium/Electron browsers and apps, curl, git, " +
            "wget, OpenSSL- and Python-based tools) write TLS session keys when the variable " +
            "is set at launch. Windows system components using Schannel ignore it — their " +
            "flows stay 'encrypted (no keys)' with full metadata. Certificate-pinned apps " +
            "keep working; their keys decrypt their traffic here the same way.";
    }
}
