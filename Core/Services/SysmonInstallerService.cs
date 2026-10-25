using System;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using AutoScope.Helpers;

namespace AutoScope.Services
{
    public enum SysmonInstallState
    {
        Installed,
        NotInstalled,
        Inconsistent
    }

    public class SysmonInstallerService
    {
        private const string SysmonDownloadUrl = "https://live.sysinternals.com/Sysmon64.exe";
        private const string SysmonExeName = "Sysmon64.exe";
        private const string ConfigFileName = "sysmon_config.xml";
        private const string EventChannelName = "Microsoft-Windows-Sysmon/Operational";
        private const string ProviderName = "Microsoft-Windows-Sysmon";

        // Sysmon's ETW provider GUID, used for its event-manifest registration
        private const string SysmonProviderGuid = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}";

        // The Operational channel defaults to 64 MB. On a busy dev box the
        // app has measured ~15,000 events/hour — the default wraps in ~4
        // hours, silently breaking "every spawn retroactively traceable"
        // for anything older than a lunch break (an overnight incident is
        // already gone by morning triage). 3× = 192 MB buys roughly half a
        // day of history at that rate; growing a live channel keeps every
        // event already in it.
        public const long ChannelMaxSizeBytes = 192 * 1024 * 1024;

        private static readonly string TempDir = Path.Combine(Path.GetTempPath(), "AutoScope_Sysmon");
        private static readonly string PendingRepairMarker = Path.Combine(TempDir, "repair_pending.flag");

        public bool IsSysmonInstalled()
        {
            // Sysmon registers a "Sysmon64" service on install; the exe on disk
            // alone is not proof (a failed install leaves it behind)
            var (_, _, exitCode) = ProcessRunner.RunWithDetails("sc.exe", "query Sysmon64");
            return exitCode == 0;
        }

        /// <summary>
        /// Distinguishes a clean "never installed" machine from one stuck with
        /// leftovers of a failed install, which makes every "-i" attempt abort
        /// with "wevtutil.exe returned failure / Event manifest installation failed".
        /// </summary>
        public SysmonInstallState DetectInstallState()
        {
            if (IsSysmonInstalled())
            {
                // Service present but its event channel unreadable = broken manifest
                return IsEventChannelHealthy() ? SysmonInstallState.Installed : SysmonInstallState.Inconsistent;
            }

            string installedExe = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), SysmonExeName);
            if (File.Exists(installedExe)) return SysmonInstallState.Inconsistent;
            if (IsProviderRegistered()) return SysmonInstallState.Inconsistent;

            return SysmonInstallState.NotInstalled;
        }

        /// <summary>
        /// Repairs an inconsistent install: removes leftovers, reinstalls and
        /// verifies. When the stale event-manifest registration can only be
        /// cleared by restarting Windows, RebootRequired is true and a pending
        /// marker is written so the next startup finishes and verifies the repair.
        /// </summary>
        public async Task<(bool Success, string ErrorMessage, bool RebootRequired)> RepairAsync()
        {
            try
            {
                string exePath = await EnsureSysmonDownloadedAsync();
                string configPath = await WriteConfigAsync();

                CleanupStaleInstall(exePath);

                var (output, error, exitCode) = await ProcessRunner.RunWithDetailsAsync(exePath, $"-i \"{configPath}\" -accepteula");
                if (exitCode == 0)
                {
                    DeletePendingRepairMarker();
                    EnsureChannelSize();
                    return (true, string.Empty, false);
                }

                string details = $"Exit code: {exitCode}. Output: {output}. Error: {error}";
                if ($"{output} {error}".IndexOf("Event manifest installation failed", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    // The stale manifest registration is held by the event log
                    // service and only a restart flushes it; the install is then
                    // retried and verified automatically on startup
                    WritePendingRepairMarker(details);
                    return (false, details, true);
                }

                return (false, details, false);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SysmonInstallerService Error: {ex.Message}");
                return (false, ex.Message, false);
            }
        }

        /// <summary>
        /// Called on app startup after a repair restart: reinstalls Sysmon and
        /// verifies the service and its event channel. Message is null when no
        /// repair was pending.
        /// </summary>
        public async Task<(bool Verified, string Message)> CompletePendingRepairIfAnyAsync()
        {
            if (!File.Exists(PendingRepairMarker)) return (false, null);
            DeletePendingRepairMarker();

            try
            {
                string exePath = await EnsureSysmonDownloadedAsync();
                string configPath = await WriteConfigAsync();

                var (output, error, exitCode) = await ProcessRunner.RunWithDetailsAsync(exePath, $"-i \"{configPath}\" -accepteula");
                if (exitCode != 0)
                    return (false, $"Exit code: {exitCode}. Output: {output}. Error: {error}");

                if (!IsSysmonInstalled())
                    return (false, "Sysmon setup reported success but the Sysmon64 service is not present.");

                if (!IsEventChannelHealthy())
                    return (false, "The Sysmon64 service is installed but its event channel did not register correctly.");

                EnsureChannelSize();
                return (true, $"Sysmon64 service installed and event channel '{EventChannelName}' is healthy.");
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
        }

        public async Task<(bool Success, string ErrorMessage)> InstallAndConfigureAsync()
        {
            try
            {
                string exePath = await EnsureSysmonDownloadedAsync();
                string configPath = await WriteConfigAsync();

                // Clear any leftovers of previous failed installs
                CleanupStaleInstall(exePath);

                // -i: Install, -accepteula: self-explanatory, -c: use config
                var (output, error, exitCode) = await ProcessRunner.RunWithDetailsAsync(exePath, $"-i \"{configPath}\" -accepteula");

                if (exitCode == 0)
                {
                    EnsureChannelSize();
                    return (true, string.Empty);
                }
                else
                    return (false, $"Exit code: {exitCode}. Output: {output}. Error: {error}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SysmonInstallerService Error: {ex.Message}");
                return (false, ex.Message);
            }
        }

        private static async Task<string> EnsureSysmonDownloadedAsync()
        {
            if (!Directory.Exists(TempDir)) Directory.CreateDirectory(TempDir);

            string exePath = Path.Combine(TempDir, SysmonExeName);
            if (!File.Exists(exePath))
            {
                using (var client = new HttpClient())
                {
                    var data = await client.GetByteArrayAsync(SysmonDownloadUrl);
                    await File.WriteAllBytesAsync(exePath, data);
                }
            }
            return exePath;
        }

        private static async Task<string> WriteConfigAsync()
        {
            // Recommended config for post-hoc process/network forensics:
            //   ProcessCreate   (ID 1)  every launch with full command line + parent image
            //   NetworkConnect  (ID 3)  every outbound connection with image + PID
            //   DnsQuery       (ID 22)  hostname lookups, ties IPs to names after the fact
            // An empty onmatch="exclude" rule is the Sysmon idiom for "capture
            // everything"; noise filtering happens app-side (ignore lists,
            // cloud-IP filter) so the raw log stays complete.
            string configXml = @"
<Sysmon schemaversion=""4.82"">
  <EventFiltering>
    <RuleGroup name="""" groupRelation=""or"">
      <ProcessCreate onmatch=""exclude""/>
      <NetworkConnect onmatch=""exclude""/>
      <DnsQuery onmatch=""exclude""/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>";
            string configPath = Path.Combine(TempDir, ConfigFileName);
            await File.WriteAllTextAsync(configPath, configXml);
            return configPath;
        }

        /// <summary>
        /// Applies the recommended config to an already-installed Sysmon
        /// without reinstalling (Sysmon64 -c). Needed when an install made
        /// with an older config (e.g. network-only) should start capturing
        /// process creations and DNS queries too. Call only when Sysmon is
        /// actually installed — otherwise the call just fails.
        /// </summary>
        public async Task<(bool Success, string ErrorMessage)> UpdateConfigAsync()
        {
            try
            {
                // Prefer the installed exe; fall back to the downloaded copy
                string installedExe = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), SysmonExeName);
                string exePath = File.Exists(installedExe)
                    ? installedExe
                    : await EnsureSysmonDownloadedAsync();

                string configPath = await WriteConfigAsync();
                var (output, error, exitCode) = await ProcessRunner.RunWithDetailsAsync(exePath, $"-c \"{configPath}\" -accepteula");

                if (exitCode == 0)
                    return (true, string.Empty);
                return (false, $"Exit code: {exitCode}. Output: {output}. Error: {error}");
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
        }

        private static bool IsProviderRegistered()
        {
            var (output, _, _) = ProcessRunner.RunWithDetails("wevtutil.exe", "ep");
            return output.Split('\n').Any(line => line.Trim() == ProviderName);
        }

        private static bool IsEventChannelHealthy()
        {
            var (_, _, exitCode) = ProcessRunner.RunWithDetails("wevtutil.exe", $"gl \"{EventChannelName}\"");
            return exitCode == 0;
        }

        /// <summary>
        /// Raises the Sysmon Operational channel's max size to
        /// ChannelMaxSizeBytes (3× the 64 MB default) so the forensic
        /// history survives more than a few hours on an active machine.
        /// Best-effort: SaveChanges needs elevation; false just means the
        /// default (shorter) retention stands — it never fails an install.
        /// Called after every successful install/repair/verify and from the
        /// startup diagnostics pass for machines where Sysmon predates this.
        /// </summary>
        public static bool EnsureChannelSize()
        {
            try
            {
                var config = new EventLogConfiguration(EventChannelName);
                if (config.MaximumSizeInBytes >= ChannelMaxSizeBytes) return true;
                config.MaximumSizeInBytes = ChannelMaxSizeBytes;
                config.SaveChanges();
                return true;
            }
            catch
            {
                // Channel missing, or session not elevated — degrade, never guess
                return false;
            }
        }

        /// <summary>
        /// Removes leftovers of a previous failed/partial install. A half-installed
        /// Sysmon leaves its event-manifest provider registered; until that is gone,
        /// the next "-i" aborts with "wevtutil.exe returned failure /
        /// Event manifest installation failed".
        /// </summary>
        private static void CleanupStaleInstall(string exePath)
        {
            // Stops and removes the Sysmon64 service/driver and uninstalls the
            // event manifest; a no-op when Sysmon is not installed
            ProcessRunner.RunWithDetails(exePath, "-u force");

            // Orphaned provider registration (registry view) left behind when
            // a manifest install failed midway
            ProcessRunner.RunWithDetails("reg.exe",
                $"delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Winevt\\Publishers\\{SysmonProviderGuid}\" /f");

            try
            {
                string installedExe = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), SysmonExeName);
                if (File.Exists(installedExe)) File.Delete(installedExe);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private static void WritePendingRepairMarker(string details)
        {
            try
            {
                if (!Directory.Exists(TempDir)) Directory.CreateDirectory(TempDir);
                File.WriteAllText(PendingRepairMarker,
                    $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}{Environment.NewLine}{details}");
            }
            catch { /* marker is best-effort */ }
        }

        private static void DeletePendingRepairMarker()
        {
            try
            {
                if (File.Exists(PendingRepairMarker)) File.Delete(PendingRepairMarker);
            }
            catch { }
        }
    }
}
