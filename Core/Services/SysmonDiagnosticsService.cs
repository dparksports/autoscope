using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AutoScope.Helpers;

namespace AutoScope.Services
{
    /// <summary>All read-only status facts about the Sysmon install, for the status card.</summary>
    public class SysmonStatusInfo
    {
        public SysmonInstallState State;
        public string StateText => State switch
        {
            SysmonInstallState.Installed => "Installed",
            SysmonInstallState.NotInstalled => "Not installed",
            _ => "Inconsistent — needs repair"
        };
        public string Version;
        public bool ServiceRunning;
        public bool ChannelHealthy;
        public long EventsLast24h;
        public DateTime? NewestEventTime;
        public string ConfigHash;      // short hex form from SysmonDrv\Parameters
        public string ExePath;
    }

    /// <summary>
    /// Gathers Sysmon install facts for the Sysmon Audit tab: what is
    /// installed, whether the service and its event channel are alive, how
    /// much it has recorded lately, and which config hash is active. All
    /// probes are read-only; installs/repairs stay in SysmonInstallerService.
    /// </summary>
    public class SysmonDiagnosticsService
    {
        private const string ChannelName = "Microsoft-Windows-Sysmon/Operational";
        private const string SysmonConfigHashKey = @"SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters";

        private readonly SysmonInstallerService _installer = new();

        public async Task<SysmonStatusInfo> GetStatusAsync()
        {
            var info = new SysmonStatusInfo
            {
                State = _installer.DetectInstallState(),
                ExePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Sysmon64.exe")
            };

            if (File.Exists(info.ExePath))
            {
                try { info.Version = FileVersionInfo.GetVersionInfo(info.ExePath).FileVersion; }
                catch { }
            }

            if (info.State == SysmonInstallState.NotInstalled)
                return info;

            // sc.exe output is localized, but "RUNNING" is not translated
            var (scOut, _, _) = ProcessRunner.RunWithDetails("sc.exe", "query Sysmon64");
            info.ServiceRunning = scOut != null && scOut.Contains("RUNNING", StringComparison.Ordinal);

            // One PowerShell round-trip for both channel stats: newest event
            // timestamp and the 24h event count. Failure leaves zeros — the
            // status card treats "no data" separately from "not installed".
            var ps = "$e = Get-WinEvent -LogName '" + ChannelName + "' -MaxEvents 1 -ErrorAction SilentlyContinue; " +
                     "if ($e) { $e.TimeCreated.ToString('o') } else { 'NONE' }; " +
                     "(Get-WinEvent -FilterHashtable @{LogName='" + ChannelName + "'; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue | Measure-Object).Count";
            var (out1, _, _) = await ProcessRunner.RunWithDetailsAsync("powershell.exe",
                "-NoProfile -NonInteractive -Command \"" + ps + "\"");
            try
            {
                var lines = (out1 ?? string.Empty)
                    .Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
                if (lines.Count > 0 && lines[0] != "NONE")
                    info.NewestEventTime = DateTime.Parse(lines[0]);
                if (lines.Count > 1 && long.TryParse(lines[1], out long count))
                    info.EventsLast24h = count;
            }
            catch { }

            // Channel readability doubles as "healthy": if the manifest is
            // broken the read above fails wholesale, so an empty stat block
            // with a RUNNING service means the channel is the problem.
            info.ChannelHealthy = info.NewestEventTime != null || info.EventsLast24h > 0;

            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(SysmonConfigHashKey);
                if (key?.GetValue("ConfigHash") is byte[] hash && hash.Length > 0)
                    info.ConfigHash = string.Concat(hash.Take(8).Select(b => b.ToString("x2")));
            }
            catch { }

            return info;
        }
    }
}
