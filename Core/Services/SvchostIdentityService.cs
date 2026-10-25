using System.Collections.Generic;
using System.Management;
using SvchostAnalyzer.Core;

namespace AutoScope.Services
{
    /// <summary>Resolved svchost identity for one PID: SCM services + -k/-s tokens.</summary>
    public sealed class SvchostPidIdentity
    {
        /// <summary>SCM-resident service names, csv ("WpnService") — the ground truth.</summary>
        public string ServicesCsv;

        /// <summary>Names + display names + state, one per line, for tooltips.</summary>
        public string ServicesDetail;

        /// <summary>-k group ("netsvcs") — null when the command line is unreadable.</summary>
        public string Group;

        /// <summary>-s self-declared service — null for grouped hosts and hidden lines.</summary>
        public string DeclaredService;

        /// <summary>False when WMI could not read the command line (SYSTEM process, non-elevated).</summary>
        public bool CommandLineVisible;

        /// <summary>-s claim contradicts the SCM-resident services — masquerade signal.</summary>
        public bool Mismatch;

        /// <summary>Readable command line without -k — the SCM always passes -k.</summary>
        public bool NoK;
    }

    /// <summary>
    /// One-shot svchost identity resolution per PID: the SCM's Win32_Service
    /// map (ground truth, readable non-elevated) plus the Win32_Process
    /// command line (often hidden for SYSTEM instances — surfaced as such,
    /// never guessed). Parsed with the shared SvchostAnalyzer.Core tokens so
    /// the CLI, the analyzer and this app agree on what -k/-s mean.
    /// </summary>
    public static class SvchostIdentityService
    {
        public static SvchostPidIdentity Resolve(int pid)
        {
            var id = new SvchostPidIdentity();

            var names = new List<string>();
            var details = new List<string>();
            try
            {
                using var s = new ManagementObjectSearcher(
                    $"SELECT Name, DisplayName, State FROM Win32_Service WHERE ProcessId = {pid}");
                foreach (ManagementObject o in s.Get())
                {
                    string name = o["Name"]?.ToString();
                    if (string.IsNullOrEmpty(name)) continue;
                    names.Add(name);
                    details.Add($"{name} — {o["DisplayName"]} ({o["State"]})");
                }
            }
            catch { /* best-effort: SCM map unreadable → no corroboration, no false claim */ }
            id.ServicesCsv = string.Join(",", names);
            id.ServicesDetail = string.Join("\n", details);

            string cmd = null;
            try
            {
                using var s = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject o in s.Get())
                {
                    cmd = o["CommandLine"]?.ToString();
                    break;
                }
            }
            catch { /* best-effort: hidden line is the normal non-elevated case */ }
            id.CommandLineVisible = !string.IsNullOrEmpty(cmd);

            var parsed = SvchostIdentity.Parse(cmd);
            id.Group = parsed.Group;
            id.DeclaredService = parsed.DeclaredService;
            id.Mismatch = SvchostIdentity.Mismatches(id.DeclaredService, id.ServicesCsv);
            id.NoK = id.CommandLineVisible && parsed.Group == null;
            return id;
        }
    }
}
