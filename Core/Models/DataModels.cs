using Engines = AutoCommand.Engines;

namespace AutoScope.Models
{
    public class ScheduledTaskItem
    {
        public string TaskName { get; set; }
        public string TaskPath { get; set; }
        public string State { get; set; }
        public string Action { get; set; }
        public string User { get; set; }
    }

    // FirewallRuleItem moved to Engines.Firewall (F# RuleInfo)

    public class StartupItem
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public string Location { get; set; }
        public string TargetPath { get; set; }
    }

    public class AppPackageItem
    {
        public string Name { get; set; }

        /// <summary>Exact Appx package name (e.g. Microsoft.Todos) — identity used
        /// for user-added custom bloatware entries, unlike the display Name.</summary>
        public string PackageName { get; set; }
        public string FullName { get; set; }
        public string Version { get; set; }
        public string Publisher { get; set; }
        public string InstallLocation { get; set; }
        public string SignatureStatus { get; set; }
        public string SignerCertificate { get; set; }
        public bool IsSystem { get; set; }
    }
}

