using System;
using System.IO;
using AutoCommand.Engines.Core;
using AutoCommand.Engines.Firewall;

using Engines = AutoCommand.Engines;
namespace AutoScope.Services
{
    /// <summary>
    /// App-side composition root for the F# firewall engine: constructs the
    /// engines once with AutoScope's naming policy and exposes them app-wide
    /// (Fw.Service / Fw.Profiles / Fw.Baseline / Fw.Config). The engines are
    /// app-agnostic — this file is the ONLY place AutoScope's
    /// AS-BLOCK/adopted-AC-BLOCK policy is expressed. Baseline and config
    /// keep their historical ProgramData home so the existing baseline
    /// survives the engine swap unchanged.
    /// </summary>
    public static class Fw
    {
        private static readonly string SharedRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "AutoScope");

        public static readonly Engines.Firewall.FirewallService Service =
            new Engines.Firewall.FirewallService(Naming.autoscope());

        public static readonly ProfilePresets Profiles = new ProfilePresets(Service);

        public static readonly BaselineManager Baseline = new BaselineManager(SharedRoot);

        public static readonly ConfigManager Config = new ConfigManager(SharedRoot);
    }
}
