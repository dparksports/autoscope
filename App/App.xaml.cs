using Microsoft.UI.Xaml;
using AutoScope.Services;

namespace AutoScope
{
    /// <summary>
    /// Startup ported from AutoCommand's WPF App.xaml.cs, trimmed to the six
    /// ported tabs: theme is fixed dark, there is no OneSettings watchdog and
    /// no legacy-analytics cleanup here. Kept: crash logging, Sysmon
    /// preparation (channel sizing, archive, live watch, block-hit feed),
    /// the telemetry sinkhole listener, and the (inert-by-default) usage
    /// ping flow.
    /// </summary>
    public partial class App : Application
    {
        public static MainWindow MainWin { get; private set; }

        public App()
        {
            InitializeComponent();

            // WinUI's unhandled-exception hook (the WinUI analog of WPF's
            // DispatcherUnhandledException); keep the app alive like the
            // original did, and log to crash.log next to the exe.
            UnhandledException += (s, args) =>
            {
                LogCrash(args.Exception, "Xaml");
                args.Handled = true;
            };
            System.AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                if (args.ExceptionObject is System.Exception ex) LogCrash(ex, "AppDomain");
            };
            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, args) =>
            {
                LogCrash(args.Exception, "TaskScheduler");
                args.SetObserved();
            };
        }

        protected override void OnLaunched(LaunchActivatedEventArgs args)
        {
            // First run: adopt an existing AutoCommand install — block records
            // and the ignored-process list merge in, and AC-BLOCK firewall
            // rules become manageable here (never renamed). Before anything
            // else so no store or watcher reads pre-migration state.
            MigrationService.RunIfNeeded();

            // The bridge's tier-3 consent dialog (mutating AI actions) needs
            // a UI to ask with — install it before anything can start a session.
            AgentBridgeService.Ui = new AgentBridgeUI();

            PrepareSysmonAtStartup();

            // Telemetry sinkhole: when hosts pins point at 127.0.0.1 (set from
            // AutoCommand's Black Hole tab), start the logging listener so
            // proof accumulates even if no proof view is opened. No pins →
            // no-op.
            // Keep the blocked list in step with the firewall (rules
            // AutoCommand added since the migration snapshot get adopted);
            // pages read the store fresh when opened.
            _ = System.Threading.Tasks.Task.Run(async () =>
            {
                try { await Services.BlocksStore.ReconcileWithFirewallAsync(); } catch { }
            });

            SinkholeService.Instance.EnsureRunningForCurrentPins();
            _ = TelemetryProofService.Instance.TotalDenied;

            // Anonymous usage ping (opt-in, off by default). No consent prompt
            // is installed in this build, so the ask path is inert; consented
            // installs still ping once a day.
            _ = UsagePingService.RunStartupFlowAsync();

            MainWin = new MainWindow();
            MainWin.Activate();
        }

        // Off the UI thread: DetectInstallState probes sc.exe/wevtutil, the
        // backfill can scan the whole retained channel, and none of it must
        // stall startup. Every step degrades silently when unelevated.
        private async void PrepareSysmonAtStartup()
        {
            try
            {
                await System.Threading.Tasks.Task.Run(() =>
                {
                    // one-shot ever: make pfirewall.log a usable second hit source
                    Services.FirewallService.EnsureDropLoggingOnce();

                    var installer = new SysmonInstallerService();
                    if (installer.DetectInstallState() != SysmonInstallState.Installed)
                        return; // nothing installed — the install path sizes and archives it
                    SysmonInstallerService.EnsureChannelSize();
                    SysmonArchiveService.Prune();
                    SysmonArchiveService.Backfill();
                    SysmonArchiveService.StartLiveWatch();
                    // real-time 'who is being blocked' feed: joins Sysmon connects
                    // against the blocked inventory; without it, blocks fire
                    // silently at the kernel and no tab ever sees them
                    BlockHitFeedService.Instance.Start();
                });
            }
            catch (System.Exception ex)
            {
                LogCrash(ex, "SysmonStartup");
            }
        }

        private static void LogCrash(System.Exception ex, string source)
        {
            try
            {
                string logPath = System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, "crash.log");
                string logEntry = $"\n[{System.DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{source}]\n{ex}\n";
                System.IO.File.AppendAllText(logPath, logEntry);
            }
            catch { /* Failsafe */ }
        }
    }
}
