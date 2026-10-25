using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AutoScope.Services
{
    /// <summary>
    /// One-time adoption of an existing AutoCommand install, so switching to
    /// AutoScope loses nothing:
    ///   • blocks.txt records (identity, attribution, history) merge into the
    ///     AutoScope store — the AC-BLOCK firewall rules themselves are
    ///     recognized in place by FirewallService (ImportedIpPrefix /
    ///     ImportedAppPrefix), never renamed, so AutoCommand keeps seeing
    ///     its own rules too;
    ///   • the ignored-processes list merges into AutoScope's.
    /// Runs once per install (marker file); deletes the marker to re-run.
    /// Every step is best-effort — migration must never block startup.
    /// </summary>
    public static class MigrationService
    {
        private static string DataDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AutoScope");

        private static string MarkerPath => Path.Combine(DataDir, "migration-autocommand.done");

        public static void RunIfNeeded()
        {
            try
            {
                if (File.Exists(MarkerPath)) return;
                var (blocks, ignored) = Import();

                Directory.CreateDirectory(DataDir);
                File.WriteAllText(MarkerPath,
                    $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC — imported {blocks} block record(s), " +
                    $"{ignored} ignored process(es) from AutoCommand. Delete this file to re-run.");

                if (blocks > 0)
                    BlocksStore.AppendEvent("migrated", "-", "-",
                        $"{blocks} block record(s) imported from AutoCommand — AC-BLOCK rules adopted in place",
                        "migration");
            }
            catch { /* never block startup on migration */ }
        }

        private static (int blocks, int ignored) Import()
        {
            string acDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AutoCommand");
            int blocks = 0;

            // ── blocks.txt: parse through BlocksStore's own reader by
            // pointing it at the AutoCommand data dir for one Load() ──
            string acStore = Path.Combine(acDir, "blocks.txt");
            if (File.Exists(acStore))
            {
                var restore = BlocksStore.DataDirectory;
                List<BlockRecord> imported;
                try
                {
                    BlocksStore.DataDirectory = acDir;
                    BlocksStore.Load();
                    imported = BlocksStore.Records.ToList();
                }
                finally { BlocksStore.DataDirectory = restore; }

                BlocksStore.Load(); // our own store (no-op if already loaded)
                var mine = BlocksStore.Records;
                foreach (var r in imported)
                {
                    if (mine.Any(b => b.Kind == r.Kind &&
                                      string.Equals(b.Key, r.Key, StringComparison.OrdinalIgnoreCase))) continue;
                    BlocksStore.AddOrUpdate(r, "migrated-from-autocommand");
                    blocks++;
                }
            }

            // ── ignored processes: CWD-relative file next to whichever exe ──
            int ignored = 0;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string candidate in AutoCommandIgnoreListCandidates(acDir))
            {
                try
                {
                    if (!File.Exists(candidate)) continue;
                    // SysmonWatcherService owns the ignore-list file format;
                    // an instance over the shared tracked-ips map of the view
                    // is not needed — normalization + persistence are static
                    // behavior of the service over its own file.
                    var watcher = new SysmonWatcherService(
                        new System.Collections.Concurrent.ConcurrentDictionary<string, Models.SvchostMonitorItem>(),
                        new DnsResolutionService());
                    foreach (string line in File.ReadAllLines(candidate))
                    {
                        string name = line.Trim();
                        if (name.Length == 0 || !seen.Add(name)) continue;
                        if (!watcher.IsProcessIgnored(name))
                        {
                            watcher.AddIgnoredProcess(name);
                            ignored++;
                        }
                    }
                }
                catch { /* best effort per candidate */ }
            }

            return (blocks, ignored);
        }

        /// <summary>Where AutoCommand's ignored_processes.txt might live, in
        /// order of confidence: its data dir, next to the exe its startup
        /// task launches, and (dev machines) the sibling source checkout.</summary>
        private static IEnumerable<string> AutoCommandIgnoreListCandidates(string acDataDir)
        {
            var list = new List<string>();

            // explicit override first — set AUTOCOMMAND_IGNORE_LIST to point
            // at the file directly when the probes below miss
            try
            {
                string env = Environment.GetEnvironmentVariable("AUTOCOMMAND_IGNORE_LIST");
                if (!string.IsNullOrEmpty(env)) list.Add(env);
            }
            catch { }

            list.Add(Path.Combine(acDataDir, "ignored_processes.txt"));

            // AutoCommand's startup scheduled task points at its exe — the
            // CWD-relative ignore file sits next to it.
            try
            {
                Type tsType = Type.GetTypeFromProgID("Schedule.Service");
                if (tsType != null)
                {
                    dynamic ts = Activator.CreateInstance(tsType);
                    ts.Connect();
                    dynamic task = ts.GetFolder("\\").GetTask("AutoCommandStartupTask");
                    foreach (dynamic action in task.Definition.Actions)
                    {
                        try
                        {
                            string exe = (string)action.Path;
                            if (!string.IsNullOrEmpty(exe) && File.Exists(exe))
                                list.Add(Path.Combine(Path.GetDirectoryName(exe), "ignored_processes.txt"));
                        }
                        catch { }
                    }
                }
            }
            catch { /* task absent or unreadable */ }

            // dev-layout fallback: an AutoCommand checkout sitting near this
            // app's output (bin depth varies between harnesses and layouts;
            // every probe is a no-op where the file doesn't exist)
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string dir = baseDir;
                for (int i = 0; i < 7 && dir != null; i++)
                {
                    try { dir = Path.GetFullPath(Path.Combine(dir, "..")); } catch { break; }
                    list.Add(Path.Combine(dir, "autocommand1004", "ignored_processes.txt"));
                }
            }
            catch { }

            return list;
        }
    }
}
