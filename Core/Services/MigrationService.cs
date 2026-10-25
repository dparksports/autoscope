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
                // v0.1.2 wrongly DELETED System32\ignored_processes.txt as
                // "our stray" — but AutoCommand reads/writes that exact file
                // whenever IT runs elevated (its list is CWD-relative too).
                // Restore its last known content (the entries v0.1.1 left
                // there) once, and never touch the file again.
                try
                {
                    string shared = Path.Combine(Environment.SystemDirectory, "ignored_processes.txt");
                    string restoreMarker = Path.Combine(DataDir, "restored-autocommand-ignore.done");
                    if (!File.Exists(shared) && !File.Exists(restoreMarker))
                    {
                        var ours = new SysmonWatcherService(
                            new System.Collections.Concurrent.ConcurrentDictionary<string, Models.SvchostMonitorItem>(),
                            new DnsResolutionService());
                        if (ours.IgnoredProcesses.Count > 0)
                        {
                            File.WriteAllLines(shared, ours.IgnoredProcesses);
                            Directory.CreateDirectory(DataDir);
                            File.WriteAllText(restoreMarker,
                                $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC — restored AutoCommand's elevated ignore list after v0.1.2 deleted it");
                        }
                    }
                }
                catch { /* best effort */ }

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
            int blocks = ImportBlocks(acDir);
            int ignored = ImportIgnored(acDir);
            return (blocks, ignored);
        }

        /// <summary>
        /// Copies/merges AutoCommand's blocks.txt into ours at the FILE
        /// level, before BlocksStore loads anything. BlocksStore.Load() is a
        /// one-shot lazy parse of the v3 pipe format, so a straight file
        /// merge is both simpler and exactly format-preserving (attribution,
        /// history, unrecognized lines all survive verbatim).
        /// </summary>
        private static int ImportBlocks(string acDir)
        {
            try
            {
                string acStore = Path.Combine(acDir, "blocks.txt");
                if (!File.Exists(acStore)) return 0;

                Directory.CreateDirectory(DataDir);
                string mine = BlocksStore.StorePath;

                // v3 line: v3|kind|key|... — identity is (kind, key), same as
                // BlocksStore.AddOrUpdate's dedupe
                static string LineKey(string l)
                {
                    var parts = l.Split('|');
                    return parts.Length > 2 ? parts[1] + "|" + parts[2] : l;
                }

                if (!File.Exists(mine))
                {
                    File.Copy(acStore, mine);
                    return File.ReadAllLines(mine).Count(l => l.StartsWith("v3|", StringComparison.Ordinal));
                }

                var known = new HashSet<string>(
                    File.ReadAllLines(mine)
                        .Where(l => l.StartsWith("v3|", StringComparison.Ordinal))
                        .Select(LineKey),
                    StringComparer.OrdinalIgnoreCase);
                var add = File.ReadAllLines(acStore)
                    .Where(l => l.StartsWith("v3|", StringComparison.Ordinal))
                    .Where(l => known.Add(LineKey(l)))
                    .ToList();
                if (add.Count > 0) File.AppendAllLines(mine, add);
                return add.Count;
            }
            catch { return 0; /* migration must never block startup */ }
        }

        /// <summary>AutoCommand's ignore list, found next to its exe (its
        /// startup task), in its data dir, via env var, or in a sibling
        /// checkout. Merged through SysmonWatcherService so the file format
        /// and normalization stay in one place.</summary>
        private static int ImportIgnored(string acDataDir)
        {
            int ignored = 0;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string candidate in AutoCommandIgnoreListCandidates(acDataDir))
            {
                try
                {
                    if (!File.Exists(candidate)) continue;
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
            return ignored;
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
