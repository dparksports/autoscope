using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace AutoScope.Services
{
    /// <summary>One Assets/known-tasks.json entry: the plain-English half of an investigation.</summary>
    public class KnownTaskEntry
    {
        public string Title { get; set; }
        public string Explanation { get; set; }
        public string Note { get; set; }
    }

    /// <summary>
    /// Plain-English explanations for well-known scheduled tasks, shipped as
    /// Assets/known-tasks.json so the corpus grows without a rebuild: add a
    /// path-keyed entry, restart, and every future spawn of that task carries
    /// its explanation in the Taskhostw Spawns tab. The catalog is lookup-only
    /// enrichment — unknown tasks are not errors, they simply fall back to the
    /// task XML's own Description/Author in the summary pane.
    /// </summary>
    public static class KnownTaskCatalog
    {
        private static Dictionary<string, KnownTaskEntry> _entries;
        private static bool _loaded;

        public static KnownTaskEntry Lookup(string taskPath)
        {
            if (string.IsNullOrEmpty(taskPath)) return null;
            LoadIfNeeded();
            return _entries.TryGetValue(Normalize(taskPath), out var entry) ? entry : null;
        }

        private static string Normalize(string path) => path.Trim().TrimEnd('\\').ToLowerInvariant();

        private static void LoadIfNeeded()
        {
            if (_loaded) return;
            _loaded = true;
            _entries = new Dictionary<string, KnownTaskEntry>(StringComparer.Ordinal);
            try
            {
                string file = Path.Combine(AppContext.BaseDirectory, "Assets", "known-tasks.json");
                if (!File.Exists(file)) return;

                var entries = JsonSerializer.Deserialize<Dictionary<string, KnownTaskEntry>>(File.ReadAllText(file));
                if (entries == null) return;
                foreach (var kv in entries)
                    if (!string.IsNullOrEmpty(kv.Value?.Title))
                        _entries[Normalize(kv.Key)] = kv.Value;
            }
            catch { /* the catalog is best-effort enrichment, never fatal */ }
        }
    }
}
