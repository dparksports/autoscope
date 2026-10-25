using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace AutoScope.Helpers
{
    /// <summary>
    /// Persists the user's bloatware-list customizations to JSON, mirroring
    /// FirewallConfigManager. Edits are stored as a delta on top of the
    /// compiled-in AppManagerService.BloatwarePatterns defaults, so defaults
    /// shipped with new app versions still reach users who already customized
    /// their list: DisabledDefaults opts out, CustomPackages/CustomPatterns opt in.
    /// </summary>
    public class BloatwareConfig
    {
        private static BloatwareConfig _instance;
        public static BloatwareConfig Instance => _instance ??= new BloatwareConfig();

        private readonly string _configPath;
        // Fresh Setup's verify step reads the config from worker threads while
        // the UI can be mutating it — all access goes through this lock.
        private readonly object _lock = new();

        private HashSet<string> _disabledDefaults = new(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _customPackages = new(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _customPatterns = new(StringComparer.OrdinalIgnoreCase);

        public BloatwareConfig()
        {
            _configPath = Path.Combine(@"C:\ProgramData\AutoScope", "bloatware_config.json");
            Load();
        }

        /// <summary>Copies of the current sets, safe to enumerate off the lock.</summary>
        public (HashSet<string> DisabledDefaults, HashSet<string> CustomPackages, HashSet<string> CustomPatterns) Snapshot()
        {
            lock (_lock)
            {
                return (new HashSet<string>(_disabledDefaults, StringComparer.OrdinalIgnoreCase),
                        new HashSet<string>(_customPackages, StringComparer.OrdinalIgnoreCase),
                        new HashSet<string>(_customPatterns, StringComparer.OrdinalIgnoreCase));
            }
        }

        public void DisableDefault(string pattern)
        {
            lock (_lock) { _disabledDefaults.Add(pattern); }
            Save();
        }

        public void EnableDefault(string pattern)
        {
            lock (_lock) { _disabledDefaults.Remove(pattern); }
            Save();
        }

        public void AddCustomPackage(string packageName)
        {
            if (string.IsNullOrWhiteSpace(packageName)) return;
            lock (_lock) { _customPackages.Add(packageName.Trim()); }
            Save();
        }

        public void RemoveCustomPackage(string packageName)
        {
            lock (_lock) { _customPackages.Remove(packageName); }
            Save();
        }

        public void AddCustomPattern(string pattern)
        {
            if (string.IsNullOrWhiteSpace(pattern)) return;
            lock (_lock) { _customPatterns.Add(pattern.Trim()); }
            Save();
        }

        public void RemoveCustomPattern(string pattern)
        {
            lock (_lock) { _customPatterns.Remove(pattern); }
            Save();
        }

        /// <summary>Clears every customization back to the compiled-in defaults.</summary>
        public void Reset()
        {
            lock (_lock)
            {
                _disabledDefaults.Clear();
                _customPackages.Clear();
                _customPatterns.Clear();
            }
            Save();
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_configPath)) return;
                string json = File.ReadAllText(_configPath);
                var data = JsonSerializer.Deserialize<ConfigFile>(json);
                if (data == null) return;
                lock (_lock)
                {
                    _disabledDefaults = ToSet(data.DisabledDefaults);
                    _customPackages = ToSet(data.CustomPackages);
                    _customPatterns = ToSet(data.CustomPatterns);
                }
            }
            catch
            {
                // A corrupt config must never break bloatware scanning — the
                // compiled-in defaults remain in force.
            }
        }

        private void Save()
        {
            lock (_lock)
            {
                try
                {
                    var dir = Path.GetDirectoryName(_configPath);
                    if (dir != null && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                    // Sorted lists keep the file diffable across saves
                    var file = new ConfigFile
                    {
                        DisabledDefaults = _disabledDefaults.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList(),
                        CustomPackages = _customPackages.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList(),
                        CustomPatterns = _customPatterns.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList()
                    };
                    File.WriteAllText(_configPath,
                        JsonSerializer.Serialize(file, new JsonSerializerOptions { WriteIndented = true }));
                }
                catch
                {
                    // Persistence failures leave the session working with in-memory state
                }
            }
        }

        private static HashSet<string> ToSet(List<string> values)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (values == null) return set;
            foreach (var v in values)
                if (!string.IsNullOrWhiteSpace(v)) set.Add(v.Trim());
            return set;
        }

        private sealed class ConfigFile
        {
            public List<string> DisabledDefaults { get; set; } = new();
            public List<string> CustomPackages { get; set; } = new();
            public List<string> CustomPatterns { get; set; } = new();
        }
    }
}
