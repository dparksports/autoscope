using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace AutoScope.Helpers
{
    /// <summary>
    /// Persists firewall rule override state to JSON.
    /// Ported from DeviceMonitorCS.
    /// </summary>
    public class FirewallConfigManager
    {
        private static FirewallConfigManager _instance;
        public static FirewallConfigManager Instance => _instance ??= new FirewallConfigManager();

        private readonly string _configPath;
        public Dictionary<string, string> RuleOverrides { get; set; } = new Dictionary<string, string>();

        public FirewallConfigManager()
        {
            _configPath = Path.Combine(@"C:\ProgramData\AutoScope", "firewall_config.json");
            Load();
        }

        public void Load()
        {
            try
            {
                if (File.Exists(_configPath))
                {
                    string json = File.ReadAllText(_configPath);
                    var data = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                    if (data != null) RuleOverrides = data;
                }
            }
            catch { }
        }

        public void Save()
        {
            try
            {
                var dir = Path.GetDirectoryName(_configPath);
                if (dir != null && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                string json = JsonSerializer.Serialize(RuleOverrides, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_configPath, json);
            }
            catch { }
        }

        public void SetOverride(string ruleName, bool enabled)
        {
            string state = enabled ? "True" : "False";
            RuleOverrides[ruleName] = state;
            Save();
        }

        public string GetOverride(string ruleName)
        {
            return RuleOverrides.TryGetValue(ruleName, out string val) ? val : null;
        }
    }
}

