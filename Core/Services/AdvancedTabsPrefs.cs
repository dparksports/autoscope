using System.IO;

namespace AutoScope.Services
{
    /// <summary>
    /// "Advanced investigation" sidebar preference: whether the deep-dive
    /// tabs (Spawns, BITS Transfers, Traffic Patterns, Black Hole, Windows
    /// Defender, Data &amp; Privacy, OneSettings, Sysmon Audit) are shown.
    /// Disabled by default — the app opens as a plain watch-and-block tool
    /// and grows the extra surfaces only for people who opt in. Persisted
    /// in advanced_tabs.txt ("1"/"0"), the same best-effort flat-file
    /// pattern as confirm_prefs.txt and tx_threshold.txt.
    /// </summary>
    public static class AdvancedTabsPrefs
    {
        private const string PrefsPath = "advanced_tabs.txt";

        public static bool Load()
        {
            try { return File.Exists(PrefsPath) && File.ReadAllText(PrefsPath).Trim() == "1"; }
            catch { return false; } // unreadable — the safe default is hidden
        }

        public static void Save(bool enabled)
        {
            try { File.WriteAllText(PrefsPath, enabled ? "1" : "0"); }
            catch { /* disk refused — the live toggle still applies this session */ }
        }
    }
}
