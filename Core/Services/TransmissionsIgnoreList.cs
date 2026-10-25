using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace AutoScope.Services
{
    /// <summary>
    /// The user's "stop telling me about this app" list for the
    /// Transmissions tab: full image paths, persisted beside the archive as
    /// ignored-apps.json. An ignored image gets no encrypted-upload toasts
    /// and no "Apps without keys" suggestion entries — its rows still
    /// appear in the grid (the feed stays truthful); only the prompting is
    /// silenced. This is the pressure valve for the deliberately
    /// unthrottled toast stream.
    /// </summary>
    public static class TransmissionsIgnoreList
    {
        private static readonly object Gate = new();
        private static HashSet<string> _images;

        private static string ListPath => Path.Combine(
            TransmissionsArchiveService.ArchiveDirectory, "ignored-apps.json");

        private static void Load()
        {
            if (_images != null) return;
            try
            {
                if (File.Exists(ListPath))
                {
                    var stored = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(ListPath));
                    _images = new HashSet<string>(stored ?? new List<string>(), StringComparer.OrdinalIgnoreCase);
                    return;
                }
            }
            catch { /* unreadable list — start empty, never crash over a hint file */ }
            _images = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        private static void Save()
        {
            try
            {
                Directory.CreateDirectory(TransmissionsArchiveService.ArchiveDirectory);
                File.WriteAllText(ListPath, JsonSerializer.Serialize(new List<string>(_images),
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* persistence is best-effort */ }
        }

        public static bool IsIgnored(string image)
        {
            if (string.IsNullOrEmpty(image)) return false;
            lock (Gate) { Load(); return _images.Contains(image); }
        }

        public static void Ignore(string image)
        {
            if (string.IsNullOrEmpty(image)) return;
            lock (Gate)
            {
                Load();
                if (_images.Add(image)) Save();
            }
        }

        public static void Unignore(string image)
        {
            if (string.IsNullOrEmpty(image)) return;
            lock (Gate)
            {
                Load();
                if (_images.Remove(image)) Save();
            }
        }

        /// <summary>Copy of the ignored image paths, for the management UI.</summary>
        public static List<string> All()
        {
            lock (Gate) { Load(); return new List<string>(_images); }
        }
    }
}
