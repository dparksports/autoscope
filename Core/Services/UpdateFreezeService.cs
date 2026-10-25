using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AutoScope.Helpers;

namespace AutoScope.Services
{
    /// <summary>An app that can update itself in place, discovered or frozen.</summary>
    public class UpdateFreezeTarget
    {
        public string Name;             // display name (exe file name)
        public string ExePath;
        public string Evidence;         // how it was discovered / why it is an updater
        public string Vendor;           // Authenticode signer, "Unsigned" or "Unknown"
        public bool IsFreezable = true;
        public string NotFreezableReason;
    }

    /// <summary>
    /// Version pinning for self-updating apps. A freeze adds an NTFS Deny ACE
    /// (Delete + WriteData + AppendData for the current user) to the app's exe,
    /// so the updater's replace-by-rename or in-place write fails while the app
    /// itself keeps running (read/execute are untouched). Before denying, the
    /// original ACL is saved with "icacls /save" so unfreezing restores exactly
    /// what was there. OS binaries are refused outright.
    /// </summary>
    public class UpdateFreezeService
    {
        private const string StateFile = "update_freeze.json";
        private const string BackupDir = "freeze_backups";

        // Self-update backups like "agy.exe.1791616910661016200.old": an exe
        // renamed away by its own updater before writing the replacement
        private static readonly Regex SelfUpdateOldRegex =
            new Regex(@"^(?<exe>.+\.exe)(?:\.\d+)?\.old$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private readonly Dictionary<string, FrozenEntry> _state = new(StringComparer.OrdinalIgnoreCase);

        private sealed class FrozenEntry
        {
            public string ExePath { get; set; }
            public string Name { get; set; }
            public DateTime FrozenAt { get; set; }
            public string BackupFile { get; set; }
        }

        public UpdateFreezeService()
        {
            LoadState();
        }

        public IReadOnlyCollection<string> FrozenPaths => _state.Keys.ToList();

        public bool IsFrozen(string exePath) => _state.ContainsKey(exePath);

        // -----------------------------------------------------------------------
        // Discovery
        // -----------------------------------------------------------------------

        /// <summary>
        /// Finds self-updating apps: "*.old" self-update leftovers, updater
        /// folders and "update" autostart entries under the user profile.
        /// Read-only — freezing is always an explicit user action.
        /// </summary>
        public List<UpdateFreezeTarget> DiscoverCandidates()
        {
            var byPath = new Dictionary<string, UpdateFreezeTarget>(StringComparer.OrdinalIgnoreCase);

            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            // Depth-limited walk: updater binaries live near the surface, and a
            // full recursion would crawl through node_modules-sized trees
            foreach (string root in new[] { localAppData, appData })
            {
                foreach (string file in EnumerateFilesSafe(root, depth: 3, pattern: "*.old"))
                {
                    var match = SelfUpdateOldRegex.Match(Path.GetFileName(file));
                    if (!match.Success) continue;

                    string exePath = Path.Combine(Path.GetDirectoryName(file), match.Groups["exe"].Value);
                    if (!File.Exists(exePath)) continue;

                    AddCandidate(byPath, exePath,
                        $"Self-updater: left backup \"{Path.GetFileName(file)}\" next to the exe (rename-and-replace update)");
                }

                foreach (string dir in EnumerateDirsSafe(root, depth: 2))
                {
                    string dirName = Path.GetFileName(dir);
                    if (dirName.IndexOf("updat", StringComparison.OrdinalIgnoreCase) < 0) continue;

                    foreach (string exe in Directory.EnumerateFiles(dir, "*.exe").Take(3))
                        AddCandidate(byPath, exe, $"Updater folder: \"{dirName}\" under the user profile");
                }
            }

            // Autostart Run keys that mention "update" (Brave, Edge, ...)
            foreach (var runKey in new[]
                     {
                         Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"),
                         Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")
                     })
            {
                if (runKey == null) continue;
                using (runKey)
                {
                    foreach (var valueName in runKey.GetValueNames())
                    {
                        string command = runKey.GetValue(valueName)?.ToString();
                        if (command == null || command.IndexOf("updat", StringComparison.OrdinalIgnoreCase) < 0) continue;

                        string exePath = ParseExeFromCommand(command);
                        if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath)) continue;
                        AddCandidate(byPath, exePath, $"Autostart Run key \"{valueName}\"");
                    }
                }
            }

            return byPath.Values
                .OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static void AddCandidate(Dictionary<string, UpdateFreezeTarget> byPath, string exePath, string evidence)
        {
            if (byPath.ContainsKey(exePath)) return;

            string vendor = GetSigner(exePath);
            var target = new UpdateFreezeTarget
            {
                Name = Path.GetFileName(exePath),
                ExePath = exePath,
                Evidence = evidence,
                Vendor = vendor
            };

            // Never freeze Windows' own binaries: breaking them can make the
            // OS unbootable/undeletable, and Windows updates are not the
            // user-level surprise this feature exists to stop
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (exePath.StartsWith(winDir, StringComparison.OrdinalIgnoreCase))
            {
                target.IsFreezable = false;
                target.NotFreezableReason = "Windows system binary — freezing OS components is refused.";
            }
            else if (vendor.Contains("Microsoft Windows", StringComparison.OrdinalIgnoreCase))
            {
                target.IsFreezable = false;
                target.NotFreezableReason = "Windows-signed binary — freezing OS components is refused.";
            }

            byPath[exePath] = target;
        }

        private static string ParseExeFromCommand(string command)
        {
            command = command.Trim();
            if (command.StartsWith("\""))
            {
                int end = command.IndexOf('"', 1);
                if (end > 1) return command.Substring(1, end - 1);
            }
            int space = command.IndexOf(' ');
            return space < 0 ? command : command.Substring(0, space);
        }

        private static string GetSigner(string exePath)
        {
            try
            {
#pragma warning disable SYSLIB0057 // no non-obsolete signed-file loader on this TFM
                using var cert = X509Certificate.CreateFromSignedFile(exePath);
#pragma warning restore SYSLIB0057
                return cert.Subject;
            }
            catch
            {
                return File.Exists(exePath) ? "Unsigned" : "Unknown";
            }
        }

        // -----------------------------------------------------------------------
        // Freeze / thaw
        // -----------------------------------------------------------------------

        public async Task<(bool Success, string Message)> FreezeAsync(string exePath)
        {
            if (!File.Exists(exePath)) return (false, "File not found.");
            if (IsFrozen(exePath)) return (true, "Already frozen.");

            Directory.CreateDirectory(BackupDir);
            string backupFile = Path.Combine(BackupDir,
                $"{Path.GetFileNameWithoutExtension(exePath)}_{DateTime.Now:yyyyMMdd_HHmmss}.acl");

            // Snapshot the ACL first so unfreeze restores exactly the original
            var (saveOut, saveErr, saveCode) = await ProcessRunner.RunWithDetailsAsync("icacls.exe",
                $"\"{exePath}\" /save \"{backupFile}\"");
            if (saveCode != 0)
                return (false, $"ACL snapshot failed (icacls /save exit {saveCode}). {saveErr}");

            string user = Environment.UserName;
            var (_, denyErr, denyCode) = await ProcessRunner.RunWithDetailsAsync("icacls.exe",
                $"\"{exePath}\" /deny \"{user}:(DE,WD,AD)\"");
            if (denyCode != 0)
                return (false, $"Deny ACE failed (icacls /deny exit {denyCode}). {denyErr}");

            // Trust but verify: the deny must actually be on the file now
            var (listOut, _, _) = await ProcessRunner.RunWithDetailsAsync("icacls.exe", $"\"{exePath}\"");
            if (!(listOut ?? string.Empty).Contains("(DENY)", StringComparison.OrdinalIgnoreCase))
                return (false, "Deny ACE did not stick — aborting (state unchanged, backup kept).");

            _state[exePath] = new FrozenEntry
            {
                ExePath = exePath,
                Name = Path.GetFileName(exePath),
                FrozenAt = DateTime.Now,
                BackupFile = backupFile
            };
            SaveState();
            return (true, $"{Path.GetFileName(exePath)} frozen: delete/write denied for {user}, read+execute untouched.");
        }

        public async Task<(bool Success, string Message)> ThawAsync(string exePath)
        {
            if (!IsFrozen(exePath)) return (true, "Not frozen.");

            var entry = _state[exePath];
            if (!File.Exists(entry.BackupFile))
                return (false, $"ACL backup missing ({entry.BackupFile}). Remove the deny ACE manually: icacls \"{exePath}\" /remove:d {Environment.UserName}");

            // icacls /save records the file relative to its parent, so restore
            // is issued against the parent directory
            var (_, err, code) = await ProcessRunner.RunWithDetailsAsync("icacls.exe",
                $"\"{Path.GetDirectoryName(exePath)}\" /restore \"{entry.BackupFile}\"");
            if (code != 0)
                return (false, $"ACL restore failed (icacls /restore exit {code}). {err}");

            var (listOut, _, _) = await ProcessRunner.RunWithDetailsAsync("icacls.exe", $"\"{exePath}\"");
            if ((listOut ?? string.Empty).Contains("(DENY)", StringComparison.OrdinalIgnoreCase))
                return (false, "A deny ACE is still present after restore — check the file's ACL manually.");

            try { File.Delete(entry.BackupFile); } catch { }
            _state.Remove(exePath);
            SaveState();
            return (true, $"{Path.GetFileName(exePath)} unfrozen — updates will work again.");
        }

        // -----------------------------------------------------------------------
        // State persistence (update_freeze.json)
        // -----------------------------------------------------------------------

        private void LoadState()
        {
            try
            {
                if (!File.Exists(StateFile)) return;
                var entries = JsonSerializer.Deserialize<List<FrozenEntry>>(File.ReadAllText(StateFile));
                if (entries == null) return;
                foreach (var entry in entries)
                    if (!string.IsNullOrEmpty(entry.ExePath))
                        _state[entry.ExePath] = entry;
            }
            catch { /* unreadable state — start empty; frozen ACLs stay frozen */ }
        }

        private void SaveState()
        {
            try
            {
                File.WriteAllText(StateFile, JsonSerializer.Serialize(_state.Values.ToList(),
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* best-effort: the ACL deny is the real enforcement */ }
        }

        // -----------------------------------------------------------------------
        // Safe enumeration helpers
        // -----------------------------------------------------------------------

        private static IEnumerable<string> EnumerateFilesSafe(string root, int depth, string pattern)
        {
            var found = new List<string>();
            void Walk(string dir, int remaining)
            {
                if (remaining < 0 || found.Count > 500) return;
                try
                {
                    found.AddRange(Directory.EnumerateFiles(dir, pattern));
                    foreach (string child in Directory.EnumerateDirectories(dir))
                        Walk(child, remaining - 1);
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
            Walk(root, depth);
            return found;
        }

        private static IEnumerable<string> EnumerateDirsSafe(string root, int depth)
        {
            var found = new List<string>();
            void Walk(string dir, int remaining)
            {
                if (remaining < 0 || found.Count > 500) return;
                try
                {
                    found.AddRange(Directory.EnumerateDirectories(dir));
                    foreach (string child in Directory.EnumerateDirectories(dir))
                        Walk(child, remaining - 1);
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
            Walk(root, depth);
            return found;
        }
    }
}
