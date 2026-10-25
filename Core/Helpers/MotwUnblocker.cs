using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace AutoScope.Helpers
{
    /// <summary>
    /// Removes the Mark-of-the-Web (the Zone.Identifier alternate data
    /// stream) from every file under a folder. Files extracted from a
    /// downloaded zip carry the mark, and SmartScreen / Smart App Control
    /// block unsigned apps because of it — deleting the named stream is
    /// exactly what PowerShell's Unblock-File cmdlet does, done here via
    /// DeleteFileW so it works on any file without spawning a shell.
    /// </summary>
    public static class MotwUnblocker
    {
        public sealed class Result
        {
            public int Scanned;
            public int Unblocked;
            public int AlreadyClean;
            public readonly List<string> Failures = new();

            public string Summary =>
                Failures.Count == 0
                    ? $"Unblocked {Unblocked} file(s) · {AlreadyClean} already clean · {Scanned} scanned"
                    : $"Unblocked {Unblocked} file(s) · {AlreadyClean} already clean · {Failures.Count} could not be updated (in use or denied)";
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool DeleteFile(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFileAttributes(string lpFileName);

        private const uint InvalidFileAttributes = 0xFFFFFFFF;

        /// <summary>Strips Zone.Identifier from every file under the folder (recursively, no junction following).</summary>
        public static Result UnblockFolder(string folder)
        {
            var result = new Result();
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
            {
                result.Failures.Add($"Folder not found: {folder}");
                return result;
            }

            foreach (string file in SafeEnumerateFiles(folder))
            {
                result.Scanned++;
                try
                {
                    // Deleting the named stream succeeds only when the mark
                    // exists; ERROR_FILE_NOT_FOUND means the file was clean.
                    if (DeleteFile(file + ":Zone.Identifier"))
                        result.Unblocked++;
                    else if (Marshal.GetLastWin32Error() == 2) // ERROR_FILE_NOT_FOUND
                        result.AlreadyClean++;
                    else
                        result.Failures.Add(file);
                }
                catch
                {
                    result.Failures.Add(file);
                }
            }
            return result;
        }

        /// <summary>True when the file currently carries the Mark-of-the-Web.</summary>
        public static bool IsMarked(string file)
        {
            try
            {
                return GetFileAttributes(file + ":Zone.Identifier") != InvalidFileAttributes;
            }
            catch
            {
                return false;
            }
        }

        private static IEnumerable<string> SafeEnumerateFiles(string root)
        {
            var queue = new Queue<string>();
            queue.Enqueue(root);
            while (queue.Count > 0)
            {
                string dir = queue.Dequeue();
                string[] files = null, subDirs = null;
                try { files = Directory.GetFiles(dir); } catch { /* denied: skip */ }
                try { subDirs = Directory.GetDirectories(dir); } catch { }

                if (files != null)
                    foreach (string file in files)
                        yield return file;

                if (subDirs == null) continue;
                foreach (string sub in subDirs)
                {
                    try
                    {
                        // Reparse points (junctions/symlinks) can loop back up the tree
                        if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) == 0)
                            queue.Enqueue(sub);
                    }
                    catch { }
                }
            }
        }
    }
}
