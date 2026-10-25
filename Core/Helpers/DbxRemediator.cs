using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace AutoScope.Helpers
{
    /// <summary>
    /// DBX update download and installation.
    /// Ported from DeviceMonitorCS.
    /// </summary>
    public static class DbxRemediator
    {
        public const string DbxUrl = "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/DBX/amd64/DBXUpdate.bin";
        private const string DbxFileName = "DBXUpdate.bin";

        public static string GetInstallCommand(string path)
        {
            return $"Set-SecureBootUEFI -Name dbx -ContentFilePath '{path}'";
        }

        public static async Task<(string Path, string Checksum, string Error)> DownloadUpdateAsync()
        {
            string tempPath = Path.Combine(Path.GetTempPath(), DbxFileName);
            try
            {
                using (var client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Add("User-Agent", "AutoScope/1.0");
                    var data = await client.GetByteArrayAsync(DbxUrl);
                    await File.WriteAllBytesAsync(tempPath, data);

                    using (var sha256 = System.Security.Cryptography.SHA256.Create())
                    {
                        var hash = sha256.ComputeHash(data);
                        return (tempPath, BitConverter.ToString(hash).Replace("-", ""), null);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Download Failed: {ex.Message}");
                return (string.Empty, string.Empty, ex.Message);
            }
        }

        public static async Task<(bool Success, string Error)> InstallUpdateAsync(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
                return (false, "File not found");

            try
            {
                // Apply via PowerShell is unavoidable for Set-SecureBootUEFI (no native C# API for this)
                // This is the ONLY place we use PowerShell — it's a firmware-level UEFI command
                var psCommand = GetInstallCommand(path);
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = $"-Command \"{psCommand}\"",
                    UseShellExecute = true,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                var process = Process.Start(psi);
                if (process != null)
                {
                    await process.WaitForExitAsync();
                    if (process.ExitCode == 0) return (true, null);
                    return (false, $"PowerShell exited with code {process.ExitCode}. Firmware may have rejected the update.");
                }
                return (false, "Failed to start process.");
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
        }
    }
}

