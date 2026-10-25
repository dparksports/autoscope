using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

namespace AutoScope.Services
{
    /// <summary>
    /// Reads and tails the NSS-format TLS keylog that instrumented python
    /// processes write (SSLKEYLOGFILE → pytrace\sslkeys.log), and owns the
    /// file's hygiene: created with a current-user-only ACL, rotated at 5 MB,
    /// the rotation leftover deleted at app exit, and a no-keylog flag file
    /// that makes the hook stop setting the env var entirely.
    ///
    /// Secrets live in memory only — they are never exported or logged.
    /// </summary>
    public class TlsKeylogService
    {
        /// <summary>Self-test seam: redirects the pytrace dir when set (null in the app).</summary>
        public static string DirOverride { get; set; }

        public static string Dir =>
            DirOverride ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AutoScope", "pytrace");

        public static string KeylogPath => Path.Combine(Dir, "sslkeys.log");
        public static string OldKeylogPath => KeylogPath + ".old";
        public static string NoKeylogFlagPath => Path.Combine(Dir, "no-keylog");

        private const long RotateAtBytes = 5 * 1024 * 1024;

        // client_random (uppercase hex) → label → secret bytes
        private readonly Dictionary<string, Dictionary<string, byte[]>> _secrets =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly object _lock = new();
        private long _readOffset;
        private long _fileGeneration = -1;

        public event Action<string> OnError;

        /// <summary>False when the user turned TLS keylogging off (flag file present).</summary>
        public static bool KeylogEnabled => !File.Exists(NoKeylogFlagPath);

        /// <summary>Creates the keylog file with a current-user-only ACL if absent, rotates when oversized.</summary>
        public static void EnsureHygiene()
        {
            try
            {
                Directory.CreateDirectory(Dir);
                if (!File.Exists(KeylogPath))
                    CreateWithUserOnlyAcl(KeylogPath);
                else if (new FileInfo(KeylogPath).Length > RotateAtBytes)
                    Rotate();
            }
            catch (Exception)
            {
                // hygiene is best-effort — decryption simply finds no secrets
            }
        }

        private static void CreateWithUserOnlyAcl(string path)
        {
            using (File.Create(path, 4096, FileOptions.None)) { }
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false); // nothing inherited: current user only
            security.AddAccessRule(new FileSystemAccessRule(
                WindowsIdentity.GetCurrent().User,
                FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(security);
        }

        private static void Rotate()
        {
            // Children open the log per record (append), so moving it under
            // them is safe; the .old from any previous rotation is dropped.
            File.Delete(OldKeylogPath);
            File.Move(KeylogPath, OldKeylogPath);
            CreateWithUserOnlyAcl(KeylogPath);
        }

        /// <summary>App-exit cleanup — call from MainWindow.OnClosed.</summary>
        public static void CleanupAtExit()
        {
            try { File.Delete(OldKeylogPath); } catch { }
        }

        /// <summary>
        /// Turns keylogging off for future instrumented launches: wipes the
        /// log and drops the flag file the hook checks before user code runs.
        /// </summary>
        public static void DisableKeylogging()
        {
            try
            {
                Directory.CreateDirectory(Dir);
                File.WriteAllText(NoKeylogFlagPath, "TLS keylogging disabled from AutoScope settings");
                File.Delete(KeylogPath);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Could not disable keylogging: {ex.Message}", ex);
            }
        }

        /// <summary>Re-enables keylogging (removes the flag, recreates the ACL'd log).</summary>
        public static void EnableKeylogging()
        {
            try
            {
                File.Delete(NoKeylogFlagPath);
                EnsureHygiene();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Could not enable keylogging: {ex.Message}", ex);
            }
        }

        /// <summary>Parses any new lines appended since the last call.</summary>
        public void Refresh()
        {
            try
            {
                var fi = new FileInfo(KeylogPath);
                if (!fi.Exists)
                {
                    lock (_lock) { _secrets.Clear(); _readOffset = 0; _fileGeneration = -1; }
                    return;
                }

                long generation = fi.CreationTimeUtc.Ticks ^ fi.Length;
                bool rotated = generation != _fileGeneration && _fileGeneration != -1;
                long offset = rotated ? 0 : _readOffset;
                if (!rotated && fi.Length <= offset) return;

                using var fs = new FileStream(KeylogPath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                fs.Seek(offset, SeekOrigin.Begin);
                using var reader = new StreamReader(fs);

                string line;
                var parsed = new List<(string, string, byte[])>(16);
                while ((line = reader.ReadLine()) != null)
                {
                    var entry = ParseLine(line);
                    if (entry.HasValue) parsed.Add(entry.Value);
                }

                lock (_lock)
                {
                    foreach (var (randomHex, label, secret) in parsed)
                    {
                        if (!_secrets.TryGetValue(randomHex, out var labels))
                            _secrets[randomHex] = labels = new Dictionary<string, byte[]>(8, StringComparer.Ordinal);
                        labels[label] = secret;
                    }
                    _readOffset = fs.Position;
                    _fileGeneration = generation;
                }
            }
            catch (IOException)
            {
                // mid-append read; the next Refresh retries from the last good offset
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"TLS keylog read failed: {ex.Message}");
            }
        }

        /// <summary>
        /// NSS keylog line: "LABEL client_random_hex secret_hex". TLS 1.2 uses
        /// CLIENT_RANDOM; TLS 1.3 logs the handshake/application traffic
        /// secrets per direction (plus _N successors after KeyUpdate).
        /// </summary>
        private static (string randomHex, string label, byte[] secret)? ParseLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) return null;
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 3) return null;
            if (parts[1].Length % 2 != 0 || parts[2].Length % 2 != 0) return null;

            switch (parts[0])
            {
                case "CLIENT_RANDOM":
                case "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
                case "SERVER_HANDSHAKE_TRAFFIC_SECRET":
                case "CLIENT_TRAFFIC_SECRET_0":
                case "SERVER_TRAFFIC_SECRET_0":
                    break;
                default:
                    return null; // EXPORTER_* and KeyUpdate successors are not needed for decryption
            }

            try
            {
                byte[] secret = HexToBytes(parts[2]);
                if (secret.Length < 16) return null;
                return (parts[1].ToUpperInvariant(), parts[0], secret);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>All secrets logged for the given 32-byte client random, keyed by label.</summary>
        public IReadOnlyDictionary<string, byte[]> GetSecrets(byte[] clientRandom)
        {
            string key = BytesToHex(clientRandom);
            lock (_lock)
            {
                if (!_secrets.TryGetValue(key, out var labels)) return null;
                return new Dictionary<string, byte[]>(labels, StringComparer.Ordinal);
            }
        }

        public int SessionCount { get { lock (_lock) return _secrets.Count; } }

        internal static byte[] HexToBytes(string hex)
        {
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }

        internal static string BytesToHex(byte[] bytes)
        {
            var sb = new System.Text.StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes) sb.Append(b.ToString("X2"));
            return sb.ToString();
        }
    }
}
