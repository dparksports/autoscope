using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace AutoScope.Services
{
    /// <summary>
    /// On-disk store behind the Transmissions tab, mirroring the Sysmon
    /// archive's shape: one readable, greppable JSONL index file per day
    /// under %LOCALAPPDATA%\AutoScope\transmissions, plus full-request /
    /// full-response body blobs in bodies\ — no truncation, the >10 KB
    /// cases are exactly the ones that must be complete on disk. Each row
    /// carries a SHA-256 over both plaintext directions so "what was sent"
    /// stays provable after the fact.
    ///
    /// Retention: day files prune after DefaultRetainDays; the bodies
    /// folder additionally rotates oldest-day directories out once it
    /// exceeds BodiesBudgetBytes. Everything stays local — the AI bridge
    /// exposes metadata only, never these files.
    /// </summary>
    public static class TransmissionsArchiveService
    {
        public const int DefaultRetainDays = 30;
        public const long BodiesBudgetBytes = 256L * 1024 * 1024;

        /// <summary>Archive root; settable for offline self-tests (house pattern).</summary>
        public static string ArchiveDirectory { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoScope", "transmissions");

        private static string BodiesRoot => Path.Combine(ArchiveDirectory, "bodies");
        private static readonly object _gate = new();
        private static DateTime _lastPruneUtc = DateTime.MinValue;

        public static string DayFilePath(DateTime utc) =>
            Path.Combine(ArchiveDirectory, "transmissions-" + utc.ToString("yyyy-MM-dd") + ".jsonl");

        // ── append ────────────────────────────────────────────────────────

        /// <summary>
        /// Writes one row's index line and (when the flow decrypted to
        /// content) its body blobs. Returns true when anything was written.
        /// The pair (request, response) are the decrypted plaintext streams;
        /// either may be null/empty.
        /// </summary>
        public static bool Append(Models.TransmissionRecord record, byte[] requestStream, byte[] responseStream)
        {
            if (record == null) return false;
            try
            {
                lock (_gate)
                {
                    Directory.CreateDirectory(ArchiveDirectory);

                    bool hasContent = (requestStream != null && requestStream.Length > 0) ||
                                      (responseStream != null && responseStream.Length > 0);
                    record.HasContent = hasContent;

                    if (hasContent)
                    {
                        record.Sha256 = ComputeSha256(requestStream, responseStream);
                        Directory.CreateDirectory(BodiesRoot);
                        if (requestStream is { Length: > 0 })
                            File.WriteAllBytes(BodyPath(record, "request"), requestStream);
                        if (responseStream is { Length: > 0 })
                            File.WriteAllBytes(BodyPath(record, "response"), responseStream);
                    }
                    record.ArchiveDay = record.TsUtc.ToString("yyyy-MM-dd");

                    var line = JsonSerializer.Serialize(new Dictionary<string, object>
                    {
                        ["id"] = record.Id,
                        ["ts"] = record.TsUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                        ["pid"] = record.Pid,
                        ["image"] = record.Image,
                        ["remote"] = record.ServerEndpoint,
                        ["local"] = record.LocalEndpoint,
                        ["sni"] = record.Sni,
                        ["tls"] = record.TlsVersion,
                        ["alpn"] = record.Alpn,
                        ["cipher"] = record.CipherSuite,
                        ["provider"] = record.Provider,
                        ["provider_country"] = record.ProviderCountry,
                        ["client_bytes"] = record.ClientBytes,
                        ["server_bytes"] = record.ServerBytes,
                        ["client_app_bytes"] = record.ClientAppBytes,
                        ["server_app_bytes"] = record.ServerAppBytes,
                        ["status"] = record.Status,
                        ["has_content"] = hasContent,
                        ["sha256"] = record.Sha256,
                        ["message_count"] = record.MessageCount,
                        ["content_kinds"] = record.ContentKinds,
                    });
                    File.AppendAllText(DayFilePath(record.TsUtc), line + Environment.NewLine);

                    MaybePrune();
                    return true;
                }
            }
            catch (Exception)
            {
                return false; // archive is best-effort; the live row still showed in the UI
            }
        }

        public static byte[] LoadBody(string id, string day, string direction)
        {
            try
            {
                string path = BodyPath(id, day, direction);
                return File.Exists(path) ? File.ReadAllBytes(path) : null;
            }
            catch { return null; }
        }

        private static string BodyPath(Models.TransmissionRecord record, string direction) =>
            BodyPath(record.Id, record.ArchiveDay, direction);

        private static string BodyPath(string id, string day, string direction)
        {
            string dir = Path.Combine(BodiesRoot, string.IsNullOrEmpty(day) ? "unknown" : day);
            return Path.Combine(dir, $"{id}.{direction}.bin");
        }

        private static string ComputeSha256(byte[] request, byte[] response)
        {
            using var sha = SHA256.Create();
            using var combined = new MemoryStream(
                (request?.Length ?? 0) + (response?.Length ?? 0) + 1);
            if (request is { Length: > 0 })
            {
                combined.Write(request, 0, request.Length);
                combined.WriteByte((byte)'\n');
            }
            if (response is { Length: > 0 })
                combined.Write(response, 0, response.Length);
            combined.Position = 0;
            return Convert.ToHexString(sha.ComputeHash(combined)).ToLowerInvariant();
        }

        // ── retention ─────────────────────────────────────────────────────

        /// <summary>Runs at most hourly: day-file age prune + bodies budget
        /// rotation. Public for the tab's "prune now" and self-tests.</summary>
        public static void Prune(int retainDays = DefaultRetainDays)
        {
            try
            {
                if (!Directory.Exists(ArchiveDirectory)) return;

                var cutoff = DateTime.UtcNow.Date.AddDays(-retainDays);
                foreach (var file in Directory.GetFiles(ArchiveDirectory, "transmissions-*.jsonl"))
                {
                    string stem = Path.GetFileName(file)
                        .Substring("transmissions-".Length)
                        .Replace(".jsonl", "");
                    if (DateTime.TryParseExact(stem, "yyyy-MM-dd", null,
                            System.Globalization.DateTimeStyles.None, out var day) && day < cutoff)
                    {
                        try { File.Delete(file); } catch { /* locked — next prune */ }
                    }
                }

                if (Directory.Exists(BodiesRoot))
                {
                    var dayDirs = Directory.GetDirectories(BodiesRoot)
                        .Select(d => (Path: d, Day: ParseDay(d)))
                        .Where(x => x.Day.HasValue)
                        .OrderBy(x => x.Day.Value)
                        .ToList();
                    foreach (var (path, day) in dayDirs.Where(x => x.Day.Value < cutoff))
                    {
                        try { Directory.Delete(path, recursive: true); } catch { }
                    }

                    long budget = BodiesBudgetBytes;
                    long used = dayDirs.Sum(d => DirSize(d.Path));
                    int oldest = 0;
                    while (used > budget && oldest < dayDirs.Count)
                    {
                        var victim = dayDirs[oldest++];
                        long size = DirSize(victim.Path);
                        try { Directory.Delete(victim.Path, recursive: true); used -= size; }
                        catch { break; }
                    }
                }
            }
            catch { /* retention is opportunistic */ }
        }

        private static void MaybePrune()
        {
            if ((DateTime.UtcNow - _lastPruneUtc).TotalMinutes < 60) return;
            _lastPruneUtc = DateTime.UtcNow;
            Prune();
        }

        private static DateTime? ParseDay(string dir)
        {
            string stem = Path.GetFileName(dir);
            return DateTime.TryParseExact(stem, "yyyy-MM-dd", null,
                System.Globalization.DateTimeStyles.None, out var day) ? day : null;
        }

        private static long DirSize(string dir)
        {
            try { return Directory.GetFiles(dir, "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length); }
            catch { return 0; }
        }

        // ── queries ───────────────────────────────────────────────────────

        /// <summary>Newest-first read of archived rows. Filters are applied
        /// in-memory per line; `contains` matches any field.</summary>
        public static List<Models.TransmissionRecord> Read(
            int max = 200, int? pid = null, string contains = null, DateTime? sinceUtc = null)
        {
            var hits = new List<Models.TransmissionRecord>();
            try
            {
                if (!Directory.Exists(ArchiveDirectory)) return hits;
                var files = Directory.GetFiles(ArchiveDirectory, "transmissions-*.jsonl")
                    .OrderByDescending(f => f, StringComparer.Ordinal)
                    .ToList();

                foreach (var file in files)
                {
                    if (hits.Count >= max) break;
                    string stem = Path.GetFileName(file)
                        .Substring("transmissions-".Length)
                        .Replace(".jsonl", "");
                    if (sinceUtc.HasValue &&
                        DateTime.TryParseExact(stem, "yyyy-MM-dd", null,
                            System.Globalization.DateTimeStyles.None, out var day) &&
                        day < sinceUtc.Value.Date)
                        continue;

                    var lines = File.ReadAllLines(file);
                    for (int li = lines.Length - 1; li >= 0 && hits.Count < max; li--)
                    {
                        string line = lines[li];
                        if (line.Length == 0) continue;
                        try
                        {
                            using var doc = JsonDocument.Parse(line);
                            var root = doc.RootElement;
                            int rowPid = root.TryGetProperty("pid", out var p) ? p.GetInt32() : 0;
                            if (pid.HasValue && rowPid != pid.Value) continue;

                            var rec = new Models.TransmissionRecord
                            {
                                Id = GetString(root, "id"),
                                TsUtc = DateTime.Parse(GetString(root, "ts"),
                                    System.Globalization.CultureInfo.InvariantCulture,
                                    System.Globalization.DateTimeStyles.AssumeUniversal).ToUniversalTime(),
                                Pid = rowPid,
                                Image = GetString(root, "image"),
                                RemoteIp = RemoteIpOf(GetString(root, "remote")),
                                RemotePort = RemotePortOf(GetString(root, "remote")),
                                LocalEndpoint = GetString(root, "local"),
                                Sni = GetString(root, "sni"),
                                TlsVersion = GetString(root, "tls"),
                                Alpn = GetString(root, "alpn"),
                                CipherSuite = GetString(root, "cipher"),
                                Provider = GetString(root, "provider") ?? "Unclassified",
                                ProviderCountry = GetString(root, "provider_country"),
                                ClientBytes = GetLong(root, "client_bytes"),
                                ServerBytes = GetLong(root, "server_bytes"),
                                ClientAppBytes = GetLong(root, "client_app_bytes"),
                                ServerAppBytes = GetLong(root, "server_app_bytes"),
                                Status = GetString(root, "status"),
                                HasContent = root.TryGetProperty("has_content", out var hc) && hc.GetBoolean(),
                                Sha256 = GetString(root, "sha256"),
                                MessageCount = (int)GetLong(root, "message_count"),
                                ContentKinds = GetString(root, "content_kinds"),
                                ArchiveDay = stem,
                            };

                            if (!string.IsNullOrEmpty(contains))
                            {
                                string haystack = $"{rec.Image} {rec.Sni} {rec.RemoteIp} {rec.Provider} {rec.Status}";
                                if (!haystack.Contains(contains, StringComparison.OrdinalIgnoreCase)) continue;
                            }
                            hits.Add(rec);
                        }
                        catch { /* truncated/corrupt line — skip, keep the file */ }
                    }
                }
            }
            catch { /* unreadable archive — partial result, never a throw */ }
            return hits;
        }

        /// <summary>(day files, bytes on disk) for the tab's status line.</summary>
        public static (int Days, long Bytes) StatusSummary()
        {
            try
            {
                if (!Directory.Exists(ArchiveDirectory)) return (0, 0);
                int days = Directory.GetFiles(ArchiveDirectory, "transmissions-*.jsonl").Length;
                long bytes = DirSize(ArchiveDirectory);
                return (days, bytes);
            }
            catch { return (0, 0); }
        }

        private static string GetString(JsonElement root, string prop) =>
            root.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        private static long GetLong(JsonElement root, string prop) =>
            root.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out long n) ? n : 0;

        private static string RemoteIpOf(string endpoint) =>
            endpoint != null && endpoint.LastIndexOf(':') > 0 ? endpoint[..endpoint.LastIndexOf(':')] : endpoint;

        private static int RemotePortOf(string endpoint) =>
            endpoint != null && endpoint.LastIndexOf(':') > 0 &&
            int.TryParse(endpoint[(endpoint.LastIndexOf(':') + 1)..], out int port) ? port : 0;
    }
}
