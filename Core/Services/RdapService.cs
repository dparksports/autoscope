using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace AutoScope.Services
{
    /// <summary>
    /// RDAP client with a persistent, block-keyed cache.
    ///
    /// Why cache by REGISTERED BLOCK, not per-IP: an RDAP response describes the
    /// whole allocated range (e.g. 20.0.0.0/8's sub-block), so one lookup answers
    /// every sibling IP in that range. That keeps the cache tiny (hundreds of
    /// entries cover effectively all recurring Windows traffic) and lookups
    /// rare — which also keeps us friendly to registry rate limits.
    ///
    /// Cache file: C:\ProgramData\AutoScope\rdap-cache.json (machine-wide, so
    /// future CLI tools — e.g. SvchostAnalyzer --rdap — can share it).
    /// TTL: respects the server's Cache-Control max-age when present, else 7
    /// days (registration data changes slowly). Failed lookups are negative-
    /// cached for 6 hours so a flaky network doesn't hammer the registries.
    /// </summary>
    public class RdapService
    {
        public class CacheEntry
        {
            public string StartIp { get; set; }
            public string EndIp { get; set; }
            public string QueryIp { get; set; }
            public string Netname { get; set; }
            public string Org { get; set; }
            public string Country { get; set; }
            public string Type { get; set; }
            public string AbuseEmail { get; set; }
            public bool IsNegative { get; set; }
            public DateTime FetchedUtc { get; set; }
            public DateTime ExpiresUtc { get; set; }
            public bool IsCurrent => DateTime.UtcNow < ExpiresUtc;
        }

        public static RdapService Instance { get; } = new();

        private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };
        private readonly string _cachePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "AutoScope", "rdap-cache.json");
        private readonly object _lock = new();
        private List<CacheEntry> _entries = new();
        private readonly Dictionary<string, Task<CacheEntry>> _inflight = new();

        private RdapService() => Load();

        // ── cache persistence ──────────────────────────────────────────────

        private void Load()
        {
            try
            {
                if (File.Exists(_cachePath))
                    _entries = JsonSerializer.Deserialize<List<CacheEntry>>(
                        File.ReadAllText(_cachePath)) ?? new();
            }
            catch { _entries = new(); }
        }

        private void Save()
        {
            try
            {
                // trim: expired entries first, then oldest — the cache covers
                // whole blocks, so 500 entries is effectively unbounded reach
                lock (_lock)
                {
                    _entries = _entries.OrderByDescending(e => e.ExpiresUtc).Take(500).ToList();
                }
                Directory.CreateDirectory(Path.GetDirectoryName(_cachePath));
                File.WriteAllText(_cachePath, JsonSerializer.Serialize(_entries,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* cache is an optimization, never fatal */ }
        }

        // ── lookup ─────────────────────────────────────────────────────────

        /// <summary>Cached block containing this IP, if any (never hits network).</summary>
        public CacheEntry Cached(string ip)
        {
            lock (_lock)
            {
                foreach (var e in _entries)
                    if (e.IsCurrent && Contains(e, ip)) return e;
                return null;
            }
        }

        /// <summary>Lookup with cache + in-flight dedup. Network failures are
        /// returned as negative entries, not thrown.</summary>
        public Task<CacheEntry> LookupAsync(string ip)
        {
            lock (_lock)
            {
                var hit = Cached(ip);
                if (hit != null) return Task.FromResult(hit);
                if (_inflight.TryGetValue(ip, out Task<CacheEntry> task)) return task;
                _inflight[ip] = task = FetchAsync(ip);
                return task;
            }
        }

        private async Task<CacheEntry> FetchAsync(string ip)
        {
            try
            {
            CacheEntry entry;
            try
            {
                using var resp = await Http.GetAsync($"https://rdap.org/ip/{ip}");
                if (!resp.IsSuccessStatusCode)
                {
                    entry = Negative(ip, $"HTTP {(int)resp.StatusCode}");
                }
                else
                {
                    entry = Parse(await resp.Content.ReadAsStringAsync(), ip) ?? Negative(ip, "unparseable response");
                    // registries send Cache-Control max-age — honor it, else 7 days
                    TimeSpan ttl = resp.Headers.CacheControl?.MaxAge ?? TimeSpan.FromDays(7);
                    entry.ExpiresUtc = DateTime.UtcNow + ttl;
                }
            }
            catch (Exception ex)
            {
                entry = Negative(ip, ex.Message);
            }

            lock (_lock)
            {
                // drop this entry's predecessor and any expired entries the new
                // positive block covers — but never let a negative result delete
                // a still-valid positive block
                _entries.RemoveAll(e => ReferenceEquals(e, entry)
                                      || (!entry.IsNegative && !e.IsNegative && Contains(entry, e.QueryIp)));
                _entries.Add(entry);
            }
            Save();
            return entry;
            }
            finally
            {
                lock (_lock) { _inflight.Remove(ip); }
            }
        }

        private static CacheEntry Negative(string ip, string why)
        {
            return new CacheEntry
            {
                QueryIp = ip, IsNegative = true, Netname = why,
                FetchedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddHours(6), // don't hammer on 404s/timeouts
            };
        }

        private static CacheEntry Parse(string json, string queryIp)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                string org = null, abuse = null;
                if (root.TryGetProperty("entities", out var entities))
                    foreach (var ent in entities.EnumerateArray())
                    {
                        var roles = ent.TryGetProperty("roles", out var r)
                            ? r.EnumerateArray().Select(x => x.GetString()).ToList() : new List<string>();
                        var fn = VcardValue(ent, "fn");
                        if (roles.Contains("registrant")) org ??= fn;
                        if (roles.Contains("abuse"))
                        {
                            abuse ??= VcardValue(ent, "email");
                            if (fn != null && abuse == null) abuse = fn;
                        }
                    }
                return new CacheEntry
                {
                    QueryIp = queryIp,
                    StartIp = GetString(root, "startAddress"),
                    EndIp = GetString(root, "endAddress"),
                    Netname = GetString(root, "name"),
                    Country = GetString(root, "country"),
                    Type = GetString(root, "type"),
                    Org = org,
                    AbuseEmail = abuse,
                    FetchedUtc = DateTime.UtcNow,
                };
            }
            catch { return null; }
        }

        private static string VcardValue(JsonElement entity, string key)
        {
            try
            {
                if (entity.TryGetProperty("vcardArray", out var va) && va.GetArrayLength() > 1)
                    foreach (var field in va[1].EnumerateArray())
                        if (field.GetArrayLength() > 3 && field[0].GetString() == key)
                            return field[3].GetString();
            }
            catch { }
            return null;
        }

        private static string GetString(JsonElement e, string prop) =>
            e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        /// <summary>True when the entry's start–end range contains the IP (v4 and v6).</summary>
        private static bool Contains(CacheEntry e, string ip)
        {
            if (string.IsNullOrEmpty(e.StartIp) || string.IsNullOrEmpty(e.EndIp)) return false;
            try
            {
                // negative entries have no range — only match their exact query IP
                if (e.IsNegative) return string.Equals(e.QueryIp, ip, StringComparison.OrdinalIgnoreCase);
                byte[] lo = IPAddress.Parse(e.StartIp).GetAddressBytes();
                byte[] hi = IPAddress.Parse(e.EndIp).GetAddressBytes();
                byte[] v = IPAddress.Parse(ip).GetAddressBytes();
                if (lo.Length != v.Length) return false;
                int cmpLo = Compare(v, lo), cmpHi = Compare(v, hi);
                return cmpLo >= 0 && cmpHi <= 0;
            }
            catch { return false; }
        }

        private static int Compare(byte[] a, byte[] b)
        {
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
            return 0;
        }

        public string CachePath => _cachePath;
        public int EntryCount { get { lock (_lock) { return _entries.Count; } } }
    }
}
