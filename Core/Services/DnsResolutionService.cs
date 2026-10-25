using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// Resolves IP → hostname in the background, with:
    ///   • A persistent JSON cache on disk (survives app restarts)
    ///   • An in-memory LRU/TTL layer for fast repeated lookups
    ///   • Rate-limited queue so we never spam any API
    ///   • Live update of SvchostMonitorItem.Hostname via INotifyPropertyChanged
    /// </summary>
    public sealed class DnsResolutionService : IDisposable
    {
        // -----------------------------------------------------------------------
        // Constants
        // -----------------------------------------------------------------------

        private static readonly TimeSpan DnsCacheTtl   = TimeSpan.FromHours(24);
        private static readonly TimeSpan GeoCacheTtl   = TimeSpan.FromHours(24);

        /// <summary>Minimum delay between successive ip-api.com calls (45 req/min free tier).</summary>
        private static readonly TimeSpan GeoApiThrottle = TimeSpan.FromMilliseconds(1_400);

        private static readonly string CacheFilePath =
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "dns_cache.json");

        private static readonly string ForwardCacheFilePath =
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "dns_forward_cache.json");

        /// <summary>Forward (hostname→IPs) entries are short-lived: CDN names rotate.</summary>
        private static readonly TimeSpan ForwardCacheTtl = TimeSpan.FromMinutes(60);
        private static readonly TimeSpan ForwardNegativeTtl = TimeSpan.FromMinutes(10);

        // -----------------------------------------------------------------------
        // Fields
        // -----------------------------------------------------------------------

        // ip → (hostname, resolvedAt)
        private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();

        // hostname → (ips, resolvedAt) — the BITS tab's "where do they connect"
        private readonly ConcurrentDictionary<string, ForwardCacheEntry> _forwardCache = new();
        private readonly SemaphoreSlim _forwardGate = new(1, 1);

        // Queue of items waiting for resolution; bounded to avoid runaway growth
        private readonly Channel<IResolvableHost> _queue =
            Channel.CreateBounded<IResolvableHost>(new BoundedChannelOptions(512)
            {
                FullMode    = BoundedChannelFullMode.DropOldest,
                SingleReader = true
            });

        private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };

        private readonly CancellationTokenSource _cts = new();
        private Task _workerTask;

        private DateTime _lastGeoCall = DateTime.MinValue;

        // -----------------------------------------------------------------------
        // Public API
        // -----------------------------------------------------------------------

        public DnsResolutionService()
        {
            LoadCacheFromDisk();
            LoadForwardCacheFromDisk();
        }

        /// <summary>Starts the background resolution worker.</summary>
        public void Start()
        {
            _workerTask = Task.Run(() => WorkerLoopAsync(_cts.Token));
        }

        /// <summary>
        /// Returns the cached hostname for <paramref name="ip"/> synchronously,
        /// or null if not yet resolved.
        /// </summary>
        public string GetCachedHostname(string ip)
        {
            if (_cache.TryGetValue(ip, out var entry) && !entry.IsStale(DnsCacheTtl))
                return entry.Hostname;
            return null;
        }

        /// <summary>
        /// Resolves <paramref name="item"/>.RemoteIp → Hostname asynchronously.
        /// If a fresh cache entry exists, the item is updated immediately on the
        /// calling thread; otherwise it is queued for background resolution and
        /// the DataGrid row will update itself via INotifyPropertyChanged.
        /// </summary>
        public void EnqueueForResolution(IResolvableHost item)
        {
            if (item == null || string.IsNullOrEmpty(item.RemoteIp)) return;

            // Already has a real hostname
            if (!IsUnresolvedHostname(item.Hostname)) return;

            // Check cache first — update immediately if fresh
            if (_cache.TryGetValue(item.RemoteIp, out var entry) && !entry.IsStale(DnsCacheTtl))
            {
                item.Hostname = entry.Hostname;
                return;
            }

            // Otherwise push to background queue (drops silently if full)
            _queue.Writer.TryWrite(item);
        }

        /// <summary>
        /// Pre-seeds the cache with a Sysmon-provided hostname (already resolved at event time).
        /// </summary>
        public void SeedFromSysmon(string ip, string hostname)
        {
            if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(hostname) || hostname == "-") return;
            _cache[ip] = new CacheEntry(hostname, DateTime.UtcNow);
        }

        public void Dispose()
        {
            _cts.Cancel();
            _queue.Writer.TryComplete();
            _workerTask?.Wait(TimeSpan.FromSeconds(3));
            SaveCacheToDisk();
            SaveForwardCacheToDisk();
            _cts.Dispose();
        }

        // -----------------------------------------------------------------------
        // Forward resolution (hostname → IPs) — used by the BITS tab to turn
        // a job's URL host into the IPs it actually connects from. Cached
        // with a short TTL because CDN names rotate; failed lookups are
        // negative-cached briefly so a dead resolver can't spin the loop.
        // -----------------------------------------------------------------------

        public async Task<string[]> ResolveForwardAsync(string host)
        {
            if (string.IsNullOrEmpty(host) || IPAddress.TryParse(host, out _)) return new[] { host };

            if (_forwardCache.TryGetValue(host, out var cached) && !cached.IsStale)
                return cached.Ips;

            await _forwardGate.WaitAsync();
            try
            {
                if (_forwardCache.TryGetValue(host, out var second) && !second.IsStale)
                    return second.Ips;   // resolved while waiting on the gate

                string[] ips = Array.Empty<string>();
                try
                {
                    var entry = await Dns.GetHostEntryAsync(host);
                    ips = entry.AddressList
                        .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                                 || a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        .Select(a => a.ToString())
                        .Distinct()
                        .Take(6)
                        .ToArray();
                }
                catch { /* NXDOMAIN / no resolver answer — negative cache below */ }

                _forwardCache[host] = new ForwardCacheEntry(ips, DateTime.UtcNow,
                    ips.Length == 0 ? ForwardNegativeTtl : ForwardCacheTtl);
                if (_forwardCache.Count % 10 == 0) SaveForwardCacheToDisk();
                return ips;
            }
            finally { _forwardGate.Release(); }
        }

        private void LoadForwardCacheFromDisk()
        {
            try
            {
                if (!File.Exists(ForwardCacheFilePath)) return;
                var dict = JsonSerializer.Deserialize<Dictionary<string, PersistedForwardEntry>>(
                    File.ReadAllText(ForwardCacheFilePath));
                if (dict == null) return;
                foreach (var kv in dict)
                {
                    var entry = new ForwardCacheEntry(kv.Value.I ?? Array.Empty<string>(), kv.Value.T,
                        kv.Value.I?.Length == 0 ? ForwardNegativeTtl : ForwardCacheTtl);
                    if (!entry.IsStale) _forwardCache[kv.Key] = entry;
                }
            }
            catch { /* corrupt or missing file — start fresh */ }
        }

        private void SaveForwardCacheToDisk()
        {
            try
            {
                var dict = new Dictionary<string, PersistedForwardEntry>(_forwardCache.Count);
                foreach (var kv in _forwardCache)
                    dict[kv.Key] = new PersistedForwardEntry { I = kv.Value.Ips, T = kv.Value.ResolvedAt };
                File.WriteAllText(ForwardCacheFilePath,
                    JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = false }));
            }
            catch { /* disk full, permissions — silently skip */ }
        }

        // -----------------------------------------------------------------------
        // Background worker — processes one item at a time
        // -----------------------------------------------------------------------

        private async Task WorkerLoopAsync(CancellationToken ct)
        {
            await foreach (var item in _queue.Reader.ReadAllAsync(ct))
            {
                if (ct.IsCancellationRequested) break;
                if (!IsUnresolvedHostname(item.Hostname)) continue; // resolved by another path

                try
                {
                    string hostname = await ResolveAsync(item.RemoteIp, ct);
                    item.Hostname = hostname; // triggers INotifyPropertyChanged → DataGrid refresh
                }
                catch (OperationCanceledException) { break; }
                catch { /* silently skip failed items */ }
            }

            SaveCacheToDisk();
        }

        // -----------------------------------------------------------------------
        // Resolution pipeline: reverse DNS → geo-IP fallback
        // -----------------------------------------------------------------------

        private async Task<string> ResolveAsync(string ip, CancellationToken ct)
        {
            // 1. Return fresh cache hit
            if (_cache.TryGetValue(ip, out var cached) && !cached.IsStale(DnsCacheTtl))
                return cached.Hostname;

            // 2. Reverse DNS
            string resolved = await ReversesDnsAsync(ip);

            // 3. If DNS only gave us the raw IP, try geo-IP (rate-limited)
            if (resolved == ip || IsUnresolvedHostname(resolved))
            {
                string geoLabel = await GeoIpLookupAsync(ip, ct);
                if (!string.IsNullOrEmpty(geoLabel))
                    resolved = geoLabel;
            }

            // 4. Store in cache (even failed lookups, so we don't retry immediately)
            _cache[ip] = new CacheEntry(resolved, DateTime.UtcNow);

            // 5. Periodically persist to disk (every 20 resolutions)
            if (_cache.Count % 20 == 0)
                SaveCacheToDisk();

            return resolved;
        }

        private static async Task<string> ReversesDnsAsync(string ip)
        {
            try
            {
                var entry = await Dns.GetHostEntryAsync(ip);
                return string.IsNullOrEmpty(entry.HostName) ? ip : entry.HostName;
            }
            catch
            {
                return ip; // DNS NXDOMAIN or timeout
            }
        }

        private async Task<string> GeoIpLookupAsync(string ip, CancellationToken ct)
        {
            // Enforce throttle between successive API calls
            var elapsed = DateTime.UtcNow - _lastGeoCall;
            if (elapsed < GeoApiThrottle)
            {
                var wait = GeoApiThrottle - elapsed;
                await Task.Delay(wait, ct);
            }

            _lastGeoCall = DateTime.UtcNow;

            try
            {
                string url = $"http://ip-api.com/json/{Uri.EscapeDataString(ip)}?fields=status,org,countryCode";
                string json = await _http.GetStringAsync(url, ct);

                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (!root.TryGetProperty("status", out var status) || status.GetString() != "success")
                    return string.Empty;

                string org  = root.TryGetProperty("org",         out var o) ? o.GetString() ?? "" : "";
                string code = root.TryGetProperty("countryCode", out var c) ? c.GetString() ?? "" : "";

                // Strip "AS12345 " prefix
                if (org.Length > 3 && org[0] == 'A' && org[1] == 'S')
                {
                    int space = org.IndexOf(' ');
                    if (space > 0) org = org[(space + 1)..];
                }

                return string.IsNullOrEmpty(code) ? org : $"{org} · {code}";
            }
            catch (OperationCanceledException) { throw; }
            catch { return string.Empty; }
        }

        // -----------------------------------------------------------------------
        // Disk persistence  (simple JSON: { "ip": { "h": "host", "t": "utc" } })
        // -----------------------------------------------------------------------

        private void LoadCacheFromDisk()
        {
            try
            {
                if (!File.Exists(CacheFilePath)) return;

                string json = File.ReadAllText(CacheFilePath);
                var dict = JsonSerializer.Deserialize<Dictionary<string, PersistedEntry>>(json);
                if (dict == null) return;

                foreach (var kv in dict)
                {
                    var entry = new CacheEntry(kv.Value.H, kv.Value.T);
                    // Only load entries that are still within TTL
                    if (!entry.IsStale(DnsCacheTtl))
                        _cache[kv.Key] = entry;
                }
            }
            catch { /* corrupt or missing file — start fresh */ }
        }

        private void SaveCacheToDisk()
        {
            try
            {
                var dict = new Dictionary<string, PersistedEntry>(_cache.Count);
                foreach (var kv in _cache)
                    dict[kv.Key] = new PersistedEntry { H = kv.Value.Hostname, T = kv.Value.ResolvedAt };

                string json = JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = false });
                File.WriteAllText(CacheFilePath, json);
            }
            catch { /* disk full, permissions, etc. — silently skip */ }
        }

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        /// <summary>True when the hostname value is effectively unresolved (raw IP or empty).</summary>
        public static bool IsUnresolvedHostname(string hostname)
        {
            if (string.IsNullOrEmpty(hostname)) return true;
            if (hostname == "Unknown" || hostname == "-") return true;
            // Looks like a raw IPv4 address
            return IPAddress.TryParse(hostname, out _);
        }

        public int CacheCount => _cache.Count;

        // -----------------------------------------------------------------------
        // Inner types
        // -----------------------------------------------------------------------

        private sealed class CacheEntry
        {
            public string   Hostname   { get; }
            public DateTime ResolvedAt { get; }

            public CacheEntry(string hostname, DateTime resolvedAt)
            {
                Hostname   = hostname;
                ResolvedAt = resolvedAt;
            }

            public bool IsStale(TimeSpan ttl) => (DateTime.UtcNow - ResolvedAt) > ttl;
        }

        // Used only for JSON serialization (short keys to keep file small)
        private sealed class PersistedEntry
        {
            public string   H { get; set; } // hostname
            public DateTime T { get; set; } // resolved-at (UTC)
        }

        private sealed class ForwardCacheEntry
        {
            public string[] Ips { get; }
            public DateTime ResolvedAt { get; }
            private readonly DateTime _expiresAt;

            public ForwardCacheEntry(string[] ips, DateTime resolvedAt, TimeSpan ttl)
            {
                Ips = ips;
                ResolvedAt = resolvedAt;
                _expiresAt = resolvedAt + ttl;
            }

            public bool IsStale => DateTime.UtcNow >= _expiresAt;
        }

        private sealed class PersistedForwardEntry
        {
            public string[]  I { get; set; } // resolved IPs (empty = negative entry)
            public DateTime  T { get; set; } // resolved-at (UTC)
        }
    }
}
