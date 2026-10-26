// F# port of Core\Services\DnsResolutionService.cs (namespace
// AutoScope.Services). Behavioral faithfulness is the contract: same cache
// TTLs, same throttle, same queue caps, same persisted JSON shape (short
// keys "h"/"t"/"i"), same public member names — the Process Monitor and the
// BITS tab call into this.
//
// F# port notes (deviations, none behavioral beyond the cache location):
//   • C# cached to AppDomain.CurrentDomain.BaseDirectory (next to the exe);
//     engines take every path from the identity, and an installed app's
//     base directory is not writable — the two cache files now live under
//     WatchConfig.Identity.DataRoot. Same file names, same JSON, so an
//     existing cache can be carried over by hand.
//   • The C# private nested classes (CacheEntry, PersistedEntry,
//     ForwardCacheEntry, PersistedForwardEntry) are file-private top-level
//     types — F# cannot nest type declarations inside a class.
//   • Async members use the F# `task` CE; ResolveForwardAsync still returns
//     System.Threading.Tasks.Task<string[]> exactly as C# sees it.

namespace AutoScope.Engines.Watch

open System
open System.Collections.Concurrent
open System.Collections.Generic
open System.IO
open System.Net
open System.Net.Http
open System.Text.Json
open System.Threading
open System.Threading.Channels
open System.Threading.Tasks

// -----------------------------------------------------------------------
// Inner types (F# port: C# nested them inside the class; F# cannot nest
// types in a class, so they are file-private top-level — invisible outside
// the compilation unit, same effective visibility)
// -----------------------------------------------------------------------

/// <summary>Reverse-cache row: ip → (hostname, resolved-at).</summary>
type private CacheEntry(hostname: string, resolvedAt: DateTime) =

    member _.Hostname: string = hostname
    member _.ResolvedAt: DateTime = resolvedAt

    member _.IsStale(ttl: TimeSpan) : bool = (DateTime.UtcNow - resolvedAt) > ttl

// F# port: the two JSON DTOs moved into a public module — F# caps member
// accessibility to the type's visibility, so a private DTO's properties
// compile non-public and System.Text.Json would silently write {}.
// (CacheEntry/ForwardCacheEntry below are runtime-only, no reflection.)

module DnsJsonDto =

    /// <summary>Used only for JSON serialization (short keys to keep file small).</summary>
    type PersistedEntry() =
        member val H: string = null with get, set // hostname
        member val T = DateTime() with get, set // resolved-at (UTC)

    type PersistedForwardEntry() =
        member val I: string[] = null with get, set // resolved IPs (empty = negative entry)
        member val T = DateTime() with get, set // resolved-at (UTC)

type private ForwardCacheEntry(ips: string[], resolvedAt: DateTime, ttl: TimeSpan) =
    let expiresAt = resolvedAt + ttl

    member _.Ips: string[] = ips
    member _.ResolvedAt: DateTime = resolvedAt
    member _.IsStale: bool = DateTime.UtcNow >= expiresAt

/// <summary>
/// Resolves IP → hostname in the background, with:
///   • A persistent JSON cache on disk (survives app restarts)
///   • An in-memory LRU/TTL layer for fast repeated lookups
///   • Rate-limited queue so we never spam any API
///   • Live update of SvchostMonitorItem.Hostname via INotifyPropertyChanged
/// </summary>
type DnsResolutionService() as this =

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    static let dnsCacheTtl = TimeSpan.FromHours 24.

    // F# port: C# also declared a private GeoCacheTtl (24h) — dead weight,
    // never consulted by any C# branch — dropped.

    /// Minimum delay between successive ip-api.com calls (45 req/min free tier).
    static let geoApiThrottle = TimeSpan.FromMilliseconds 1400.

    /// <summary>Forward (hostname→IPs) entries are short-lived: CDN names rotate.</summary>
    static let forwardCacheTtl = TimeSpan.FromMinutes 60.

    static let forwardNegativeTtl = TimeSpan.FromMinutes 10.

    // -----------------------------------------------------------------------
    // Fields
    // -----------------------------------------------------------------------

    // ip → (hostname, resolvedAt)
    let cache = ConcurrentDictionary<string, CacheEntry>()

    // hostname → (ips, resolvedAt) — the BITS tab's "where do they connect"
    let forwardCache = ConcurrentDictionary<string, ForwardCacheEntry>()

    let forwardGate = new SemaphoreSlim(1, 1)

    // Queue of items waiting for resolution; bounded to avoid runaway growth
    let queue =
        Channel.CreateBounded<IResolvableHost>(
            BoundedChannelOptions(
                512,
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true
            )
        )

    static let http = new HttpClient(Timeout = TimeSpan.FromSeconds 5.)

    let cts = new CancellationTokenSource()
    let mutable workerTask: Task = null

    let mutable lastGeoCall = DateTime.MinValue

    do
        // C# constructor called LoadCacheFromDisk()/LoadForwardCacheFromDisk()
        this.LoadCacheFromDisk()
        this.LoadForwardCacheFromDisk()

    // F# port: was Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ...)
    // — the cache now routes under the injected data root (engines read
    // every path from the identity; the install directory is not writable).
    static member private CacheFilePath =
        Path.Combine(WatchConfig.Identity.DataRoot, "dns_cache.json")

    static member private ForwardCacheFilePath =
        Path.Combine(WatchConfig.Identity.DataRoot, "dns_forward_cache.json")

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// <summary>Starts the background resolution worker.</summary>
    member _.Start() : unit =
        workerTask <- Task.Run(fun () -> this.WorkerLoopAsync cts.Token)

    /// <summary>
    /// Returns the cached hostname for <c>ip</c> synchronously, or null if
    /// not yet resolved.
    /// </summary>
    member _.GetCachedHostname(ip: string) : string =
        let mutable entry = Unchecked.defaultof<CacheEntry>

        match cache.TryGetValue(ip, &entry) with
        | true when not (entry.IsStale dnsCacheTtl) -> entry.Hostname
        | _ -> null

    /// <summary>
    /// Resolves <c>item</c>.RemoteIp → Hostname asynchronously. If a fresh
    /// cache entry exists, the item is updated immediately on the calling
    /// thread; otherwise it is queued for background resolution and the
    /// DataGrid row will update itself via INotifyPropertyChanged.
    /// </summary>
    member _.EnqueueForResolution(item: IResolvableHost) : unit =
        if not (isNull (box item)) && not (String.IsNullOrEmpty item.RemoteIp) then
            // Already has a real hostname
            if DnsResolutionService.IsUnresolvedHostname item.Hostname then
                // Check cache first — update immediately if fresh
                let mutable entry = Unchecked.defaultof<CacheEntry>

                match cache.TryGetValue(item.RemoteIp, &entry) with
                | true when not (entry.IsStale dnsCacheTtl) -> item.Hostname <- entry.Hostname
                | _ ->
                    // Otherwise push to background queue (drops silently if full)
                    queue.Writer.TryWrite item |> ignore

    /// <summary>
    /// Pre-seeds the cache with a Sysmon-provided hostname (already resolved
    /// at event time).
    /// </summary>
    member _.SeedFromSysmon(ip: string, hostname: string) : unit =
        if
            not (String.IsNullOrEmpty ip)
            && not (String.IsNullOrEmpty hostname)
            && hostname <> "-"
        then
            cache.[ip] <- CacheEntry(hostname, DateTime.UtcNow)

    // C# had `public void Dispose()` — public here too, with the explicit
    // IDisposable implementation delegating to it.
    member _.Dispose() : unit =
        cts.Cancel()
        queue.Writer.TryComplete() |> ignore

        (if not (isNull workerTask) then
             workerTask.Wait(TimeSpan.FromSeconds 3.) |> ignore)

        this.SaveCacheToDisk()
        this.SaveForwardCacheToDisk()
        cts.Dispose()

    interface IDisposable with
        member this.Dispose() = this.Dispose()

    // -----------------------------------------------------------------------
    // Forward resolution (hostname → IPs) — used by the BITS tab to turn
    // a job's URL host into the IPs it actually connects from. Cached
    // with a short TTL because CDN names rotate; failed lookups are
    // negative-cached briefly so a dead resolver can't spin the loop.
    // -----------------------------------------------------------------------

    member _.ResolveForwardAsync(host: string) : Task<string[]> =
        task {
            if String.IsNullOrEmpty host || (IPAddress.TryParse host |> fst) then
                return [| host |]
            else
                let mutable cached = Unchecked.defaultof<ForwardCacheEntry>

                match forwardCache.TryGetValue(host, &cached) with
                | true when not cached.IsStale -> return cached.Ips
                | _ ->
                    do! forwardGate.WaitAsync()

                    try
                        let mutable second = Unchecked.defaultof<ForwardCacheEntry>

                        match forwardCache.TryGetValue(host, &second) with
                        | true when not second.IsStale ->
                            return second.Ips // resolved while waiting on the gate
                        | _ ->
                            let mutable ips: string[] = [||]

                            try
                                let! entry = Dns.GetHostEntryAsync host

                                ips <-
                                    entry.AddressList
                                    |> Array.filter (fun a ->
                                        a.AddressFamily = Sockets.AddressFamily.InterNetwork
                                        || a.AddressFamily = Sockets.AddressFamily.InterNetworkV6)
                                    |> Array.map (fun a -> a.ToString())
                                    |> Array.distinct
                                    |> Array.truncate 6
                            with _ -> () // NXDOMAIN / no resolver answer — negative cache below

                            forwardCache.[host] <-
                                ForwardCacheEntry(
                                    ips,
                                    DateTime.UtcNow,
                                    (if ips.Length = 0 then forwardNegativeTtl else forwardCacheTtl)
                                )

                            if forwardCache.Count % 10 = 0 then this.SaveForwardCacheToDisk ()

                            return ips
                    finally
                        forwardGate.Release() |> ignore
        }

    member private _.LoadForwardCacheFromDisk() : unit =
        try
            if File.Exists DnsResolutionService.ForwardCacheFilePath then
                let dict =
                    JsonSerializer.Deserialize<Dictionary<string, DnsJsonDto.PersistedForwardEntry>>(
                        File.ReadAllText DnsResolutionService.ForwardCacheFilePath
                    )

                if not (isNull dict) then
                    for kv in dict do
                        let entry =
                            ForwardCacheEntry(
                                (if isNull kv.Value.I then [||] else kv.Value.I),
                                kv.Value.T,
                                (if
                                    isNull kv.Value.I
                                    || kv.Value.I.Length = 0
                                 then forwardNegativeTtl
                                 else forwardCacheTtl)
                            )

                        if not entry.IsStale then forwardCache.[kv.Key] <- entry
        with _ -> () // corrupt or missing file — start fresh

    member private _.SaveForwardCacheToDisk() : unit =
        try
            let dict = Dictionary<string, DnsJsonDto.PersistedForwardEntry>(forwardCache.Count)

            for kv in forwardCache do
                dict.[kv.Key] <- DnsJsonDto.PersistedForwardEntry(I = kv.Value.Ips, T = kv.Value.ResolvedAt)

            File.WriteAllText(
                DnsResolutionService.ForwardCacheFilePath,
                JsonSerializer.Serialize(dict, JsonSerializerOptions(WriteIndented = false))
            )
        with _ -> () // disk full, permissions — silently skip

    // -----------------------------------------------------------------------
    // Background worker — processes one item at a time
    // -----------------------------------------------------------------------

    member private _.WorkerLoopAsync(ct: CancellationToken) : Task =
        task {
            // F# port: C#'s `await foreach` + break/continue written as a
            // manual enumerator loop — F# has no break, and the C# flow
            // exits on the cancellation flag, on OperationCanceledException
            // and at channel completion.
            let mutable keepGoing = true
            let reader = queue.Reader.ReadAllAsync(ct).GetAsyncEnumerator ct

            try
                while keepGoing do
                    let! moved = reader.MoveNextAsync().AsTask()

                    if not moved then keepGoing <- false
                    else
                        let item = reader.Current

                        if ct.IsCancellationRequested then keepGoing <- false
                        elif not (DnsResolutionService.IsUnresolvedHostname item.Hostname) then
                            () // resolved by another path
                        else
                            try
                                let! hostname = this.ResolveAsync(item.RemoteIp, ct)
                                // triggers INotifyPropertyChanged → DataGrid refresh
                                item.Hostname <- hostname
                            with
                            | :? OperationCanceledException -> keepGoing <- false
                            | _ -> () // silently skip failed items
            finally
                // F# port: `await foreach` disposes the enumerator in a
                // finally; the channel enumerator's DisposeAsync completes
                // synchronously, so this blocking await is equivalent.
                reader.DisposeAsync().AsTask().GetAwaiter().GetResult()

            this.SaveCacheToDisk ()
        }

    // -----------------------------------------------------------------------
    // Resolution pipeline: reverse DNS → geo-IP fallback
    // -----------------------------------------------------------------------

    member private _.ResolveAsync(ip: string, ct: CancellationToken) : Task<string> =
        task {
            // 1. Return fresh cache hit
            let mutable cached = Unchecked.defaultof<CacheEntry>

            if
                cache.TryGetValue(ip, &cached)
                && not (cached.IsStale dnsCacheTtl)
            then
                return cached.Hostname
            else
                // 2. Reverse DNS
                let! resolved = DnsResolutionService.ReversesDnsAsync ip

                // 3. If DNS only gave us the raw IP, try geo-IP (rate-limited)
                let mutable resolved = resolved

                if resolved = ip || DnsResolutionService.IsUnresolvedHostname resolved then
                    let! geoLabel = this.GeoIpLookupAsync(ip, ct)

                    if not (String.IsNullOrEmpty geoLabel) then resolved <- geoLabel

                // 4. Store in cache (even failed lookups, so we don't retry immediately)
                cache.[ip] <- CacheEntry(resolved, DateTime.UtcNow)

                // 5. Periodically persist to disk (every 20 resolutions)
                if cache.Count % 20 = 0 then this.SaveCacheToDisk ()

                return resolved
        }

    static member private ReversesDnsAsync(ip: string) : Task<string> =
        task {
            try
                let! entry = Dns.GetHostEntryAsync ip
                return if String.IsNullOrEmpty entry.HostName then ip else entry.HostName
            with _ ->
                return ip // DNS NXDOMAIN or timeout
        }

    member private _.GeoIpLookupAsync(ip: string, ct: CancellationToken) : Task<string> =
        task {
            // Enforce throttle between successive API calls
            let elapsed = DateTime.UtcNow - lastGeoCall

            if elapsed < geoApiThrottle then do! Task.Delay(geoApiThrottle - elapsed, ct)

            lastGeoCall <- DateTime.UtcNow

            try
                let url =
                    $"http://ip-api.com/json/{Uri.EscapeDataString ip}?fields=status,org,countryCode"

                let! json = http.GetStringAsync(url, ct)

                use doc = JsonDocument.Parse json
                let root = doc.RootElement

                let statusOk =
                    match root.TryGetProperty("status") with
                    | true, status -> status.GetString() = "success"
                    | _ -> false

                if not statusOk then
                    return String.Empty
                else
                    let org =
                        match root.TryGetProperty("org") with
                        | true, o ->
                            match o.GetString() with
                            | null -> ""
                            | s -> s
                        | _ -> ""

                    let mutable code =
                        match root.TryGetProperty("countryCode") with
                        | true, c ->
                            match c.GetString() with
                            | null -> ""
                            | s -> s
                        | _ -> ""

                    // Strip "AS12345 " prefix
                    let mutable org = org

                    if
                        org.Length > 3
                        && org.[0] = 'A'
                        && org.[1] = 'S'
                    then
                        let space = org.IndexOf ' '

                        if space > 0 then org <- org[(space + 1) ..]

                    if String.IsNullOrEmpty code then
                        return org
                    else
                        return $"{org} · {code}"
            with
            | :? OperationCanceledException ->
                return! Task.FromException<string>(OperationCanceledException ct)
            | _ ->
                return String.Empty
        }

    // -----------------------------------------------------------------------
    // Disk persistence  (simple JSON: { "ip": { "h": "host", "t": "utc" } })
    // -----------------------------------------------------------------------

    member private _.LoadCacheFromDisk() : unit =
        try
            if File.Exists DnsResolutionService.CacheFilePath then
                let json = File.ReadAllText DnsResolutionService.CacheFilePath

                let dict =
                    JsonSerializer.Deserialize<Dictionary<string, DnsJsonDto.PersistedEntry>>(json)

                if not (isNull dict) then
                    for kv in dict do
                        let entry = CacheEntry(kv.Value.H, kv.Value.T)

                        // Only load entries that are still within TTL
                        if not (entry.IsStale dnsCacheTtl) then cache.[kv.Key] <- entry
        with _ -> () // corrupt or missing file — start fresh

    member private _.SaveCacheToDisk() : unit =
        try
            let dict = Dictionary<string, DnsJsonDto.PersistedEntry>(cache.Count)

            for kv in cache do
                dict.[kv.Key] <- DnsJsonDto.PersistedEntry(H = kv.Value.Hostname, T = kv.Value.ResolvedAt)

            let json =
                JsonSerializer.Serialize(dict, JsonSerializerOptions(WriteIndented = false))

            File.WriteAllText(DnsResolutionService.CacheFilePath, json)
        with _ -> () // disk full, permissions, etc. — silently skip

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// True when the hostname value is effectively unresolved (raw IP or empty).
    /// </summary>
    static member IsUnresolvedHostname(hostname: string) : bool =
        if String.IsNullOrEmpty hostname then true
        elif hostname = "Unknown" || hostname = "-" then true
        else
            // Looks like a raw IPv4 address
            IPAddress.TryParse hostname |> fst

    member _.CacheCount: int = cache.Count
