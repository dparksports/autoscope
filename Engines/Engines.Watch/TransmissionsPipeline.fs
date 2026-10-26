// F# port of Core\Services\TransmissionsPipelineService.cs (namespace
// AutoScope.Services) for the Engines library. Behavioral faithfulness is
// the contract: same queue, same counters, same status strings, same
// archive rule, same events (same Action<T> delegate shapes).
//
// F# port notes (deviations forced by F#/C# interop, none behavioral):
//   • Events are [<CLIEvent>] members over DelegateEvent<Action<'T>> —
//     from C# they are plain `event Action<TransmissionRecord>` and
//     subscribe with += exactly as before.
//   • The C# FlowPortHelper internal static class held ONE extension
//     method (RemotePortOrDefault); F# cannot add a static class, so the
//     extension becomes an intrinsic member on TcpFlowRecord — the
//     flow.RemotePortOrDefault() call shape is unchanged.
//   • Provider attribution went through the app's RdapService singleton
//     (Core/Services/RdapService.cs), which is NOT part of the
//     Engines.Watch port set (and owns a ProgramData\<app> cache file an
//     engine may not hardcode). It is replaced by a static, settable
//     Rdap seam implementing the two calls the pipeline made
//     (Cached / LookupAsync over a Netname/Org/Country/IsNegative entry).
//     The host app wires an adapter at startup; unwired, attribution
//     falls back to the static IpClassification ranges — the same
//     fallback the C# path takes when every RDAP answer is negative.
//   • TcpStreamCaptureService / TcpFlowRecord / SysmonConnectWatcherService
//     / SysmonConnectEvent come from the parallel Engines.Watch ports
//     (same names as the C# originals) — Capture.fs and SysmonConnect.fs
//     in fsproj order before this file.

namespace AutoScope.Engines.Watch

open System
open System.Collections.Concurrent
open System.Collections.Generic
open System.Net
open System.Runtime.InteropServices
open System.Threading
open System.Threading.Tasks
open AutoScope.Engines.Core

// ── flow port helper (C# internal static class FlowPortHelper) ─────

// F# port: the C# helper was an internal static class with ONE extension
// method (flow.RemotePortOrDefault()); F# cannot declare cross-file
// intrinsic extensions (FS0644) and the member is internal-only with a
// single caller, so it becomes a plain function on the same-named
// internal module — FlowPortHelper.RemotePortOrDefault flow.
module internal FlowPortHelper =

    let RemotePortOrDefault (flow: TcpFlowRecord) : int =
        let endpoint = flow.ServerEndpoint
        if isNull endpoint then 0
        else
            let colon = endpoint.LastIndexOf(':')
            if colon > 0 then
                match Int32.TryParse(endpoint[colon + 1..]) with
                | true, port -> port
                | _ -> 0
            else 0

// ── RDAP seam (see the port notes at the top of this file) ─────────

/// <summary>
/// The slice of an RDAP answer the pipeline's provider attribution
/// consumes (a subset of the app-side RdapService.CacheEntry).
/// </summary>
type TransmissionsRdapEntry() =
    member val Netname: string = null with get, set
    member val Org: string = null with get, set
    member val Country: string = null with get, set
    member val IsNegative = false with get, set

/// <summary>
/// Adapter interface over the host app's RDAP service; wire it into
/// TransmissionsPipelineService.Rdap at startup.
/// </summary>
type ITransmissionsRdap =
    /// <summary>Cached block containing this IP, if any (never hits network); null when nothing is cached.</summary>
    abstract Cached: ip: string -> TransmissionsRdapEntry
    /// <summary>Lookup with cache; network failures come back as negative entries, not throws.</summary>
    abstract LookupAsync: ip: string -> Task<TransmissionsRdapEntry>

// ── per-image stats (C# TransmissionsImageStats, same file) ─────────

/// <summary>Per-image counters for the "Apps without keys" suggestions:
/// how many of this image's TLS flows decrypted, how many arrived
/// encrypted with no keys, and enough about the most recent encrypted
/// one (pid + time) to recover its command line from the Sysmon archive
/// for a faithful restart-under-watch.</summary>
type TransmissionsImageStats() =
    member val Image: string = null with get, set
    member val DecryptedFlows = 0L with get, set
    member val EncryptedFlows = 0L with get, set
    member val LastEncryptedUtc = DateTime() with get, set
    member val LastEncryptedPid = 0 with get, set
    member val LastEncryptedBiggestUpload = 0L with get, set

    member this.Clone() = this.MemberwiseClone() :?> TransmissionsImageStats

// ── the pipeline ───────────────────────────────────────────────────

/// <summary>
/// The Transmissions pipeline: every finalized TCP flow from the shared
/// raw-socket capture is run through the TLS decryptor (keys from the
/// keylog the python hook and/or SSLKEYLOGFILE-supporting apps wrote),
/// the decrypted directions are decoded into HTTP messages, the row is
/// archived (metadata always when archived; full bodies when they
/// decrypted), and the UI gets an event per new row.
///
/// PID attribution is Sysmon EID 3 via this service's own connect
/// watcher feeding TagFlow — first-writer-wins, so the python tab's
/// identical tagging is harmless.
///
/// Archiving rule: a flow earns a row when it decrypted to content OR
/// when it pushed more than 10 KB upstream (the threshold this tab
/// exists for — a big upload deserves a record even when no keys
/// existed). Everything else is counted and discarded.
/// </summary>
type TransmissionsPipelineService private () as this =

    static let shared = TransmissionsPipelineService()

    let capture = TcpStreamCaptureService.Shared
    let keylog = TlsKeylogService()
    let mutable connectWatcher: SysmonConnectWatcherService = Unchecked.defaultof<_>
    let mutable worker: Thread = null
    let mutable cts: CancellationTokenSource = null
    // Recreated on every Start: CompleteAdding is permanent, so a
    // stopped-and-restarted watch needs a fresh queue.
    let mutable queue = new BlockingCollection<TcpFlowRecord>(boundedCapacity = 512)
    let mutable running = 0

    // Recent bodies kept in memory for instant viewer access; archived
    // rows fall back to disk. FIFO with a byte budget.
    let bodiesLock = obj()
    let bodyOrder = LinkedList<string * int64>()
    let bodies = Dictionary<string, byte[] * byte[]>()
    let BodyCacheBytes = 96L * 1024L * 1024L
    let mutable bodyCacheUsed = 0L

    let onRecord = DelegateEvent<Action<TransmissionRecord>>()
    let onError = DelegateEvent<Action<string>>()
    let onBigEncryptedUpload = DelegateEvent<Action<TransmissionRecord>>()

    // Stable delegate so Stop() removes exactly what Start() added.
    let onFlowFinalizedHandler = Action<TcpFlowRecord>(fun flow -> this.OnFlowFinalized flow)

    let mutable processed = 0L
    let mutable decryptedCount = 0L
    let mutable noKeys = 0L
    let mutable queueDropped = 0L

    // per-image stats (drives "Apps without keys")
    let statsLock = obj()
    let stats = Dictionary<string, TransmissionsImageStats>(StringComparer.OrdinalIgnoreCase)

    static member Shared = shared

    member _.ProcessedCount = Interlocked.Read(&processed)
    member _.DecryptedCount = Interlocked.Read(&decryptedCount)
    member _.EncryptedNoKeysCount = Interlocked.Read(&noKeys)
    member _.DroppedCount = Interlocked.Read(&queueDropped)
    member _.LiveQueueDepth = queue.Count

    member _.IsRunning = Volatile.Read(&running) = 1

    /// <summary>
    /// Every &gt;10KB upload that arrived encrypted with no keys — one
    /// event per flow, deliberately unthrottled. The ignore-list filter
    /// and any pacing live on the consumer (the view), not here: the
    /// pipeline reports, it does not decide.
    /// </summary>
    [<CLIEvent>]
    member _.OnBigEncryptedUpload = onBigEncryptedUpload.Publish

    [<CLIEvent>]
    member _.OnRecord = onRecord.Publish

    [<CLIEvent>]
    member _.OnError = onError.Publish

    /// <summary>
    /// RDAP attribution seam — see the port notes at the top of this
    /// file. Assign an ITransmissionsRdap adapter at app startup; null
    /// (the default) keeps attribution on the static IpClassification
    /// ranges only.
    /// </summary>
    static member val Rdap: ITransmissionsRdap = Unchecked.defaultof<ITransmissionsRdap> with get, set

    member _.Start() =
        if Interlocked.Exchange(&running, 1) = 1 then ()
        else
            queue <- new BlockingCollection<TcpFlowRecord>(boundedCapacity = 512)
            cts <- new CancellationTokenSource()

            TlsKeylogService.EnsureHygiene()

            connectWatcher <- new SysmonConnectWatcherService()
            // F# port: the parallel port declares these as [<CLIEvent>]
            // Action<T> events; F# consumes CLI events of non-standard
            // delegate shape through their explicit add_/remove_ accessors
            // (FS1091) — from C# these are still plain += events.
            connectWatcher.add_OnError(Action<string>(fun e -> onError.Trigger [| box e |]))
            connectWatcher.add_OnConnect(Action<SysmonConnectEvent>(fun evt -> this.OnConnect evt))
            connectWatcher.Start()

            capture.add_OnFlowFinalized onFlowFinalizedHandler // balanced by Stop() — the raw socket runs while the pipeline does
            capture.AddRef()

            worker <- new Thread(ThreadStart(fun () -> this.ProcessQueue()),
                                 IsBackground = true, Name = "TransmissionsPipeline")
            worker.Start()

    member _.Stop() =
        if Interlocked.Exchange(&running, 0) = 0 then ()
        else
            capture.remove_OnFlowFinalized onFlowFinalizedHandler
            (if not (isNull (box connectWatcher)) then connectWatcher.Stop())
            connectWatcher <- Unchecked.defaultof<_>
            capture.Release()

            queue.CompleteAdding()
            (try (if not (isNull worker) then worker.Join(TimeSpan.FromSeconds 3.0) |> ignore) with _ -> ())
            (if not (isNull cts) then cts.Cancel())

    member private _.OnConnect(evt: SysmonConnectEvent) =
        if not evt.IsTcp then ()
        else capture.TagFlow(evt.SourceIp, evt.SourcePort, evt.DestIp, evt.DestPort, evt.Pid, evt.Image) |> ignore

    member private _.OnFlowFinalized(flow: TcpFlowRecord) =
        // Raised on capture threads — enqueue or drop, never block.
        if not (TransmissionsPipelineService.IsInteresting flow) then ()
        elif not (queue.TryAdd flow) then
            Interlocked.Increment(&queueDropped) |> ignore // queue full: capture outpaces decryption

    /// <summary>TLS-shaped flows only: a handshake record at the head of
    /// the client direction, or a classic TLS port when the head is
    /// missing (mid-stream capture still decrypts nothing, but the row
    /// documents an encrypted conversation).</summary>
    static member private IsInteresting(flow: TcpFlowRecord) : bool =
        if isNull (box flow) || isNull flow.ClientData || flow.ClientData.Length < 5 then false
        elif flow.ClientData[0] = 0x16uy && flow.ClientData[1] = 0x03uy then true // TLS handshake
        else
            match FlowPortHelper.RemotePortOrDefault flow with
            | 443 | 8443 | 853 -> true
            | _ -> false

    member private _.ProcessQueue() =
        try
            for flow in queue.GetConsumingEnumerable cts.Token do
                try this.Process flow
                with _ -> () // one flow's failure never stops the pipeline
        with
        | :? OperationCanceledException -> ()
        | _ -> () // shutdown race

    member private this.Process(flow: TcpFlowRecord) =
        Interlocked.Increment(&processed) |> ignore

        let remoteIp = TransmissionsPipelineService.RemoteIpOf flow.ServerEndpoint
        let remotePort = TransmissionsPipelineService.RemotePortOf flow.ServerEndpoint

        keylog.Refresh()
        let result = TlsDecryptor.Decrypt(flow, keylog)

        let decrypted = result.Success
        let mutable status =
            if decrypted then "decrypted"
            elif result.Status <> null && result.Status.Contains("No TLS handshake") then "no handshake"
            elif result.Status <> null && (result.Status.Contains("no TLS secrets") ||
                                           result.Status.Contains("Not instrumented") ||
                                           result.Status.Contains("keylogging is disabled")) then "encrypted (no keys)"
            elif result.Status <> null && result.Status.Contains("Unsupported cipher") then "unsupported cipher"
            else "undecryptable"
        if result.Truncated && not (status.Contains "truncated") then status <- status + " · truncated"

        let record =
            TransmissionRecord(
                TsUtc = (if flow.EndedUtc = DateTime() then DateTime.UtcNow else flow.EndedUtc),
                Pid = flow.Pid,
                Image = flow.Image,
                RemoteIp = remoteIp,
                RemotePort = remotePort,
                LocalEndpoint = flow.ClientEndpoint,
                Sni = result.Sni,
                TlsVersion = result.TlsVersion,
                Alpn = result.Alpn,
                CipherSuite = result.CipherSuite,
                ClientBytes = flow.ClientBytes,
                ServerBytes = flow.ServerBytes,
                ClientAppBytes = result.ClientAppBytes,
                ServerAppBytes = result.ServerAppBytes,
                Status = status)

        let mutable requestStream: byte[] = null
        let mutable responseStream: byte[] = null
        let mutable messageCount = 0
        let kinds = HashSet<string>(StringComparer.Ordinal)

        if decrypted then
            Interlocked.Increment(&decryptedCount) |> ignore
            requestStream <- TransmissionsPipelineService.ConcatAppData(result, true)
            responseStream <- TransmissionsPipelineService.ConcatAppData(result, false)

            for msg in HttpStreamDecoder.Decode(requestStream, true, result.Alpn) do
                messageCount <- messageCount + 1
                kinds.Add msg.Kind |> ignore
            for msg in HttpStreamDecoder.Decode(responseStream, false, result.Alpn) do
                messageCount <- messageCount + 1
                kinds.Add msg.Kind |> ignore
            record.MessageCount <- messageCount
            record.ContentKinds <- String.Join(", ", kinds |> Seq.filter (fun k -> k <> null))
        elif status = "encrypted (no keys)" then
            Interlocked.Increment(&noKeys) |> ignore

        // Archive rule: content, or the >10 KB upload this tab exists for.
        let worthArchiving =
            (decrypted && (requestStream.Length > 0 || responseStream.Length > 0)) ||
            record.BigUpload ||
            (status = "encrypted (no keys)" && record.BigUpload)
        if worthArchiving then
            TransmissionsArchiveService.Append(record, requestStream, responseStream) |> ignore
            if record.HasContent then this.CacheBodies(record.Id, requestStream, responseStream)
        else
            // Live-only row: viewers can still show it for this session.
            if decrypted && (requestStream.Length > 0 || responseStream.Length > 0) then
                this.CacheBodies(record.Id, requestStream, responseStream)

        this.ResolveProvider(record, remoteIp)
        this.TallyImage record
        onRecord.Trigger [| box record |]

        if record.BigUpload && status = "encrypted (no keys)" then
            onBigEncryptedUpload.Trigger [| box record |]

    // ── per-image stats (drives "Apps without keys") ──────────────────

    member internal _.TallyImage(record: TransmissionRecord) =
        lock statsLock (fun () ->
            let imageKey = if isNull record.Image then "" else record.Image
            let statsItem =
                match stats.TryGetValue imageKey with
                | true, existing -> existing
                | _ ->
                    let created = TransmissionsImageStats(Image = imageKey)
                    stats[imageKey] <- created
                    created
            if record.Decrypted then statsItem.DecryptedFlows <- statsItem.DecryptedFlows + 1L
            elif record.Status <> null && record.Status.Contains("no keys") then
                statsItem.EncryptedFlows <- statsItem.EncryptedFlows + 1L
                statsItem.LastEncryptedUtc <- record.TsUtc
                statsItem.LastEncryptedPid <- record.Pid
                statsItem.LastEncryptedBiggestUpload <- max statsItem.LastEncryptedBiggestUpload record.ClientBytes)

    /// <summary>Snapshot of per-image counts, newest-encrypted first.</summary>
    member _.GetImageStatsSnapshot() : ResizeArray<TransmissionsImageStats> =
        lock statsLock (fun () ->
            ResizeArray<TransmissionsImageStats>(
                stats.Values
                |> Seq.sortByDescending (fun s -> s.LastEncryptedUtc)
                |> Seq.map (fun s -> s.Clone())))

    /// <summary>
    /// Entry point for layer-3 intercept records (InterceptProxyService):
    /// same treatment as captured flows — HTTP decode for message
    /// counts, archive + body cache, per-image tally, UI event. Works
    /// even when the watch is off; the archive makes rows visible
    /// whenever the tab loads.
    /// </summary>
    member this.IngestIntercepted(record: TransmissionRecord, requestStream: byte[], responseStream: byte[], host: string) =
        if isNull (box record) then ()
        else
        try
            let mutable messageCount = 0
            let kinds = HashSet<string>(StringComparer.Ordinal)
            for msg in HttpStreamDecoder.Decode(requestStream, true, null) do
                messageCount <- messageCount + 1
                kinds.Add msg.Kind |> ignore
            for msg in HttpStreamDecoder.Decode(responseStream, false, null) do
                messageCount <- messageCount + 1
                kinds.Add msg.Kind |> ignore
            record.MessageCount <- messageCount
            record.ContentKinds <- String.Join(", ", kinds |> Seq.filter (fun k -> k <> null))

            if not (String.IsNullOrEmpty host) then
                match IPAddress.TryParse host with
                | true, _ ->
                    record.RemoteIp <- host
                    this.ResolveProvider(record, host)
                | _ ->
                    // Hostname: resolve in the background, then attribute.
                    Task.Run(Action(fun () ->
                        try
                            let addresses = Dns.GetHostAddresses host
                            if not (isNull addresses) && addresses.Length > 0 then
                                record.RemoteIp <- addresses[0].ToString()
                                this.ResolveProvider(record, record.RemoteIp)
                        with _ -> ())) // hostname unresolvable post-mortem — provider stays Unclassified
                    |> ignore

            TransmissionsArchiveService.Append(record, requestStream, responseStream) |> ignore
            if record.HasContent then this.CacheBodies(record.Id, requestStream, responseStream)
            this.TallyImage record
            onRecord.Trigger [| box record |]
        with _ ->
            () // An intercept row must never break the session

    static member private ConcatAppData(result: TlsDecryptResult, fromClient: bool) : byte[] =
        let parts =
            result.Records
            |> Seq.filter (fun r -> r.Decrypted && r.ContentType = "application_data" && r.FromClient = fromClient)
            |> Seq.map (fun r -> r.Data)
            |> Seq.toList
        let total = parts |> List.sumBy (fun p -> if isNull p then 0L else int64 p.Length)
        if total = 0L || total > 16L * 1024L * 1024L then Array.empty
        else
            let buffer = Array.zeroCreate<byte> (int total)
            let mutable offset = 0
            for part in parts do
                Array.Copy(part, 0, buffer, offset, part.Length)
                offset <- offset + part.Length
            buffer

    // ── provider attribution ──────────────────────────────────────────

    member private _.ResolveProvider(record: TransmissionRecord, ip: string) =
        if String.IsNullOrEmpty ip then ()
        else
        try
            let rdap = TransmissionsPipelineService.Rdap
            let cached = if isNull (box rdap) then Unchecked.defaultof<TransmissionsRdapEntry> else rdap.Cached ip
            if not (isNull (box cached)) && not cached.IsNegative &&
               (not (String.IsNullOrEmpty cached.Netname) || not (String.IsNullOrEmpty cached.Org)) then
                record.Provider <- (if isNull cached.Netname then cached.Org else cached.Netname)
                record.ProviderCountry <- cached.Country
            else
                let classified = IpClassification.Classify ip
                if classified <> "Unclassified" then record.Provider <- classified

                // Fire the network lookup; the row's provider arrives late
                // and the grid updates in place via INotifyPropertyChanged.
                if isNull (box cached) && not (isNull (box rdap)) then
                    rdap.LookupAsync(ip).ContinueWith(
                        Action<Task<TransmissionsRdapEntry>>(fun t ->
                            try
                                let entry = t.Result
                                if not (isNull (box entry)) && not entry.IsNegative &&
                                   (not (String.IsNullOrEmpty entry.Netname) || not (String.IsNullOrEmpty entry.Org)) then
                                    record.Provider <- (if isNull entry.Netname then entry.Org else entry.Netname)
                                    record.ProviderCountry <- entry.Country
                            with _ -> ()), // negative/failed lookup keeps the static classification
                        TaskScheduler.Default) |> ignore
        with _ -> () // attribution is never fatal

    // ── body cache ────────────────────────────────────────────────────

    member _.TryGetBodies(id: string, [<Out>] request: byref<byte[]>, [<Out>] response: byref<byte[]>) : bool =
        let found, pair =
            lock bodiesLock (fun () ->
                match bodies.TryGetValue id with
                | true, p -> true, p
                | _ -> false, (null, null))
        if found then
            request <- fst pair
            response <- snd pair
            true
        else
            request <- null
            response <- null
            false

    /// <summary>Loads bodies for an archived row into the live cache
    /// (from disk) so the viewer's selection path is uniform.</summary>
    member this.LoadFromArchive(record: TransmissionRecord) : struct (byte[] * byte[]) =
        let request = TransmissionsArchiveService.LoadBody(record.Id, record.ArchiveDay, "request")
        let response = TransmissionsArchiveService.LoadBody(record.Id, record.ArchiveDay, "response")
        if request <> null || response <> null then this.CacheBodies(record.Id, request, response)
        struct (request, response)

    member private _.CacheBodies(id: string, request: byte[], response: byte[]) =
        let bytes =
            (if isNull request then 0L else int64 request.Length) +
            (if isNull response then 0L else int64 response.Length)
        lock bodiesLock (fun () ->
            if bodies.ContainsKey id then
                let existing = bodyOrder |> Seq.find (fun (idIn, _) -> idIn = id)
                bodyOrder.Remove existing |> ignore
                bodyCacheUsed <- bodyCacheUsed - snd existing
            bodies[id] <- ((if isNull request then Array.empty else request),
                           (if isNull response then Array.empty else response))
            bodyOrder.AddLast((id, bytes)) |> ignore
            bodyCacheUsed <- bodyCacheUsed + bytes

            while bodyCacheUsed > BodyCacheBytes && bodyOrder.Count > 1 do
                let oldest = bodyOrder.First.Value
                bodyOrder.RemoveFirst()
                bodies.Remove(fst oldest) |> ignore
                bodyCacheUsed <- bodyCacheUsed - snd oldest)

    static member private RemoteIpOf(endpoint: string) : string =
        if endpoint <> null && endpoint.LastIndexOf(':') > 0 then endpoint[..endpoint.LastIndexOf(':') - 1]
        else endpoint

    static member private RemotePortOf(endpoint: string) : int =
        if endpoint <> null && endpoint.LastIndexOf(':') > 0 then
            match Int32.TryParse(endpoint[endpoint.LastIndexOf(':') + 1..]) with
            | true, port -> port
            | _ -> 0
        else 0
