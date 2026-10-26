// F# port of four tightly-coupled Core pieces (namespaces
// AutoScope.Services / AutoScope.Models):
//   • Models\TcpFlowRecord.cs   — finalized-conversation record
//   • Models\TrafficStat.cs     — the Traffic Patterns row (INPC)
//   • Services\TcpStreamCaptureService.cs   — the TLS-decrypt capture socket
//   • Services\TrafficAggregationService.cs — folds flows into TrafficStat
// Behavioral faithfulness is the contract: same reassembly state machine
// (in-order append / out-of-order buffer / retransmit tail / head+tail
// budget), same flow keys, same JSONL persistence shape, same aggregation
// and persisted-state JSON shape (short keys), same public member names.
//
// F# port notes (deviations forced by F#, none behavioral):
//   • Models referenced only by this pipeline (TcpFlowRecord, TrafficStat,
//     and TrafficStat's nested DayTotals/Bucket) are not on the fsproj list
//     as standalone files — they live here, before their consumers.
//     DayTotals and Bucket were NESTED in TrafficStat in C#; F# cannot nest
//     types in a class, so they are top-level (Bucket internal).
//   • C# `public static readonly TrafficAggregationService Shared = new()`
//     (an eagerly-initialized field) stays a static property over a static
//     field — first touch initializes; reads unchanged.
//   • TrafficAggregationService consulted SysmonWatcherService.IsIgnoredByFile
//     (Core\Services\SysmonWatcherService.cs). SysmonWatcher.fs compiles
//     AFTER this file, so the call cannot be a type reference here — the
//     SHARED IGNORE FILE under the identity data root is the contract (the
//     same list the Process Monitor enforces), so this file carries a
//     private mirror of that file-backed check: same path
//     (DataRoot\ignored_processes.txt), same 30s TTL, same normalization.
//     The writer side belongs to SysmonWatcher.fs.
//   • The C# private nested classes (TcpFlow, TcpDirection, the persisted
//     DTOs) are file-private top-level types.
//   • `process` is an F# keyword; local variables named `process` in C#
//     became `procName`.

namespace AutoScope.Engines.Watch

open System
open System.Collections.Concurrent
open System.Collections.Generic
open System.ComponentModel
open System.IO
open System.Linq
open System.Net
open System.Net.NetworkInformation
open System.Net.Sockets
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks

// ── models ─────────────────────────────────────────────────────────

/// <summary>
/// A finalized TCP conversation: both directions' reassembled byte streams
/// (client = SYN sender), byte counts, and — when a Sysmon EID 3 connect
/// matched the flow's endpoints — the python pid/image that opened it. PID
/// attribution is by-endpoint-at-connect-time: it is the process that
/// connected with this exact 4-tuple, not a per-packet fact.
/// </summary>
type TcpFlowRecord() =
    member val Key: string = null with get, set
    member val ClientEndpoint: string = null with get, set // ip:port of the SYN sender
    member val ServerEndpoint: string = null with get, set
    member val StartedUtc = DateTime() with get, set
    member val EndedUtc = DateTime() with get, set
    member val ClientBytes: int64 = 0L with get, set
    member val ServerBytes: int64 = 0L with get, set
    member val FinBoth: bool = false with get, set
    member val Reset: bool = false with get, set

    /// <summary>True when the per-flow byte cap dropped middle bytes (head+tail kept).</summary>
    member val Truncated: bool = false with get, set

    member val Pid: int = 0 with get, set
    member val Image: string = null with get, set

    /// <summary>Reassembled client→server bytes (handshake included).</summary>
    member val ClientData: byte[] = null with get, set

    /// <summary>Reassembled server→client bytes (handshake included).</summary>
    member val ServerData: byte[] = null with get, set

    member this.Display: string =
        let up = TcpFlowRecord.FormatBytes this.ClientBytes
        let down = TcpFlowRecord.FormatBytes this.ServerBytes
        $"{this.ClientEndpoint} → {this.ServerEndpoint}  {up}↑ {down}↓"
        + (if this.Pid > 0 then $"  pid {this.Pid}" else "  unattributed")
        + (if this.Truncated then "  (truncated)" else "")

    member this.TimeDisplay: string = this.StartedUtc.ToLocalTime().ToString("HH:mm:ss")

    static member private FormatBytes(bytes: int64) : string =
        if bytes < 1024L then $"{bytes}B"
        elif bytes < 1048576L then $"{float bytes / 1024.0:F0}KB"
        else $"{float bytes / 1048576.0:F1}MB"

// F# port: was TrafficStat.DayTotals, a nested public struct. An F# struct
// cannot host member val auto-properties (the default ctor would skip
// them), so it is a CLASS here — same three properties, same JSON shape;
// usage semantics in this file are identical (mutate-then-replace and
// mutate-in-place behave the same for this flow).
type DayTotals() =
    member val Tx: int64 = 0L with get, set
    member val Rx: int64 = 0L with get, set
    member val Flows: int64 = 0L with get, set

// F# port: was TrafficStat.Bucket (nested internal struct).
/// <summary>
/// One 5-minute slot of the 24h ring; Abs is the absolute bucket index so a
/// reused slot can be told apart from a fresh one.
/// </summary>
[<Struct>]
type internal Bucket =
    val mutable Abs: int64
    val mutable Tx: int64
    val mutable Rx: int64
    val mutable Flows: int64

// F# port: the bucket constants and the JoinCapped helper were private
// statics on TrafficStat; a namespace cannot hold let-bindings, so they
// live in this internal module (reads stay TrafficStat.BucketCount /
// .BucketSpan via the static members on the class below).
module internal TrafficStatInternals =

    let BucketCount = 288 // 24h of 5-min buckets

    let BucketSpan = TimeSpan.FromMinutes 5.

    // C# TrafficStat.JoinCapped (private static): null → "—", else first 8.
    let JoinCapped(values: IEnumerable<int>) : string =
        if isNull (box values) then "—"
        else String.Join(",", values |> Seq.truncate 8)

/// <summary>
/// One aggregated (process → destination IP) row for the Traffic Patterns
/// tab: lifetime byte/flow totals plus a 24-hour ring of 5-minute buckets
/// that turns totals into a pattern — windowed rates, a sparkline, and a
/// conservative beaconing hint. Mutated by the TrafficAggregationService
/// (background thread, under Sync); display properties are recomputed by the
/// view on the UI thread via SetWindow, which is also the only place that
/// fires PropertyChanged.
/// </summary>
type TrafficStat(processName: string, destIp: string) as this =

    let propertyChanged = Event<PropertyChangedEventHandler, PropertyChangedEventArgs>()

    let pids = HashSet<int>()
    let portsSet = HashSet<int>()
    let daily = Dictionary<string, DayTotals>()
    let buckets: Bucket[] = Array.zeroCreate TrafficStatInternals.BucketCount

    let sync = obj ()

    let mutable txBytes = 0L
    let mutable rxBytes = 0L
    let mutable flows = 0L
    let mutable firstSeenUtc = DateTime()
    let mutable lastSeenUtc = DateTime()

    // Display window (view, UI thread)
    let mutable hostname: string = null
    let mutable windowIsAllTime = true
    let mutable windowTx = 0L
    let mutable windowRx = 0L
    let mutable windowFlows = 0L
    let mutable patternDisplay: string = null
    let mutable patternHint: string = null
    let mutable rateDisplay = "—"
    let mutable lastSeenDisplay: string = null
    let mutable windowSpan = TimeSpan.Zero

    static let glyphs = "▁▂▃▄▅▆▇█"

    // C# `public const int BucketCount` / `public static readonly TimeSpan
    // BucketSpan` — reads stay TrafficStat.BucketCount / .BucketSpan.
    static member BucketCount: int = TrafficStatInternals.BucketCount

    static member BucketSpan: TimeSpan = TrafficStatInternals.BucketSpan

    member _.ProcessName: string = processName
    member _.DestIp: string = destIp
    member _.Key: string = $"{processName}|{destIp}"

    member _.RemoteIp: string = destIp

    // Lifetime totals (guard with Sync)
    member _.TxBytes: int64 = txBytes
    member _.RxBytes: int64 = rxBytes
    member _.Flows: int64 = flows
    member _.FirstSeenUtc: DateTime = firstSeenUtc
    member _.LastSeenUtc: DateTime = lastSeenUtc

    // Day-over-day history (UTC date "yyyy-MM-dd" → totals), for exports
    member _.Daily: Dictionary<string, DayTotals> = daily

    /// <summary>Pids this process name was seen connecting from (capped).</summary>
    member _.Pids: IReadOnlyCollection<int> = pids :> IReadOnlyCollection<int>

    /// <summary>Destination ports seen on flows to this IP (capped).</summary>
    member _.Ports: IReadOnlyCollection<int> = portsSet :> IReadOnlyCollection<int>

    member internal _.Sync: obj = sync

    member internal _.Buckets: Bucket[] = buckets

    // -----------------------------------------------------------------------
    // Aggregation (TrafficAggregationService, background thread)
    // -----------------------------------------------------------------------

    member internal _.Add(tx: int64, rx: int64, port: int, pid: int, endedUtc: DateTime) : unit =
        lock
            sync
            (fun () ->
                txBytes <- txBytes + tx
                rxBytes <- rxBytes + rx
                flows <- flows + 1L

                if firstSeenUtc = DateTime() || endedUtc < firstSeenUtc then
                    firstSeenUtc <- endedUtc

                if endedUtc > lastSeenUtc then lastSeenUtc <- endedUtc

                if pids.Count < 32 then pids.Add pid |> ignore

                if portsSet.Count < 16 then portsSet.Add port |> ignore

                let abs = endedUtc.Ticks / TrafficStatInternals.BucketSpan.Ticks
                let slot = int (abs % int64 TrafficStatInternals.BucketCount)
                let mutable b = buckets.[slot]

                if b.Abs <> abs then b <- Unchecked.defaultof<Bucket>

                b.Abs <- abs
                b.Tx <- b.Tx + tx
                b.Rx <- b.Rx + rx
                b.Flows <- b.Flows + 1L
                buckets.[slot] <- b

                let day = endedUtc.ToString("yyyy-MM-dd")

                let mutable dayTotals =
                    match daily.TryGetValue day with
                    | true, d -> d
                    | _ -> DayTotals()

                dayTotals.Tx <- dayTotals.Tx + tx
                dayTotals.Rx <- dayTotals.Rx + rx
                dayTotals.Flows <- dayTotals.Flows + 1L
                daily.[day] <- dayTotals)

    /// <summary>Rebuilds a stat from persisted state (TrafficAggregationService.LoadState).</summary>
    member internal _.RestoreFrom(
        tx: int64,
        rx: int64,
        flowsValue: int64,
        firstUtc: DateTime,
        lastUtc: DateTime,
        pidList: IEnumerable<int>,
        portList: IEnumerable<int>,
        dailyPairs: IEnumerable<KeyValuePair<string, DayTotals>>,
        bucketList: IEnumerable<int64 * int64 * int64 * int64>
    ) : unit =
        lock
            sync
            (fun () ->
                txBytes <- tx
                rxBytes <- rx
                flows <- flowsValue
                firstSeenUtc <- firstUtc
                lastSeenUtc <- lastUtc

                for pid in pidList do
                    if pids.Count < 32 then pids.Add pid |> ignore

                for port in portList do
                    if portsSet.Count < 16 then portsSet.Add port |> ignore

                for kv in dailyPairs do
                    daily.[kv.Key] <- kv.Value

                for (bAbs, bTx, bRx, bFlows) in bucketList do
                    if bTx <= 0L && bRx <= 0L && bFlows <= 0L then
                        ()
                    else
                        let mutable slot = int (bAbs % int64 TrafficStatInternals.BucketCount)

                        if slot < 0 then slot <- slot + TrafficStatInternals.BucketCount

                        let mutable nb = Unchecked.defaultof<Bucket>
                        nb.Abs <- bAbs
                        nb.Tx <- bTx
                        nb.Rx <- bRx
                        nb.Flows <- bFlows
                        buckets.[slot] <- nb)

    /// <summary>
    /// Sums the buckets strictly after <c>sinceUtc</c> (inclusive window start).
    /// </summary>
    member internal _.SumSince(sinceUtc: DateTime) : int64 * int64 * int64 =
        let minAbs = sinceUtc.Ticks / TrafficStatInternals.BucketSpan.Ticks

        lock
            sync
            (fun () ->
                buckets
                |> Seq.fold
                    (fun (tx, rx, fl) (b: Bucket) ->
                        if b.Abs < minAbs then (tx, rx, fl)
                        else (tx + b.Tx, rx + b.Rx, fl + b.Flows))
                    (0L, 0L, 0L))

    // -----------------------------------------------------------------------
    // Display window (view, UI thread)
    // -----------------------------------------------------------------------

    /// <summary>
    /// Recomputes everything the grid shows. windowStartUtc == null → lifetime.
    /// </summary>
    member this.SetWindow(windowStartUtc: Nullable<DateTime>) : unit =
        let tx, rx, flowsValue =
            if not windowStartUtc.HasValue then
                let (a, b, c) = lock sync (fun () -> (txBytes, rxBytes, flows))

                windowIsAllTime <- true
                windowSpan <- TimeSpan.Zero
                (a, b, c)
            else
                let sums = this.SumSince windowStartUtc.Value

                windowIsAllTime <- false
                windowSpan <- DateTime.UtcNow - windowStartUtc.Value

                if windowSpan <= TimeSpan.Zero then windowSpan <- TrafficStatInternals.BucketSpan

                sums

        // Fire only what actually changed: the grid live-sorts and live-
        // filters on WindowTotal, so every event costs a reshape pass.
        if windowTx <> tx then
            windowTx <- tx
            this.OnPropertyChanged "WindowTx"
            this.OnPropertyChanged "TxDisplay"
            this.OnPropertyChanged "WindowTotal"
            this.OnPropertyChanged "TotalDisplay"

        if windowRx <> rx then
            windowRx <- rx
            this.OnPropertyChanged "WindowRx"
            this.OnPropertyChanged "RxDisplay"
            this.OnPropertyChanged "WindowTotal"
            this.OnPropertyChanged "TotalDisplay"

        if windowFlows <> flowsValue then
            windowFlows <- flowsValue
            this.OnPropertyChanged "WindowFlows"
            this.OnPropertyChanged "FlowsDisplay"

        this.ComputePattern()

        let rate =
            if windowIsAllTime || windowSpan <= TimeSpan.Zero then
                "—"
            else
                TrafficStat.FormatBytes(int64 (float windowTx / windowSpan.TotalSeconds)) + "/s ↑"

        if rateDisplay <> rate then
            rateDisplay <- rate
            this.OnPropertyChanged "RateDisplay"

        let lastSeen =
            if lastSeenUtc = DateTime() then "—"
            else lastSeenUtc.ToLocalTime().ToString("HH:mm:ss")

        if lastSeenDisplay <> lastSeen then
            lastSeenDisplay <- lastSeen
            this.OnPropertyChanged "LastSeenDisplay"

    member _.WindowTx: int64 = windowTx
    member _.WindowRx: int64 = windowRx
    member _.WindowTotal: int64 = windowTx + windowRx
    member _.WindowFlows: int64 = windowFlows
    member _.WindowIsAllTime: bool = windowIsAllTime

    member _.TxDisplay: string = TrafficStat.FormatBytes windowTx + " ↑"
    member _.RxDisplay: string = TrafficStat.FormatBytes windowRx + " ↓"
    member _.TotalDisplay: string = TrafficStat.FormatBytes (windowTx + windowRx)
    member _.FlowsDisplay: string = windowFlows.ToString("N0")
    member _.PidsDisplay: string = TrafficStatInternals.JoinCapped pids
    member _.PortsDisplay: string = TrafficStatInternals.JoinCapped portsSet
    member _.LastSeenDisplay: string = if isNull lastSeenDisplay then "—" else lastSeenDisplay

    /// <summary>Average outbound rate across the selected window (blank for all-time).</summary>
    member _.RateDisplay: string = rateDisplay

    /// <summary>Compact 24-hour sparkline of outbound bytes, one glyph per hour.</summary>
    member _.PatternDisplay: string = patternDisplay

    /// <summary>
    /// Non-empty when the last hours look beacon-like (regular cadence, similar sizes).
    /// </summary>
    member _.PatternHint: string = patternHint

    // -----------------------------------------------------------------------
    // Hostname (DnsResolutionService updates this; grid restyles via IsResolved)
    // -----------------------------------------------------------------------

    member this.Hostname
        with get (): string = hostname
        and set (value: string) = this.SetHostname value

    // F# port: setter body in a private mutator — the IResolvableHost
    // implementation must not re-enter through the interface-typed
    // self-identifier (recursion).
    member private this.SetHostname(value: string) : unit =
        if hostname <> value then
            hostname <- value
            this.OnPropertyChanged "Hostname"
            this.OnPropertyChanged "IsResolved"

    member _.IsResolved: bool =
        not (String.IsNullOrEmpty hostname)
        && hostname <> destIp
        && hostname <> "0.0.0.0"
        && hostname <> "::"

    // -----------------------------------------------------------------------
    // Pattern analysis
    // -----------------------------------------------------------------------

    member private this.ComputePattern() : unit =
        // 24 hourly sums from the tx ring, oldest → newest
        let absNow = DateTime.UtcNow.Ticks / TrafficStatInternals.BucketSpan.Ticks
        let hours = Array.zeroCreate<int64> 24

        lock
            sync
            (fun () ->
                for b in buckets do
                    if b.Tx > 0L then
                        let hoursAgo = (absNow - b.Abs) / 12L // 12 buckets per hour

                        if hoursAgo >= 0L && hoursAgo < 24L then
                            hours.[23 - int hoursAgo] <- hours.[23 - int hoursAgo] + b.Tx)

        let max = Array.max hours
        let sb = StringBuilder 24

        for h in hours do
            sb.Append(
                if h <= 0L then
                    '·'
                else
                    glyphs.[min (glyphs.Length - 1) (int (h * int64 glyphs.Length / max))]
            )
            |> ignore

        if patternDisplay <> sb.ToString() then
            patternDisplay <- sb.ToString()
            this.OnPropertyChanged "PatternDisplay"

        // Beaconing hint, evaluated on the last 2 hours of buckets: needs
        // ≥6 active buckets whose inter-bucket gaps are all equal (±1) and
        // whose per-bucket tx stays within ±60% of the mean. Deliberately
        // conservative — it suggests a look, never an accusation.
        let active = ResizeArray<int64 * int64>()

        lock
            sync
            (fun () ->
                for b in buckets do
                    if b.Tx > 0L && absNow - b.Abs < 24L then active.Add(b.Abs, b.Tx))

        active.Sort(fun (a1, _) (a2, _) -> a1.CompareTo a2)

        let mutable hint = ""

        if active.Count >= 6 then
            let gaps = active |> Seq.pairwise |> Seq.map (fun ((a1, _), (a2, _)) -> a2 - a1) |> Seq.toArray

            let regular =
                gaps |> Array.forall (fun g -> abs (g - gaps.[0]) <= 1L)
                && gaps.[0] >= 1L
                && gaps.[0] <= 12L

            let mean = active |> Seq.averageBy (fun (_, tx) -> float tx)

            let spread =
                (active |> Seq.map (fun (_, tx) -> float tx) |> Seq.max)
                - (active |> Seq.map (fun (_, tx) -> float tx) |> Seq.min)

            let similar = mean > 0.0 && spread / mean <= 1.2

            if regular && similar then
                hint <- $"⚠ beacon-like: every {gaps.[0] * 5L} min, ~{TrafficStat.FormatBytes(int64 mean)}"

        if patternHint <> hint then
            patternHint <- hint
            this.OnPropertyChanged "PatternHint"

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    static member internal FormatBytes(bytes: int64) : string =
        if bytes < 1024L then $"{bytes}B"
        elif bytes < 1048576L then $"{float bytes / 1024.0:F0}KB"
        elif bytes < 1073741824L then $"{float bytes / 1048576.0:F1}MB"
        else $"{float bytes / 1073741824.0:F2}GB"

    member private this.OnPropertyChanged(name: string) : unit =
        propertyChanged.Trigger(this, PropertyChangedEventArgs name)

    [<CLIEvent>]
    member this.PropertyChanged = propertyChanged.Publish

    interface IResolvableHost with
        member _.RemoteIp = this.RemoteIp

        member _.Hostname
            with get () = this.Hostname
            and set (value) = this.SetHostname value

    interface INotifyPropertyChanged with
        [<CLIEvent>]
        member this.PropertyChanged = propertyChanged.Publish

// ── reassembly internals (C# nested classes; file-private here) ─────

/// <summary>
/// One direction of a flow: in-order byte stream with head+tail retention
/// once the per-direction budget is exceeded (the middle is dropped and the
/// flow is flagged truncated).
/// </summary>
type private TcpDirection() =

    let mutable nextSeq: uint32 option = None
    let outOfOrder = SortedDictionary<uint32, byte[]>()
    let mutable finSent = false
    let mutable totalBytes = 0L

    let head = new MemoryStream()
    let tail = Queue<byte[]>()
    let mutable tailBytes = 0L
    let mutable truncated = false

    let mutable headBudget = 0L // 0 until EnsureBudget wires the owner's cap
    let mutable tailBudget = 0L

    member _.NextSeq
        with get (): uint32 option = nextSeq
        and set (value: uint32 option) = nextSeq <- value

    member _.OutOfOrder: SortedDictionary<uint32, byte[]> = outOfOrder

    member _.FinSent
        with get (): bool = finSent
        and set (value: bool) = finSent <- value

    member _.TotalBytes: int64 = totalBytes
    member _.Truncated: bool = truncated

    member _.EnsureBudget(totalPerDirection: int64) : unit =
        if headBudget <> 0L then ()
        else
            headBudget <- totalPerDirection * 3L / 4L
            tailBudget <- totalPerDirection - headBudget

    member _.Append(buffer: byte[], start: int, length: int) : unit =
        totalBytes <- totalBytes + int64 length

        let mutable start = start
        let mutable length = length
        let mutable spillToTail = false

        if head.Length < headBudget then
            let room = headBudget - head.Length

            if int64 length <= room then
                head.Write(buffer, start, length)
            else
                head.Write(buffer, start, int room)
                start <- start + int room
                length <- length - int room
                spillToTail <- true
        else
            spillToTail <- true

        // Head full: coalesce into ~64KB tail chunks, evicting the oldest
        if spillToTail then

            while length > 0 do
                let take = min length 65536
                let chunk: byte[] = Array.zeroCreate take
                Array.Copy(buffer, start, chunk, 0, take)
                tail.Enqueue chunk
                tailBytes <- tailBytes + int64 take
                start <- start + take
                length <- length - take

            while tailBytes > tailBudget && tail.Count > 1 do
                tailBytes <- tailBytes - int64 (tail.Peek().Length)
                tail.Dequeue() |> ignore
                truncated <- true

    member _.ToBytes() : byte[] =
        let total = head.Length + tailBytes

        if total = 0L then [||]
        else
            let result = Array.zeroCreate<byte> (int total)
            head.Position <- 0L
            head.ReadExactly(result, 0, int head.Length) |> ignore

            let mutable offset = int head.Length

            for chunk in tail do
                Array.Copy(chunk, 0, result, offset, chunk.Length)
                offset <- offset + chunk.Length

            result

/// <summary>Reassembly state for one TCP conversation (both directions).</summary>
type private TcpFlow(key: string, lowEndpoint: string, highEndpoint: string) =

    let mutable clientIp: string = null
    let mutable clientPort = 0
    let mutable hasClient = false
    let clientDir = TcpDirection() // Low  → High
    let serverDir = TcpDirection() // High → Low
    let mutable startedUtc = DateTime()
    let mutable lastSeenUtc = DateTime.UtcNow
    let mutable synSeen = false
    let mutable gracefulClose = false
    let mutable reset = false
    let mutable finalized = false
    let mutable pid = 0
    let mutable image: string = null

    member _.Key: string = key

    /// lexicographically smaller ip:port
    member _.LowEndpoint: string = lowEndpoint
    member _.HighEndpoint: string = highEndpoint

    // SYN sender (Ip, Port), learned from the first SYN — C# `(string Ip, int Port)?`.
    member _.ClientEndpoint
        with get (): string * int = (clientIp, clientPort)
        and set (value: string * int) =
            let ip, port = value
            clientIp <- ip
            clientPort <- port
            hasClient <- true

    member _.HasClient: bool = hasClient
    member _.ClientDir: TcpDirection = clientDir
    member _.ServerDir: TcpDirection = serverDir

    member _.StartedUtc
        with get (): DateTime = startedUtc
        and set (v: DateTime) = startedUtc <- v

    member _.LastSeenUtc
        with get (): DateTime = lastSeenUtc
        and set (v: DateTime) = lastSeenUtc <- v

    member _.SynSeen
        with get (): bool = synSeen
        and set (v: bool) = synSeen <- v

    member _.GracefulClose
        with get (): bool = gracefulClose
        and set (v: bool) = gracefulClose <- v

    member _.Reset
        with get (): bool = reset
        and set (v: bool) = reset <- v

    member _.Finalized
        with get (): bool = finalized
        and set (v: bool) = finalized <- v

    member _.Pid
        with get (): int = pid
        and set (v: int) = pid <- v

    member _.Image
        with get (): string = image
        and set (v: string) = image <- v

    member _.DirectionOf(fromLow: bool) : TcpDirection =
        // ClientDir carries Low→High. Until a SYN names the client, the
        // first payload direction is treated as the client.
        let lowIsClient =
            (not hasClient)
            || ($"{clientIp}:{clientPort}" = lowEndpoint)

        if fromLow = lowIsClient then clientDir
        else serverDir

    member _.ToRecord(maxBytesPerDirection: int64) : TcpFlowRecord =
        let client, server =
            if hasClient then
                let clientIsLow = ($"{clientIp}:{clientPort}" = lowEndpoint)

                (if clientIsLow then (lowEndpoint, highEndpoint) else (highEndpoint, lowEndpoint))
            else
                (lowEndpoint, highEndpoint) // no SYN seen: assume, the record says so via SynSeen

        TcpFlowRecord(
            Key = key,
            ClientEndpoint = client,
            ServerEndpoint = server,
            StartedUtc = startedUtc,
            EndedUtc = lastSeenUtc,
            ClientBytes = clientDir.TotalBytes,
            ServerBytes = serverDir.TotalBytes,
            FinBoth = (clientDir.FinSent && serverDir.FinSent),
            Reset = reset,
            Truncated = (clientDir.Truncated || serverDir.Truncated),
            Pid = pid,
            Image = image,
            ClientData = clientDir.ToBytes(),
            ServerData = serverDir.ToBytes()
        )

// ── the capture service ────────────────────────────────────────────

/// <summary>
/// Retains (instead of discarding) the TCP payloads crossing the NIC on a
/// private raw socket, reassembling each direction of every IPv4 TCP
/// conversation into byte streams the TLS decryptor can consume. This is a
/// separate socket and separate counters from the Process Monitor's
/// RawSocketSnifferService — the svchost tab is untouched.
///
/// Known gaps (by design, documented in the README): loopback traffic never
/// crosses the NIC so SIO_RCVALL never sees it; IPv6 and UDP/QUIC are out
/// of scope.
/// </summary>
type TcpStreamCaptureService() as this =

    // App-level sharing (static let must precede members in an F# class)
    static let shared = Lazy<TcpStreamCaptureService>(fun () -> TcpStreamCaptureService())

    let onError = DelegateEvent<Action<string>>()
    let onFlowFinalized = DelegateEvent<Action<TcpFlowRecord>>()

    let flows = ConcurrentDictionary<string, TcpFlow>(StringComparer.Ordinal)
    let mutable socket: Socket = null
    let mutable cts: CancellationTokenSource = null
    let mutable sweepTimer: Timer = null
    let mutable running = 0
    let mutable refs = 0

    // Direction visibility for the whole capture session. Some NIC/driver
    // combos deliver only outbound packets to a receive-all socket; when
    // that happens the UI must say "not observed" instead of letting a
    // zero read as "nothing ever came back".
    let mutable localIp: IPAddress = null
    let mutable inboundPackets = 0L
    let mutable outboundPackets = 0L
    let mutable captureMode = "off"

    // Per-flow memory discipline: head + tail retention around a dropped
    // middle once a direction exceeds its budget.
    member val MaxBytesPerDirection: int64 = 8L * 1024L * 1024L with get, set

    member val MaxConcurrentFlows: int = 4096 with get, set

    member val IdleTimeout: TimeSpan = TimeSpan.FromSeconds 60. with get, set

    member val PersistFlows: bool = false with get, set

    member val PersistDirBudgetBytes: int64 = 64L * 1024L * 1024L with get, set

    /// <summary>Capture failure surfaced to the host (elevate / retry hints).</summary>
    [<CLIEvent>]
    member _.OnError = onError.Publish

    /// <summary>Every finalized flow (already removed from the live set).</summary>
    [<CLIEvent>]
    member _.OnFlowFinalized = onFlowFinalized.Publish

    // F# port: F# cannot address the CLIEvent member itself (FS1091 on
    // non-standard delegate types) — this is the same publish view, for
    // F# subscribers (TrafficAggregationService.Attach).
    member internal _.FlowFinalized: IDelegateEvent<Action<TcpFlowRecord>> = onFlowFinalized.Publish

    /// <summary>Packets whose source was the local address (sent by this PC).</summary>
    member _.OutboundPackets: int64 = Interlocked.Read &outboundPackets

    /// <summary>Packets whose source was a remote address (replies and other inbound).</summary>
    member _.InboundPackets: int64 = Interlocked.Read &inboundPackets

    /// <summary>True once the session has seen at least one inbound packet.</summary>
    member _.InboundSeen: bool = Interlocked.Read &inboundPackets > 0L

    /// <summary>"ip-level" · "on" · "off" — which SIO_RCVALL flavor is live.</summary>
    member _.CaptureMode: string = captureMode

    member _.IsRunning: bool = running = 1

    // F# port: was %LOCALAPPDATA%\AutoScope\pytrace\flows (hardcoded) —
    // the flow dir now routes under the injected identity data root.
    static member private FlowDir =
        Path.Combine(WatchConfig.Identity.DataRoot, "pytrace", "flows")

    member _.LiveFlowCount: int = flows.Count

    // -----------------------------------------------------------------------
    // App-level sharing
    // -----------------------------------------------------------------------

    /// <summary>
    /// The app-level instance shared by every view that captures (Python
    /// Spawns, Traffic Patterns) — one raw socket instead of one per tab.
    /// Views hold it with AddRef/Release so it runs exactly while at least
    /// one of them wants it; settings like IdleTimeout are per-instance,
    /// so the last tab to load them configures the shared socket.
    /// </summary>
    static member Shared: TcpStreamCaptureService = shared.Value

    /// <summary>Reference-counted start: the first holder starts the capture.</summary>
    member _.AddRef() : unit =
        if Interlocked.Increment &refs = 1 then this.Start()

    /// <summary>Reference-counted stop: runs until the last holder releases.</summary>
    member _.Release() : unit =
        let refsNow = Interlocked.Decrement &refs

        if refsNow = 0 then this.Stop()
        elif refsNow < 0 then Interlocked.Exchange(&refs, 0) |> ignore // over-release guard

    member _.Start() : unit =
        if Interlocked.Exchange(&running, 1) = 1 then
            ()
        else
            cts <- new CancellationTokenSource()

            Task.Run(
                Action(fun () ->
                    try
                        let localIp = TcpStreamCaptureService.GetLocalIpAddress()

                        if isNull localIp then
                            onError.Trigger
                                [| box "Could not determine the local IPv4 address for TCP stream capture." |]
                        else
                            socket <- new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP)
                            socket.Bind(IPEndPoint(localIp, 0))

                            socket.SetSocketOption(
                                SocketOptionLevel.IP,
                                SocketOptionName.HeaderIncluded,
                                true
                            )

                            // RCVALL_IPLEVEL first: it captures both directions at the
                            // IP layer and, unlike RCVALL_ON, does not depend on the
                            // NIC honoring promiscuous mode (on hardware that ignores
                            // it, RCVALL_ON silently yields outbound-only captures).
                            // RCVALL_ON stays as the fallback for older stacks.
                            let ipLevel: byte[] = [| 3uy; 0uy; 0uy; 0uy |]
                            let on: byte[] = [| 1uy; 0uy; 0uy; 0uy |]

                            (try
                                 socket.IOControl(IOControlCode.ReceiveAll, ipLevel, [| 0uy; 0uy; 0uy; 0uy |]) |> ignore
                                 captureMode <- "ip-level"
                             with :? SocketException ->
                                 socket.IOControl(IOControlCode.ReceiveAll, on, [| 0uy; 0uy; 0uy; 0uy |]) |> ignore
                                 captureMode <- "on")

                            Interlocked.Exchange(&inboundPackets, 0L) |> ignore
                            Interlocked.Exchange(&outboundPackets, 0L) |> ignore
                            this.LocalIp <- localIp
                            socket.ReceiveTimeout <- 2000

                            let buffer: byte[] = Array.zeroCreate 65535

                            let mutable keepGoing =
                                not (isNull cts)
                                && not cts.Token.IsCancellationRequested

                            while keepGoing do
                                try
                                    let received = socket.Receive buffer

                                    if received >= 20 then this.ProcessIpPacket(buffer, received)
                                with :? SocketException as ex ->
                                    if
                                        ex.SocketErrorCode <> SocketError.TimedOut
                                        && ex.SocketErrorCode <> SocketError.Interrupted
                                        && ex.SocketErrorCode <> SocketError.WouldBlock
                                    then
                                        // transient NIC-level errors: keep the loop alive
                                        ()
                                keepGoing <-
                                    keepGoing
                                    && not (isNull cts)
                                    && not cts.Token.IsCancellationRequested
                    with
                    | :? SocketException as ex when ex.SocketErrorCode = SocketError.AccessDenied ->
                        // F# port: the C# string hardcoded the app name
                        // ("Run AutoScope as Administrator") — the name now
                        // comes from the injected identity.
                        onError.Trigger
                            [| box
                                $"TCP stream capture needs elevation (raw socket access denied). Run {WatchConfig.Identity.Name} as Administrator." |]
                    | :? ObjectDisposedException ->
                        // Stop() closed the socket mid-receive — normal shutdown
                        ()
                    | ex ->
                        onError.Trigger [| box $"TCP stream capture error: {ex.Message}" |]),
                cts.Token
            )
            |> ignore

            sweepTimer <-
                new Timer(
                    TimerCallback(fun _ -> this.FinalizeIdleFlows()),
                    null,
                    TimeSpan.FromSeconds 5.,
                    TimeSpan.FromSeconds 5.
                )

    member private _.LocalIp
        with get (): IPAddress = localIp
        and set (value: IPAddress) = localIp <- value

    member _.Stop() : unit =
        if Interlocked.Exchange(&running, 0) = 0 then
            ()
        else
            if not (isNull sweepTimer) then
                sweepTimer.Dispose()
                sweepTimer <- null

            if not (isNull cts) then cts.Cancel()

            if not (isNull socket) then
                socket.Close()
                socket <- null

            // Everything still open finalizes so the UI keeps what was captured
            for flow in flows.Values.ToList() do
                this.Finalize flow

            flows.Clear()

    /// <summary>
    /// Parses one IPv4 packet. Public for the offline self-test, which feeds
    /// synthetic IP/TCP buffers through the reassembler.
    /// </summary>
    member _.ProcessIpPacket(buffer: byte[], length: int) : unit =
        try
            let version = int buffer.[0] >>> 4

            if version <> 4 then ()
            else
                let ihl = (int buffer.[0] &&& 0x0F) * 4

                if ihl < 20 || length < ihl then ()
                else
                    let mutable totalLength = (int buffer.[2] <<< 8) ||| int buffer.[3]

                    if totalLength < ihl || totalLength > length then totalLength <- length

                    if int buffer.[9] <> 6 then () // TCP only
                    else
                        let srcIp = IPAddress(ReadOnlySpan<byte>(buffer, 12, 4))
                        let dstIp = IPAddress(ReadOnlySpan<byte>(buffer, 16, 4))

                        // Session-level direction tally (null local IP = offline
                        // self-test feeding synthetic buffers — nothing to count).
                        if not (isNull localIp) then
                            if srcIp.Equals localIp then Interlocked.Increment &outboundPackets |> ignore
                            else Interlocked.Increment &inboundPackets |> ignore

                        let tcpOffset = ihl

                        if tcpOffset + 20 > totalLength then ()
                        else
                            let srcPort = (int buffer.[tcpOffset] <<< 8) ||| int buffer.[tcpOffset + 1]

                            let dstPort =
                                (int buffer.[tcpOffset + 2] <<< 8) ||| int buffer.[tcpOffset + 3]

                            let seqNum =
                                uint32 (
                                    (int buffer.[tcpOffset + 4] <<< 24)
                                    ||| (int buffer.[tcpOffset + 5] <<< 16)
                                    ||| (int buffer.[tcpOffset + 6] <<< 8)
                                    ||| int buffer.[tcpOffset + 7]
                                )

                            let flags: byte = buffer.[tcpOffset + 13]
                            let dataOffset = (int buffer.[tcpOffset + 12] >>> 4) * 4

                            if dataOffset < 20 then ()
                            else
                                let payloadStart = tcpOffset + dataOffset

                                let mutable payloadLen = totalLength - payloadStart

                                if payloadLen < 0 then payloadLen <- 0

                                // F# port: C#'s GetOrCreateFlow has a dead
                                // `if (flow == null) return;` (GetOrAdd never
                                // returns null) — dropped.
                                let flow, fromLow = this.GetOrCreateFlow(srcIp, srcPort, dstIp, dstPort)

                                lock
                                    flow
                                    (fun () ->
                                        flow.LastSeenUtc <- DateTime.UtcNow

                                        let fin: byte = 0x01uy
                                        let syn: byte = 0x02uy
                                        let rst: byte = 0x04uy

                                        if (flags &&& rst) <> 0uy then flow.Reset <- true

                                        if (flags &&& syn) <> 0uy then
                                            if not flow.HasClient then
                                                flow.ClientEndpoint <- (srcIp.ToString(), srcPort)

                                            flow.SynSeen <- true

                                        if (flags &&& fin) <> 0uy then
                                            let dir = flow.DirectionOf fromLow
                                            dir.FinSent <- true

                                            if flow.ClientDir.FinSent && flow.ServerDir.FinSent then
                                                flow.GracefulClose <- true

                                        if payloadLen > 0 then
                                            let dir = flow.DirectionOf fromLow
                                            let mutable dataSeq = seqNum

                                            if
                                                (flags &&& syn) <> 0uy
                                                && dir.NextSeq.IsNone
                                            then
                                                // A SYN consumes one sequence number before its payload
                                                dir.NextSeq <- Some(seqNum + 1u)
                                                dataSeq <- seqNum + 1u

                                            this.FeedSegment(dir, dataSeq, buffer, payloadStart, payloadLen)

                                        if flow.GracefulClose || flow.Reset then this.Finalize flow)

        with _ -> () // one malformed packet never stops the capture

    /// <summary>
    /// Tags the flow matching this Sysmon EID 3 connect with the python
    /// pid/image. The first attribution wins — endpoints are unique per
    /// connect while the connection lives.
    /// </summary>
    member _.TagFlow(srcIp: string, srcPort: int, dstIp: string, dstPort: int, pid: int, image: string) : bool =
        let key = TcpStreamCaptureService.CanonicalKey(srcIp, srcPort, dstIp, dstPort)

        match flows.TryGetValue key with
        | false, _ -> false
        | true, flow ->
            lock
                flow
                (fun () ->
                    if flow.Pid <> 0 then
                        false
                    else
                        flow.Pid <- pid
                        flow.Image <- image
                        true)

    // -----------------------------------------------------------------------
    // Flow management
    // -----------------------------------------------------------------------

    member private _.GetOrCreateFlow(srcIp: IPAddress, srcPort: int, dstIp: IPAddress, dstPort: int) : TcpFlow * bool =
        let src = $"{srcIp}:{srcPort}"
        let dst = $"{dstIp}:{dstPort}"
        let low = String.CompareOrdinal(src, dst) < 0
        let key = if low then $"{src}|{dst}" else $"{dst}|{src}"

        let flow =
            flows.GetOrAdd(
                key,
                fun _ ->
                    let f = TcpFlow(key, (if low then src else dst), (if low then dst else src))
                    f.StartedUtc <- DateTime.UtcNow
                    f
            )

        if flows.Count > this.MaxConcurrentFlows then this.FinalizeIdleFlows () // cheap pressure valve: idle flows finalize first

        flow, low

    static member private CanonicalKey(srcIp: string, srcPort: int, dstIp: string, dstPort: int) : string =
        let src = $"{srcIp}:{srcPort}"
        let dst = $"{dstIp}:{dstPort}"

        let lowIsSource = String.CompareOrdinal(src, dst) < 0

        if lowIsSource then $"{src}|{dst}" else $"{dst}|{src}"

    member private _.FinalizeIdleFlows() : unit =
        try
            let now = DateTime.UtcNow

            // F# port: C# did `lock { if (flow.Finalized) return; ... }`
            // inside a foreach — an early RETURN that ends the whole sweep;
            // mirrored with a stop flag (not `continue`).
            let mutable stop = false
            let e = flows.GetEnumerator()

            try
                while (not stop) && e.MoveNext() do
                    let flow = e.Current.Value

                    lock
                        flow
                        (fun () ->
                            if flow.Finalized then stop <- true
                            elif
                                now - flow.LastSeenUtc >= this.IdleTimeout
                                || flow.GracefulClose
                                || flow.Reset
                            then
                                this.Finalize flow)
            finally
                e.Dispose()
        with _ -> () // the sweep is opportunistic

    member private _.Finalize(flow: TcpFlow) : unit =
        let removed =
            match flows.TryRemove flow.Key with
            | true, _ -> true
            | false, _ -> false

        if (not removed) && flow.Finalized then ()
        else
            flow.Finalized <- true

            let record = flow.ToRecord this.MaxBytesPerDirection

            if this.PersistFlows then this.Persist record

            onFlowFinalized.Trigger [| box record |]

    // -----------------------------------------------------------------------
    // Optional persistence (JSONL with base64 payloads, rotated by budget)
    // -----------------------------------------------------------------------

    member private _.Persist(record: TcpFlowRecord) : unit =
        try
            Directory.CreateDirectory TcpStreamCaptureService.FlowDir |> ignore

            let path =
                Path.Combine(TcpStreamCaptureService.FlowDir, $"flows-{DateTime.Now:yyyyMMdd}.jsonl")

            let entry = Dictionary<string, obj>()

            entry.["ts"] <- box record.EndedUtc
            entry.["key"] <- box record.Key
            entry.["client"] <- box record.ClientEndpoint
            entry.["server"] <- box record.ServerEndpoint
            entry.["pid"] <- box record.Pid
            entry.["image"] <- box record.Image
            entry.["client_b64"] <- box (Convert.ToBase64String(if isNull record.ClientData then [||] else record.ClientData))

            entry.["server_b64"] <- box (Convert.ToBase64String(if isNull record.ServerData then [||] else record.ServerData))

            entry.["truncated"] <- box record.Truncated

            File.AppendAllText(path, JsonSerializer.Serialize entry + Environment.NewLine)

            // Rotation: keep the newest files within the budget
            let files =
                DirectoryInfo(TcpStreamCaptureService.FlowDir)
                    .GetFiles("flows-*.jsonl")
                    .OrderByDescending(fun f -> f.Name)
                    .ToList()

            let mutable budget = this.PersistDirBudgetBytes

            for file in files do
                budget <- budget - file.Length

                if budget < 0L then file.Delete()
        with _ -> () // persistence is optional; capture itself already succeeded

    static member private GetLocalIpAddress() : IPAddress =
        try
            use socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, enum<ProtocolType> 0)

            // resolves the routing-table local IP without sending
            socket.Connect("8.8.8.8", 65530)

            match socket.LocalEndPoint with
            | :? IPEndPoint as endPoint -> endPoint.Address
            | _ -> null
        with _ ->
            let host = Dns.GetHostEntry(Dns.GetHostName())

            let picked =
                host.AddressList
                |> Array.tryFind (fun ip -> ip.AddressFamily = AddressFamily.InterNetwork)

            match picked with
            | Some ip -> ip
            | None -> null

    // -----------------------------------------------------------------------
    // Reassembly
    // -----------------------------------------------------------------------

    /// <summary>
    /// Feeds one TCP segment into a direction's reassembler: in-order
    /// segments append; ahead-of-order segments buffer until the gap closes;
    /// behind-order bytes are the retransmit/overlap tail.
    /// </summary>
    member private _.FeedSegment(dir: TcpDirection, seqNum: uint32, buffer: byte[], start: int, length: int) : unit =
        dir.EnsureBudget this.MaxBytesPerDirection

        if dir.NextSeq.IsNone then
            // Mid-stream capture: take this segment's sequence as the start
            dir.NextSeq <- Some seqNum

        let delta = TcpStreamCaptureService.SeqDelta(seqNum, dir.NextSeq.Value)

        if delta = 0L then
            dir.Append(buffer, start, length)
            dir.NextSeq <- Some(seqNum + uint32 length)
            this.DrainBuffered dir
        elif delta > 0L then
            // Out of order (or a gap we haven't seen the cause of yet)
            if not (dir.OutOfOrder.ContainsKey seqNum) && dir.OutOfOrder.Count < 512 then
                dir.OutOfOrder.[seqNum] <- buffer.[start .. start + length - 1]
        else
            // Retransmit overlapping what we already have: keep only the new tail
            let skip = -delta

            if skip < int64 length then
                dir.Append(buffer, start + int skip, length - int skip)
                dir.NextSeq <- Some(seqNum + uint32 length)
                this.DrainBuffered dir

    member private _.DrainBuffered(dir: TcpDirection) : unit =
        // F# port: C#'s while-ContinueWith-TryGetValue → explicit flag loop.
        let mutable keepGoing = true

        while keepGoing do
            match dir.NextSeq with
            | Some ns ->
                match dir.OutOfOrder.TryGetValue ns with
                | true, segment ->
                    dir.OutOfOrder.Remove ns |> ignore
                    dir.Append(segment, 0, segment.Length)
                    dir.NextSeq <- Some(ns + uint32 segment.Length)
                | _ -> keepGoing <- false
            | None -> keepGoing <- false

    /// <summary>Signed distance from base to seq, handling 32-bit wraparound.</summary>
    static member private SeqDelta(seqNum: uint32, baseSeq: uint32) : int64 =
        let mutable delta = int64 seqNum - int64 baseSeq

        if delta > int64 Int32.MaxValue then delta <- delta - (int64 UInt32.MaxValue + 1L)

        if delta < -int64 Int32.MaxValue then delta <- delta + (int64 UInt32.MaxValue + 1L)

        delta

// ── shared ignore file (mirror of SysmonWatcher's file-backed check) ──

// C# SysmonWatcherService.IsIgnoredByFile — the WHY (copied): the ignore
// list is a user setting ("stop listing this process"), so the Traffic
// Patterns tab honors it too, even though its packet-capture pipeline never
// goes through a SysmonWatcherService instance. Cached with a short TTL:
// consulted per finalized flow and per snapshot, and instance methods
// rewrite the file on every change.
module private IgnoreFile =

    let lockObj = obj ()
    let mutable cached = HashSet<string>(StringComparer.OrdinalIgnoreCase)
    let mutable loadedUtc = DateTime.MinValue

    let path () = Path.Combine(WatchConfig.Identity.DataRoot, "ignored_processes.txt")

    let private normalize (processName: string) : string =
        if String.IsNullOrWhiteSpace processName then
            String.Empty
        else
            let name = Path.GetFileName(processName.Trim())

            if name.Length = 0 then
                String.Empty
            elif not (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) then
                name + ".exe"
            else
                name

    /// True when the process name is on the shared ignore list file
    /// (DataRoot\ignored_processes.txt) — the same list the Process Monitor
    /// enforces (written by SysmonWatcher.fs).
    let isIgnored (processName: string) : bool =
        let normalized = normalize processName

        if normalized.Length = 0 then
            false
        else
            lock
                lockObj
                (fun () ->
                    if (DateTime.UtcNow - loadedUtc).TotalSeconds > 30.0 then
                        let fresh = HashSet<string>(StringComparer.OrdinalIgnoreCase)

                        try
                            for line in File.ReadAllLines(path()) do
                                let n = normalize line

                                if n.Length > 0 then fresh.Add n |> ignore
                        with _ -> () // missing or unreadable file — empty list

                        cached <- fresh
                        loadedUtc <- DateTime.UtcNow

                    cached.Contains normalized)

// ── persisted-state DTOs (short keys; the file is rewritten whole) ──
//
// F# port: C# had these as PRIVATE NESTED classes with public properties.
// F# caps member accessibility to the enclosing type's visibility, so a
// private type's member-val properties compile NON-public and
// System.Text.Json (public-properties-only) would silently write {} —
// verified by the scratch self-test. They are public types nested in this
// public module instead: contained names (JsonDto.PersistedStat), working
// reflection, same JSON shape.

module JsonDto =

    type PersistedBucket() =
        member val A: int64 = 0L with get, set
        member val T: int64 = 0L with get, set
        member val R: int64 = 0L with get, set
        member val F: int64 = 0L with get, set

    type PersistedStat() =
        member val Process: string = null with get, set
        member val Ip: string = null with get, set
        member val Tx: int64 = 0L with get, set
        member val Rx: int64 = 0L with get, set
        member val Flows: int64 = 0L with get, set
        member val FirstUtc = DateTime() with get, set
        member val LastUtc = DateTime() with get, set
        member val Pids: int[] = [||] with get, set
        member val Ports: int[] = [||] with get, set
        member val Daily = Dictionary<string, DayTotals>() with get, set
        member val Buckets = List<PersistedBucket>() with get, set

    type PersistedState() =
        member val SavedUtc = DateTime() with get, set
        member val Keys = List<PersistedStat>() with get, set

// ── the aggregation service ────────────────────────────────────────

/// <summary>
/// Folds every finalized TCP flow from the app-level TcpStreamCaptureService
/// into (process name → destination IP) TrafficStat rows with byte totals,
/// a 24h bucket ring, and day-over-day history. Attached once at app start
/// (MainWindow), so patterns accumulate whenever ANY tab runs the capture —
/// the Traffic Patterns tab is just a viewer for this state.
///
/// Direction rule: whichever flow endpoint is on this machine is "us"; the
/// other endpoint is the destination, and Tx is the local→remote direction
/// (normally the client direction, inverted for inbound connections). Flows
/// Sysmon never attributed land under "(unattributed)".
/// </summary>
type TrafficAggregationService private () as this =

    static let shared = TrafficAggregationService()

    let stats = ConcurrentDictionary<string, TrafficStat>(StringComparer.Ordinal)
    let persistLock = obj ()
    let mutable localIps = HashSet<string>(0, StringComparer.Ordinal)
    let mutable timer: Timer = null
    let mutable running = 0
    let mutable dirty = false
    let mutable flowsAggregated = 0L

    static let maxKeys = 5000 // eviction guard for the persisted state
    static let maxDailyDays = 30

    /// <summary>
    /// The app-level singleton (C# was a public static readonly field).
    /// </summary>
    static member Shared: TrafficAggregationService = shared

    // F# port: was %LOCALAPPDATA%\AutoScope\traffic (hardcoded) — now under
    // the injected identity data root.
    static member DataDir: string = Path.Combine(WatchConfig.Identity.DataRoot, "traffic")

    static member private StatePath: string = Path.Combine(TrafficAggregationService.DataDir, "patterns.json")

    member _.FlowsAggregated: int64 = Interlocked.Read &flowsAggregated

    member _.KeyCount: int = stats.Count

    /// <summary>Subscribes to the shared capture. Call once, before Start.</summary>
    member _.Attach(capture: TcpStreamCaptureService) : unit =
        capture.FlowFinalized.AddHandler(Action<TcpFlowRecord>(fun flow -> this.OnFlowFinalized flow))

    member _.Start() : unit =
        if Interlocked.Exchange(&running, 1) = 1 then
            ()
        else
            this.RefreshLocalIps()
            this.LoadState()

            timer <-
                new Timer(
                    TimerCallback(fun _ ->
                        this.RefreshLocalIps()
                        this.PersistIfDirty()),
                    null,
                    TimeSpan.FromSeconds 60.,
                    TimeSpan.FromSeconds 60.
                )

    member _.Shutdown() : unit =
        if Interlocked.Exchange(&running, 0) = 0 then
            ()
        else
            if not (isNull timer) then
                timer.Dispose()
                timer <- null

            this.Persist()

    // -----------------------------------------------------------------------
    // Aggregation
    // -----------------------------------------------------------------------

    member private _.OnFlowFinalized(flow: TcpFlowRecord) : unit =
        try
            // Split "ip:port" endpoints (IPv4 capture, but LastIndexOf is
            // IPv6-safe anyway)
            let clientIp, clientPort = TrafficAggregationService.SplitEndpoint flow.ClientEndpoint

            let serverIp, serverPort = TrafficAggregationService.SplitEndpoint flow.ServerEndpoint

            if isNull clientIp || isNull serverIp then
                ()
            else
                let outbound = not (localIps.Contains serverIp) // client remote → inbound to us

                let destIp = if outbound then serverIp else clientIp
                let destPort = if outbound then serverPort else clientPort
                let tx = if outbound then flow.ClientBytes else flow.ServerBytes
                let rx = if outbound then flow.ServerBytes else flow.ClientBytes

                let procName =
                    if flow.Pid > 0 && not (String.IsNullOrEmpty flow.Image) then
                        Path.GetFileName flow.Image
                    else
                        "(unattributed)"

                // Honor Process Monitor's ignore list: a process the user told
                // the app to stop listing stays out of the pattern table too.
                // (F# port: SysmonWatcherService.IsIgnoredByFile lives in
                // SysmonWatcher.fs, which compiles after this file — the
                // shared ignore FILE is the contract; see IgnoreFile above.)
                if procName <> "(unattributed)" && IgnoreFile.isIgnored procName then
                    ()
                else
                    let stat =
                        stats.GetOrAdd($"{procName}|{destIp}", fun _ -> TrafficStat(procName, destIp))

                    stat.Add(tx, rx, destPort, flow.Pid, flow.EndedUtc)
                    Interlocked.Increment &flowsAggregated |> ignore
                    dirty <- true
        with _ -> () // one bad flow never stops aggregation

    static member private SplitEndpoint(endpoint: string) : string * int =
        if String.IsNullOrEmpty endpoint then (null, 0)
        else
            let colon = endpoint.LastIndexOf ':'

            if colon <= 0 || colon = endpoint.Length - 1 then
                (null, 0)
            else
                match Int32.TryParse endpoint[(colon + 1) ..] with
                // F# port: C# endpoint[..colon] excludes the colon; F#
                // slices are end-INCLUSIVE, so this is Substring(0, colon).
                | true, port -> (endpoint.Substring(0, colon), port)
                | _ -> (null, 0)

    member private _.RefreshLocalIps() : unit =
        try
            let ips =
                HashSet(
                    [ for n in NetworkInterface.GetAllNetworkInterfaces() do
                          if n.OperationalStatus = OperationalStatus.Up then
                              for a in n.GetIPProperties().UnicastAddresses do
                                  yield a.Address.ToString() ],
                    StringComparer.Ordinal
                )

            if ips.Count > 0 then localIps <- ips
        with _ -> () // keep the last known set

    // -----------------------------------------------------------------------
    // View API
    // -----------------------------------------------------------------------

    /// <summary>
    /// All rows, biggest lifetime totals first. Rows for processes on the
    /// Process Monitor ignore list are hidden (their aggregation resumes if
    /// the process is ever un-ignored; the history stays intact).
    /// </summary>
    member _.Snapshot() : IReadOnlyList<TrafficStat> =
        stats.Values
            .Where(fun s ->
                s.ProcessName = "(unattributed)"
                || not (IgnoreFile.isIgnored s.ProcessName))
            .OrderByDescending(fun s -> s.TxBytes + s.RxBytes)
            .ToList()
        :> IReadOnlyList<TrafficStat>

    /// <summary>Clears everything and removes the persisted state.</summary>
    member _.Reset() : unit =
        stats.Clear()
        Interlocked.Exchange(&flowsAggregated, 0L) |> ignore

        lock
            persistLock
            (fun () ->
                try
                    File.Delete TrafficAggregationService.StatePath
                with _ -> ())

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    member private _.PersistIfDirty() : unit =
        if not dirty then ()
        else this.Persist()

    member private _.Persist() : unit =
        try
            Directory.CreateDirectory TrafficAggregationService.DataDir |> ignore

            // Evict the smallest rows when over budget so the file stays bounded
            let rows =
                stats.Values
                    .OrderByDescending(fun s -> s.TxBytes + s.RxBytes)
                    .Take(maxKeys)
                    .ToList()

            let state = JsonDto.PersistedState(SavedUtc = DateTime.UtcNow)

            for stat in rows do
                lock
                    stat.Sync
                    (fun () ->
                        let absNow = DateTime.UtcNow.Ticks / TrafficStatInternals.BucketSpan.Ticks

                        let minAbs = absNow - int64 TrafficStatInternals.BucketCount // keep the last 24h only

                        let entry =
                            JsonDto.PersistedStat(
                                Process = stat.ProcessName,
                                Ip = stat.DestIp,
                                Tx = stat.TxBytes,
                                Rx = stat.RxBytes,
                                Flows = stat.Flows,
                                FirstUtc = stat.FirstSeenUtc,
                                LastUtc = stat.LastSeenUtc,
                                Pids = stat.Pids.ToArray(),
                                Ports = stat.Ports.ToArray(),
                                Daily = Dictionary<string, DayTotals>(
                                    stat.Daily.Where(fun kv -> TrafficAggregationService.IsRecentDay kv.Key)
                                        .ToDictionary((fun kv -> kv.Key), (fun kv -> kv.Value))
                                )
                            )

                        for b in stat.Buckets do
                            if
                                b.Abs < minAbs
                                || (b.Tx ||| b.Rx ||| b.Flows) = 0L
                            then
                                ()
                            else
                                entry.Buckets.Add(
                                    JsonDto.PersistedBucket(A = b.Abs, T = b.Tx, R = b.Rx, F = b.Flows)
                                )

                        state.Keys.Add entry)

            lock
                persistLock
                (fun () ->
                    File.WriteAllText(
                        TrafficAggregationService.StatePath,
                        JsonSerializer.Serialize(state, JsonSerializerOptions(WriteIndented = false))
                    ))

            dirty <- false
        with _ -> () // persistence is best-effort; aggregation itself already succeeded

    static member private IsRecentDay(day: string) : bool =
        match DateTime.TryParse day with
        | true, date -> (DateTime.UtcNow - date.ToUniversalTime()).TotalDays <= float maxDailyDays
        | _ -> false

    member private _.LoadState() : unit =
        try
            if not (File.Exists TrafficAggregationService.StatePath) then
                ()
            else
                let state =
                    JsonSerializer.Deserialize<JsonDto.PersistedState>(
                        File.ReadAllText TrafficAggregationService.StatePath
                    )

                if isNull (box state) || isNull (box state.Keys) then
                    ()
                else
                    for entry in state.Keys do
                        if String.IsNullOrEmpty entry.Process || String.IsNullOrEmpty entry.Ip then
                            ()
                        else
                            let stat = TrafficStat(entry.Process, entry.Ip)

                            stat.RestoreFrom(
                                entry.Tx,
                                entry.Rx,
                                entry.Flows,
                                entry.FirstUtc,
                                entry.LastUtc,
                                (entry.Pids: IEnumerable<int>),
                                (entry.Ports: IEnumerable<int>),
                                (entry.Daily: IEnumerable<KeyValuePair<string, DayTotals>>),
                                (entry.Buckets |> Seq.map (fun b -> (b.A, b.T, b.R, b.F)))
                            )

                            stats.[stat.Key] <- stat
        with _ -> () // unreadable state — start fresh rather than fail
