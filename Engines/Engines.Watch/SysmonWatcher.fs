// F# port of Core\Services\SysmonWatcherService.cs (namespace AutoScope.Services)
// for the Engines library. The tracking contract is the contract: same
// EID 3 XML field names, same ignore-list file format, same filters in
// the same order, same row-handoff (reattribute) rules.
//
// F# port notes (deviations forced by F#/C# interop, none behavioral):
//   • C# events (OnError, OnNewConnectionTracked) are DelegateEvent fields
//     exposed with [<CLIEvent>] — C# `svc.OnError += handler` compiles
//     unchanged with the same Action<...> delegate shapes (verified: F#'s
//     two-parameter Event<'Del,'Args> rejects Action<'T> as a non-standard
//     delegate, so DelegateEvent is the one F# facility that preserves the
//     C# shape).
//   • The user ignore-list file was anchored at the hardcoded
//     %LOCALAPPDATA%\AutoScope\ignored_processes.txt; engines are
//     app-agnostic, so the path derives from
//     WatchConfig.Identity.DataRoot. Same file name, same format (one
//     normalized process name per line, sorted), so an existing list
//     carries over byte-for-byte when DataRoot points at the app's old
//     data dir.
//   • The helper IPNetwork class (CIDR math for the known-cloud filter)
//     is defined BEFORE the service in this file — F# needs definitions
//     before use — where C# had it after; same type name, same members.
//   • The C# private static helpers (ResolveProcessName, TryParseUtcTime,
//     IP filtering, …) are static let-bound functions here — private to
//     the type exactly as before.
//   • SvchostMonitorItem (RowModel.fs), DnsResolutionService (Dns.fs) and
//     TcpConnectionTable (TcpTable.fs) are the parallel ports, same
//     member names as the C# originals.

namespace AutoScope.Engines.Watch

open System
open System.Collections.Concurrent
open System.Collections.Generic
open System.Diagnostics
open System.Diagnostics.Eventing.Reader
open System.Globalization
open System.IO
open System.Net
open System.Text.RegularExpressions
open System.Threading.Tasks
open System.Xml.Linq

// Helper for CIDR math
// F# port: same constructor and Contains member as the C# IPNetwork.
type IPNetwork(ipAddress: IPAddress, prefixLength: int) =

    let toBigEndianUint (addr: IPAddress) : uint32 =
        let ipBytes = addr.GetAddressBytes()
        if BitConverter.IsLittleEndian then Array.Reverse ipBytes
        BitConverter.ToUInt32(ipBytes, 0)

    let subnetMask =
        if prefixLength = 0 then 0u else 0xFFFFFFFFu <<< (32 - prefixLength)

    let networkAddress = toBigEndianUint ipAddress &&& subnetMask

    member _.Contains(ipAddress: IPAddress) : bool =
        if ipAddress.AddressFamily <> System.Net.Sockets.AddressFamily.InterNetwork then
            false
        else
            (toBigEndianUint ipAddress &&& subnetMask) = networkAddress

/// <summary>
/// Watches Sysmon EID 3 (network connect) events for the tracked target
/// processes and maintains one row per remote IP in the shared
/// ConcurrentDictionary, with DNS enrichment through the shared
/// DnsResolutionService.
/// F# port: member names, constructor and behavior as the C# original.
/// </summary>
type SysmonWatcherService(trackedIps: ConcurrentDictionary<string, SvchostMonitorItem>,
                          dnsService: DnsResolutionService) =

    let mutable watcher: EventLogWatcher = null

    let onError = DelegateEvent<Action<string>>()
    let onNewConnectionTracked = DelegateEvent<Action<SvchostMonitorItem>>()

    let targetProcesses = ConcurrentBag<string>([| "svchost.exe" |])

    // Processes the user asked to keep out of the list, matched on the
    // image file name (e.g. "chrome.exe"), case-insensitively.
    let ignoredProcesses = ConcurrentBag<string>()

    // ── static helpers (C# private statics) ───────────────────────────

    // Same regex from monitor_ultimate.py
    static let knownDomainsRegex =
        Regex(
            @"(?i)(microsoft|windows|azure|msedge|trafficmanager|google|1e100|googleapis|bing|live|office|skype|msn|azureedge)",
            RegexOptions.Compiled
        )

    // WinUI port: was CWD-relative ("ignored_processes.txt") — an
    // elevated launch starts in C:\Windows\System32, which scattered
    // the file (and broke migration). Anchored to the app data dir now.
    // F# port: the path derives from the configured identity's DataRoot
    // (no app name may live in an engine).
    static let ignoredProcessesPath () =
        Path.Combine(WatchConfig.Identity.DataRoot, "ignored_processes.txt")

    static let normalizeProcessName (processName: string) =
        if String.IsNullOrWhiteSpace processName then
            String.Empty
        else
            let name = Path.GetFileName(processName.Trim())

            if name.Length = 0 then String.Empty
            elif not (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) then name + ".exe"
            else name

    // ── File-backed ignore check for other tabs ─────────────────────────
    //
    // The ignore list is a user setting ("stop listing this process"), so
    // the Traffic Patterns tab honors it too, even though its packet-
    // capture pipeline never goes through a SysmonWatcherService instance.
    // Cached with a short TTL: consulted per finalized flow and per
    // snapshot, and instance methods rewrite the file on every change.

    static let fileIgnoreLock = obj ()
    static let mutable fileIgnored = HashSet<string>(StringComparer.OrdinalIgnoreCase)
    static let mutable fileIgnoredLoadedUtc = DateTime.MinValue

    // -----------------------------------------------------------------------
    // Process name resolution (C# private statics)
    // -----------------------------------------------------------------------

    /// <summary>
    /// Looks up the process name for a given PID.
    /// Returns empty string if the process has already exited or access is denied.
    /// </summary>
    static let resolveProcessName (pid: int) =
        if pid <= 0 then String.Empty
        else
            try
                Process.GetProcessById(pid).ProcessName
            with _ ->
                // Process has already exited, or we don't have access (e.g. System/Idle)
                String.Empty

    /// <summary>
    /// The PID's executable path, or null when unreadable (exited, System,
    /// or access denied). Baseline rows carry it so their identity
    /// survives process exit exactly like Sysmon-sourced rows.
    /// </summary>
    static let tryGetProcessPath (pid: int) =
        if pid <= 0 then null
        else
            try
                match Process.GetProcessById(pid).MainModule with
                | null -> null
                | m -> m.FileName
            with _ ->
                null

    /// <summary>
    /// The PID's start time (UTC), or null when unreadable (exited or
    /// access denied). Called once per row creation — this is the
    /// timestamp that keeps a row's identity safe from PID recycling.
    /// </summary>
    static let tryGetProcessStartUtc (pid: int) : Nullable<DateTime> =
        if pid <= 0 then Nullable<DateTime>()
        else
            try
                Nullable(Process.GetProcessById(pid).StartTime.ToUniversalTime())
            with _ ->
                Nullable<DateTime>()

    /// <summary>True while the PID still exists (PID 0, System/Idle, never exits).</summary>
    static let isProcessAlive (pid: int) =
        if pid <= 0 then true
        else
            try
                Process.GetProcessById pid |> ignore
                true
            with _ ->
                false

    /// <summary>
    /// Parses Sysmon's UtcTime field ("2026-10-13 23:48:53.123"). Null
    /// when absent or in an unexpected format.
    /// </summary>
    static let tryParseUtcTime (value: string) : Nullable<DateTime> =
        if String.IsNullOrWhiteSpace value then
            Nullable<DateTime>()
        else
            match
                DateTime.TryParseExact(
                    value.Trim(),
                    [| "yyyy-MM-dd HH:mm:ss.fff"; "yyyy-MM-dd HH:mm:ss" |],
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal ||| DateTimeStyles.AdjustToUniversal
                )
            with
            | true, parsed -> Nullable parsed
            | _ -> Nullable<DateTime>()

    // -----------------------------------------------------------------------
    // IP filtering helpers
    // -----------------------------------------------------------------------

    // Shared with the sampled paths: loopback / link-local / ULA /
    // multicast / broadcast for BOTH families. IPv6 events used to
    // slip past this with only a literal "::1" check, seeding
    // link-local and ULA destinations as if they were internet rows.
    static let isIgnoredIp (ipStr: string) = TcpConnectionTable.IsLocalOrNonRoutable(ipStr)

    static let knownCidrBlocks =
        [| IPNetwork(IPAddress.Parse("20.0.0.0"), 8)
           IPNetwork(IPAddress.Parse("52.0.0.0"), 8)
           IPNetwork(IPAddress.Parse("13.64.0.0"), 11)
           IPNetwork(IPAddress.Parse("40.74.0.0"), 15)
           IPNetwork(IPAddress.Parse("104.40.0.0"), 13)
           IPNetwork(IPAddress.Parse("137.116.0.0"), 16)
           IPNetwork(IPAddress.Parse("204.79.197.0"), 24)
           IPNetwork(IPAddress.Parse("8.8.4.0"), 24)
           IPNetwork(IPAddress.Parse("8.8.8.0"), 24)
           IPNetwork(IPAddress.Parse("34.0.0.0"), 8)
           IPNetwork(IPAddress.Parse("35.0.0.0"), 8)
           IPNetwork(IPAddress.Parse("74.125.0.0"), 16)
           IPNetwork(IPAddress.Parse("142.250.0.0"), 15)
           IPNetwork(IPAddress.Parse("172.217.0.0"), 16)
           IPNetwork(IPAddress.Parse("216.58.192.0"), 19) |]

    static let isKnownCloudIp (ipStr: string) =
        match IPAddress.TryParse ipStr with
        | true, ip -> knownCidrBlocks |> Array.exists (fun net -> net.Contains ip)
        | _ -> false

    // ── instance helpers ─────────────────────────────────────────────

    let saveIgnoredProcesses () =
        try
            Directory.CreateDirectory(Path.GetDirectoryName(ignoredProcessesPath ())) |> ignore

            File.WriteAllLines(
                ignoredProcessesPath (),
                ignoredProcesses
                |> Seq.sortWith (fun a b -> StringComparer.OrdinalIgnoreCase.Compare(a, b))
            )
        with _ ->
            // persistence is best-effort — filtering still works without it
            ()

    // F# port: C#'s ctor called LoadIgnoredProcesses, which called the
    // instance AddIgnoredProcess per line (so a pre-normalized file is
    // re-normalized and re-saved on load). F# forbids calling instance
    // members from the ctor `do` (the initialization guard raises
    // "accessed recursively before fully initialized", silently swallowed
    // by the catch — verified), so the add logic is a let-bound function
    // the ctor and the member share — same calls, same order.
    let addIgnoredProcessCore (processName: string) =
        let normalized = normalizeProcessName processName

        if normalized.Length = 0 then ()
        elif
            ignoredProcesses
            |> Seq.exists (fun p -> String.Equals(p, normalized, StringComparison.OrdinalIgnoreCase))
        then ()
        else
            ignoredProcesses.Add normalized
            saveIgnoredProcesses ()

    do
        try
            for line in File.ReadAllLines(ignoredProcessesPath ()) do
                addIgnoredProcessCore line
        with _ ->
            // first run or unreadable file — start with an empty ignore list
            ()

    // ── members ──────────────────────────────────────────────────────

    /// <summary>F# port: the C# field-like events; C# subscribers attach
    /// with += exactly as before.</summary>
    [<CLIEvent>]
    member _.OnError = onError.Publish

    [<CLIEvent>]
    member _.OnNewConnectionTracked = onNewConnectionTracked.Publish

    member val MonitorAllProcesses: bool = false with get, set

    member val FilterKnownCloudIps: bool = false with get, set

    member _.AddTargetProcess(processName: string) =
        if
            not (
                targetProcesses
                |> Seq.exists (fun p -> String.Equals(p, processName, StringComparison.OrdinalIgnoreCase))
            )
        then
            targetProcesses.Add processName

    // -----------------------------------------------------------------------
    // User ignore list
    // -----------------------------------------------------------------------

    /// <summary>Process names currently on the ignore list.</summary>
    member _.IgnoredProcesses: IReadOnlyCollection<string> =
        ignoredProcesses.ToArray() :> IReadOnlyCollection<string>

    /// <summary>
    /// Adds a process to the ignore list: its connections will no longer
    /// create list entries. The ".exe" suffix is added when missing.
    /// </summary>
    member _.AddIgnoredProcess(processName: string) = addIgnoredProcessCore processName

    member _.RemoveIgnoredProcess(processName: string) =
        let normalized = normalizeProcessName processName
        if normalized.Length = 0 then ()
        else
            let remaining = ResizeArray<string>()
            let mutable total = 0

            for p in ignoredProcesses do
                total <- total + 1

                if not (String.Equals(p, normalized, StringComparison.OrdinalIgnoreCase)) then
                    remaining.Add p

            if remaining.Count = total then ()
            else
                // ConcurrentBag has no conditional removal — drain it and refill
                let mutable taken = Unchecked.defaultof<string>

                while ignoredProcesses.TryTake(&taken) do
                    ()

                for p in remaining do
                    ignoredProcesses.Add p

                saveIgnoredProcesses ()

    /// <summary>True when the given process name (or full image path) is ignored.</summary>
    member _.IsProcessIgnored(processName: string) =
        let normalized = normalizeProcessName processName

        normalized.Length > 0
        && ignoredProcesses
           |> Seq.exists (fun p -> String.Equals(p, normalized, StringComparison.OrdinalIgnoreCase))

    /// <summary>
    /// True when the process name is on the shared ignore list file
    /// (ignored_processes.txt) — the same list the Process Monitor enforces.
    /// </summary>
    static member IsIgnoredByFile(processName: string) : bool =
        let normalized = normalizeProcessName processName
        if normalized.Length = 0 then false
        else
            lock fileIgnoreLock (fun () ->
                if (DateTime.UtcNow - fileIgnoredLoadedUtc).TotalSeconds > 30.0 then
                    let set_ = HashSet<string>(StringComparer.OrdinalIgnoreCase)

                    try
                        for line in File.ReadAllLines(ignoredProcessesPath ()) do
                            let n = normalizeProcessName line

                            if n.Length > 0 then set_.Add n |> ignore
                    with _ ->
                        // missing or unreadable file — empty list
                        ()

                    fileIgnored <- set_
                    fileIgnoredLoadedUtc <- DateTime.UtcNow

                fileIgnored.Contains normalized)

    member this.Start() =
        try
            let query = EventLogQuery(
                "Microsoft-Windows-Sysmon/Operational",
                PathType.LogName,
                "*[System[(EventID=3)]]"
            )

            let w = new EventLogWatcher(query)
            watcher <- w
            w.EventRecordWritten.AddHandler(fun _ e -> this.WatcherEventRecordWritten e)
            w.Enabled <- true
        with
        | :? EventLogNotFoundException ->
            onError.Trigger [| box "Sysmon is not installed. Please install Sysmon to use this feature." |]
        | ex ->
            onError.Trigger [| box $"Failed to start Sysmon watcher: {ex.Message}" |]

    member _.Stop() =
        if not (isNull watcher) then
            watcher.Enabled <- false
            watcher.Dispose()
            watcher <- null

    /// <summary>
    /// Seeds the tracked-IP table with the machine's currently
    /// established TCP connections. The event path only sees connections
    /// opened from now on — long-lived channels (svchost's boot-time WNS
    /// link, persistent update/telemetry sockets) never fire a new
    /// Event ID 3, so without this snapshot they stay invisible until
    /// they happen to reconnect. Same filters as the event path (ignore
    /// list, ignored IPs, cloud filter, one row per IP); rows surface
    /// through OnNewConnectionTracked exactly like event-driven ones,
    /// so callers on any thread get UI marshaling for free. Returns the
    /// number of rows seeded. IPv4 only — GetExtendedTcpTable queries
    /// AF_INET, and the live event path covers v6 anyway. The kernel
    /// table is enumerated before any per-PID name lookup, so the join
    /// can never name a PID from data older than the connection rows
    /// themselves (the netstat-era PID-reuse race).
    /// </summary>
    member this.SeedBaseline() : int =
        let connections =
            try
                Some(TcpConnectionTable.GetEstablished())
            with _ ->
                None // enumeration unavailable — the event path still works

        match connections with
        | None -> 0
        | Some rows ->
            let mutable seeded = 0

            for c in rows do
                try
                    let destIp = c.RemoteIp

                    let passIp =
                        not (String.IsNullOrEmpty destIp)
                        && not (isIgnoredIp destIp)

                    let passIp =
                        passIp
                        && not (this.FilterKnownCloudIps && isKnownCloudIp destIp)

                    if not passIp then ()
                    else
                        let pid = c.Pid
                        let image = tryGetProcessPath pid
                        let mutable processName = resolveProcessName pid

                        if String.IsNullOrEmpty processName && not (String.IsNullOrEmpty image) then
                            processName <- Path.GetFileName image

                        // Same gates as Watcher_EventRecordWritten, same order
                        if
                            String.IsNullOrEmpty processName // unattributable
                            || this.IsProcessIgnored image
                            || this.IsProcessIgnored processName
                        then
                            ()
                        else
                            let mutable isTarget = this.MonitorAllProcesses

                            if not isTarget then
                                let matchName =
                                    match image with
                                    | null -> normalizeProcessName processName
                                    | i -> i

                                isTarget <-
                                    targetProcesses
                                    |> Seq.exists (fun target ->
                                        matchName.EndsWith(target, StringComparison.OrdinalIgnoreCase))

                            if not isTarget then ()
                            elif trackedIps.ContainsKey destIp then // a row already covers this IP
                                ()
                            else
                                let initialHost =
                                    match dnsService.GetCachedHostname destIp with
                                    | null -> destIp
                                    | h -> h

                                if this.FilterKnownCloudIps && knownDomainsRegex.IsMatch initialHost then ()
                                else
                                    let item =
                                        SvchostMonitorItem(
                                            ProcessId = pid,
                                            ProcessName = processName,
                                            ImagePath = image,
                                            RemoteIp = destIp,
                                            Hostname = initialHost,
                                            Protocol = "tcp",
                                            ProcessStartedUtc = tryGetProcessStartUtc pid,
                                            // Alive right now by definition — a real LastSeen
                                            // keeps the row out of the stale-dimming skip list
                                            LastSeen = DateTime.UtcNow,
                                            RxBytes = 0L, TxBytes = 0L, RxPackets = 0L, TxPackets = 0L
                                        )

                                    if trackedIps.TryAdd(destIp, item) then
                                        onNewConnectionTracked.Trigger [| box item |]
                                        dnsService.EnqueueForResolution item
                                        seeded <- seeded + 1
                with _ ->
                    // one bad row must not abort the snapshot
                    ()

            seeded

    member private this.WatcherEventRecordWritten(e: EventRecordWrittenEventArgs) =
        try
            if isNull e.EventRecord then ()
            else
                let xml = e.EventRecord.ToXml()
                let doc = XDocument.Parse(xml)
                let ns = XNamespace.Get("http://schemas.microsoft.com/win/2004/08/events/event")

                let eventData =
                    match doc.Root with
                    | null -> null
                    | root -> root.Element(ns + "EventData")

                if isNull eventData then ()
                else
                    let mutable image = String.Empty
                    let mutable processId = String.Empty
                    let mutable destIp = String.Empty
                    let mutable destHost = String.Empty
                    let mutable utcTime = String.Empty
                    let mutable protocol = "TCP" // Default

                    for data in eventData.Elements(ns + "Data") do
                        let name =
                            match data.Attribute(XName.Get "Name") with
                            | null -> null
                            | a -> a.Value

                        if name = "Image" then image <- data.Value
                        elif name = "ProcessId" then processId <- data.Value
                        elif name = "DestinationIp" then destIp <- data.Value
                        elif name = "DestinationHostname" then destHost <- data.Value
                        elif name = "UtcTime" then utcTime <- data.Value
                        elif name = "Protocol" then protocol <- data.Value

                    // User ignore list: these processes never create list entries
                    if this.IsProcessIgnored image then ()
                    else
                        // Monitor target processes
                        let mutable isTarget = this.MonitorAllProcesses

                        if not isTarget then
                            isTarget <-
                                targetProcesses
                                |> Seq.exists (fun target ->
                                    image.EndsWith(target, StringComparison.OrdinalIgnoreCase))

                        if not isTarget then ()
                        elif String.IsNullOrEmpty destIp || isIgnoredIp destIp then ()
                        elif this.FilterKnownCloudIps && isKnownCloudIp destIp then ()
                        else
                            // The event's own Image is the ground truth — it names the
                            // exact process that opened this connection. A live PID
                            // lookup can only degrade it: an exited PID returns nothing,
                            // a recycled one returns the WRONG tenant's name. Live
                            // lookup runs only when Sysmon itself gave no image.
                            let pid =
                                match Int32.TryParse processId with
                                | true, p -> p
                                | _ -> 0

                            let processName =
                                if String.IsNullOrEmpty image then resolveProcessName pid
                                else Path.GetFileName image

                            match trackedIps.TryGetValue destIp with
                            | true, existing ->
                                // Same process reconnecting — the row already covers it.
                                if existing.ProcessId = pid then ()
                                // A different PID on an already-tracked IP: when the row's
                                // original process has exited, hand the row to the newcomer
                                // so counters accrue to a live process instead of a ghost
                                // PID. While the original is still alive the row stays with
                                // it — the dictionary is keyed by remote IP alone, so one
                                // row per IP is all the model allows.
                                elif existing.ProcessId <= 0 || isProcessAlive existing.ProcessId then ()
                                else
                                    existing.Reattribute(
                                        pid,
                                        processName,
                                        (if String.IsNullOrEmpty image then null else image),
                                        tryGetProcessStartUtc pid
                                    )
                            | _ ->
                                // Seed cache if Sysmon already gave us the hostname
                                if not (String.IsNullOrEmpty destHost) && destHost <> "-" then
                                    dnsService.SeedFromSysmon(destIp, destHost)

                                // Build the item immediately with whatever we have; DNS service
                                // will fill in Hostname asynchronously and the DataGrid will refresh.
                                let initialHost =
                                    match dnsService.GetCachedHostname destIp with
                                    | null -> destIp
                                    | h -> h

                                if this.FilterKnownCloudIps && knownDomainsRegex.IsMatch initialHost then ()
                                else
                                    let item =
                                        SvchostMonitorItem(
                                            ProcessId = pid,
                                            ProcessName = processName,
                                            ImagePath = (if String.IsNullOrEmpty image then null else image),
                                            RemoteIp = destIp,
                                            Hostname = initialHost,
                                            Protocol = protocol,
                                            // Capture-time identity anchor: the start time binds the
                                            // row to this tenant of the PID, so a later inquiry can
                                            // never mistake a recycled PID's new owner for it.
                                            ProcessStartedUtc = tryGetProcessStartUtc pid,
                                            // Seed from the event itself: the packets that triggered
                                            // this event usually crossed the wire before the row
                                            // entered tracking, so a one-shot connection would else
                                            // show "—" forever (and never dim — IsStale skips rows
                                            // with a default LastSeen).
                                            LastSeen = (let n = tryParseUtcTime utcTime
                                                        if n.HasValue then n.Value else DateTime.UtcNow),
                                            RxBytes = 0L, TxBytes = 0L, RxPackets = 0L, TxPackets = 0L
                                        )

                                    if trackedIps.TryAdd(destIp, item) then
                                        onNewConnectionTracked.Trigger [| box item |]
                                        // Queue for async resolution (no-op if cache already had a real name)
                                        dnsService.EnqueueForResolution item
        with _ ->
            ()
