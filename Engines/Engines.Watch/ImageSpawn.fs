// F# port of Core\Services\ImageSpawnWatcherService.cs (namespace
// AutoScope.Services) for the Engines.Watch library. Behavioral
// faithfulness is the contract: same EID 1/5/3 handling, same substring
// pre-filter before any DOM parse, same venv pairing, same backfill
// ordering, same event payloads and error strings.
//
// F# port notes (deviations forced by F#, none behavioral):
//   • SpawnNetworkEvent is defined before the service — F# needs every
//     type before first reference (it was a top-level class in the C#
//     file too, so the C# surface is unchanged).
//   • SpawnItem is NOT ported here: it lives in RowModel.fs (parallel
//     port of Core\models\SpawnItem.cs). Only its data-plane members are
//     consumed — TimeUtc/Pid/ProcessGuid/Image/CommandLine/ParentPid/…,
//     the mutable Exited, and SetVenvLauncher/MarkAbsorbedLauncher/
//     SetPythonParent. null SpawnItem values go through
//     Unchecked.defaultof<SpawnItem> here so RowModel.fs is not forced
//     to carry [<AllowNullLiteral>].
//   • C# events (event Action<string> OnError, …) port to [<CLIEvent>]
//     members over DelegateEvent<Action<…>> — from C# the += surface and
//     delegate types are identical.
//   • The C# optional constructor parameter (venvPairing = false) is a
//     second constructor here; F# cannot put DefaultParameterValue on a
//     primary constructor argument. Backfill's maxRows default uses
//     [<Optional; DefaultParameterValue(400)>], which does surface as a
//     C# default value.
//   • The C# private instance/static helpers (Watch, HandleSpawnRecord,
//     PairWithLauncher, …) are let-bound functions in the constructor
//     scope — same file-private visibility, one instance, and the C#
//     private-member names live on as the let names.
//   • Private handler names lost their underscores (F# forbids '_' in
//     member names).

namespace AutoScope.Engines.Watch

open System
open System.Collections.Generic
open System.Diagnostics.Eventing.Reader
open System.Globalization
open System.IO
open System.Linq
open System.Runtime.InteropServices
open System.Xml.Linq

// ── private field plumbing ──────────────────────────────────────────
//
// EventData is parsed BY NAME, never by property index — the field
// order varies across Sysmon versions. EID 1 fires for every process
// creation on the machine, so the XML gets a cheap substring scan
// before anything is parsed into a DOM (a cmdline/parent mentioning
// python only costs one wasted parse; a real python image never
// escapes the scan).
module private SpawnField =

    let getValue (fields: Dictionary<string, string>) (name: string) : string =
        match fields.TryGetValue(name) with
        | true, value -> value
        | _ -> String.Empty

    /// <summary>Sysmon PIDs are decimal in EID 1/5 but hex (0x…) in some EID 3 versions.</summary>
    let parsePid (value: string) : int =
        if String.IsNullOrEmpty value then
            0
        else
            let mutable dec = 0

            if Int32.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, &dec) then
                dec
            elif
                value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                && Int32.TryParse(value.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, &dec)
            then
                dec
            else
                0

    let parsePort (value: string) : int =
        let mutable port = 0

        if Int32.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, &port) then
            port
        else
            0

    /// <summary>Sysmon UtcTime is "yyyy-MM-dd HH:mm:ss.fff" UTC; fall back to the record stamp.</summary>
    let parseUtcTime (value: string) (fallback: Nullable<DateTime>) : DateTime =
        let mutable parsed = DateTime()

        if
            DateTime.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal ||| DateTimeStyles.AdjustToUniversal,
                &parsed
            )
        then
            parsed
        elif fallback.HasValue then
            fallback.Value.ToUniversalTime()
        else
            DateTime.UtcNow

    let parseFields (xml: string) : Dictionary<string, string> option =
        let doc = XDocument.Parse(xml)
        let ns = XNamespace.Get("http://schemas.microsoft.com/win/2004/08/events/event")

        let eventData =
            if isNull (box doc.Root) then null else doc.Root.Element(ns + "EventData")

        if isNull (box eventData) then
            None
        else
            // F# port: case-SENSITIVE dictionary, exactly the C#
            // StringComparer.Ordinal — Sysmon field names are stable
            // spellings (unlike the scheduler log's mixed casing).
            let fields = Dictionary<string, string>(16, StringComparer.Ordinal)

            for data in eventData.Elements(ns + "Data") do
                match data.Attribute(XName.Get("Name")) with
                | null -> ()
                | attr when not (fields.ContainsKey(attr.Value)) -> fields.[attr.Value] <- data.Value
                | _ -> ()

            Some fields

/// <summary>A python TCP connect as seen by Sysmon EID 3 — the pid↔flow attribution source.</summary>
type SpawnNetworkEvent() =
    member val TimeUtc: DateTime = DateTime() with get, set
    member val Pid: int = 0 with get, set
    member val Image: string = null with get, set
    member val SourceIp: string = null with get, set
    member val SourcePort: int = 0 with get, set
    member val DestIp: string = null with get, set
    member val DestPort: int = 0 with get, set

    /// <summary>Canonical endpoint pair, orientation as the initiator saw it.</summary>
    member this.Endpoints = $"{this.SourceIp}:{this.SourcePort} → {this.DestIp}:{this.DestPort}"

/// <summary>
/// Real-time tracing of process creations for a chosen image family
/// (python.exe, taskhostw.exe, …) from the Sysmon operational channel:
/// EID 1 (create, with full parentage), EID 5 (terminate, flips Exited)
/// and EID 3 (network connect, used to attribute captured TCP flows to
/// the spawning pid). EID 1 fires for every process creation on the
/// machine, so records are pre-filtered by a cheap substring scan and
/// discarded early unless the image passes the caller's filter.
/// Backfill replays the same channel's recent records so a tab opened
/// after the fact still shows what ran.
/// F# port: the C# optional venvPairing constructor parameter is the
/// two-constructor shape here — imageFilter: client-side image filter
/// (full path in); xmlKeyword: cheap substring pre-filter applied to the
/// raw event XML before parsing, must match everything imageFilter
/// accepts; venvPairing: enable the python venv launcher/interpreter
/// pairing.
/// </summary>
type ImageSpawnWatcherService(imageFilter: Func<string, bool>, xmlKeyword: string, venvPairing: bool) =

    static let ChannelName = "Microsoft-Windows-Sysmon/Operational"

    let onError = DelegateEvent<Action<string>>()
    let onSpawn = DelegateEvent<Action<SpawnItem>>()
    let onExited = DelegateEvent<Action<SpawnItem>>()
    let onNetworkConnect = DelegateEvent<Action<SpawnNetworkEvent>>()

    let mutable spawnWatcher: EventLogWatcher = null
    let mutable exitWatcher: EventLogWatcher = null
    let mutable netWatcher: EventLogWatcher = null
    let mutable disposed = false

    // Tracked spawns by pid — drives venv pairing and EID 5 lookup. A pid
    // reuse replaces the entry (old rows keep their own copy of the data).
    let tracked = Dictionary<int, SpawnItem>()
    let trackedLock = obj ()

    // EID 5 can beat its own EID 1 through the independent watchers;
    // exits with no spawn yet wait here and stamp the item on arrival.
    let earlyExits = Dictionary<int, DateTime>()

    // Memory guard for the pid maps on long sessions
    static let TrackedCap = 20000

    // ── private helpers (the C# private methods, as let functions) ────

    let watch (xpath: string) (handler: EventHandler<EventRecordWrittenEventArgs>) : EventLogWatcher =
        let watcher = new EventLogWatcher(EventLogQuery(ChannelName, PathType.LogName, xpath))

        watcher.EventRecordWritten.AddHandler(handler)
        watcher.Enabled <- true
        watcher

    /// <summary>
    /// Venv pairing: a venv command spawns two processes — the launcher
    /// (venv\Scripts\python.exe) and the real base interpreter as its
    /// child. When the new spawn's parent is a tracked, still-running
    /// python spawn with a different image in a \Scripts\ folder, the
    /// child is the real interpreter: it carries the pair and the launcher
    /// row is absorbed into the detail pane. Correlation is purely
    /// ParentProcessId-based — nothing inside the venv is ever read.
    /// </summary>
    let isVenvLauncherImage (image: string) =
        not (String.IsNullOrEmpty image)
        && image.IndexOf("\\Scripts\\", StringComparison.OrdinalIgnoreCase) >= 0
        && ImageSpawnWatcherService.IsPythonImage image

    let pruneIfNeeded () =
        if tracked.Count < TrackedCap then
            ()
        else
            // Drop the oldest tenth by spawn time; view rows keep their own data.
            let victims =
                tracked
                    .OrderBy(fun (kv: KeyValuePair<int, SpawnItem>) -> kv.Value.TimeUtc)
                    .Take(max 1 (tracked.Count / 10))
                    .Select(fun (kv: KeyValuePair<int, SpawnItem>) -> kv.Key)
                    .ToList()

            for pid in victims do
                tracked.Remove(pid) |> ignore

    let pairWithLauncher (item: SpawnItem) =
        if not venvPairing then ()
        elif item.ParentPid <= 0 then ()
        else
            match tracked.TryGetValue(item.ParentPid) with
            | true, parent when not parent.Exited && parent.Pid <> item.Pid ->
                if
                    isVenvLauncherImage parent.Image
                    && not (String.Equals(parent.Image, item.Image, StringComparison.OrdinalIgnoreCase))
                then
                    item.SetVenvLauncher(parent)
                    parent.MarkAbsorbedLauncher()
                else
                    // python spawning python without a venv layout (multiprocessing,
                    // subprocess.run([...python...])) — keep both rows, badge the child.
                    item.SetPythonParent()
            | _ -> ()

    /// <summary>Returns true when the record produced a spawn.</summary>
    let handleSpawnRecord (record: EventRecord) (isReplay: bool) : bool =
        try
            let item =
                ImageSpawnWatcherService.ParseSpawnRecord(record, imageFilter, xmlKeyword)

            if isNull (box item) then
                false
            else
                let reported =
                    lock
                        trackedLock
                        (fun () ->
                            // Live watcher won the race for this pid — never double-add
                            if isReplay && tracked.ContainsKey(item.Pid) then
                                false
                            else
                                pairWithLauncher item

                                // Terminate event already observed for this pid — the
                                // process was shorter than the watcher round-trip.
                                if earlyExits.Remove(item.Pid) then item.Exited <- true

                                pruneIfNeeded ()
                                tracked.[item.Pid] <- item
                                true)

                if reported then onSpawn.Trigger [| box item |]

                reported
        with _ ->
            // a malformed record never takes the watcher down
            false

    let handleExitRecord (record: EventRecord) =
        try
            let parseIfMatchedRecord (record: EventRecord) (keyword: string) : Dictionary<string, string> option =
                if isNull (box record) then
                    None
                else
                    let xml = record.ToXml()

                    if xml.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) < 0 then
                        None
                    else
                        match SpawnField.parseFields xml with
                        | None -> None
                        | Some fields ->
                            if imageFilter.Invoke(SpawnField.getValue fields "Image") then
                                Some fields
                            else
                                None

            match parseIfMatchedRecord record xmlKeyword with
            | None -> ()
            | Some fields ->
                let pid = SpawnField.parsePid (SpawnField.getValue fields "ProcessId")

                if pid > 0 then
                    let item =
                        lock
                            trackedLock
                            (fun () ->
                                match tracked.TryGetValue(pid) with
                                | true, item ->
                                    item.Exited <- true
                                    Some item
                                | false, _ ->
                                    // EID 1 not processed yet — hold the exit for the spawn handler.
                                    earlyExits.[pid] <- DateTime.UtcNow

                                    if earlyExits.Count > 1024 then
                                        let stale =
                                            earlyExits
                                                .Where(fun (kv: KeyValuePair<int, DateTime>) ->
                                                    (DateTime.UtcNow - kv.Value).TotalMinutes > 10.0)
                                                .Select(fun (kv: KeyValuePair<int, DateTime>) -> kv.Key)
                                                .ToList()

                                        for key in stale do
                                            earlyExits.Remove(key) |> ignore

                                    None)

                    match item with
                    | Some item -> onExited.Trigger [| box item |]
                    | None -> ()
        with _ -> ()

    let spawnEventRecordWritten (e: EventRecordWrittenEventArgs) =
        if not (isNull (box e.EventRecord)) then handleSpawnRecord e.EventRecord false |> ignore

    let exitEventRecordWritten (e: EventRecordWrittenEventArgs) =
        if isNull (box e.EventRecord) then
            ()
        else
            try
                handleExitRecord e.EventRecord
            with _ -> ()

    let parseIfMatched (e: EventRecordWrittenEventArgs) (keyword: string) : Dictionary<string, string> option =
        if isNull (box e.EventRecord) then
            None
        else
            let record = e.EventRecord
            let xml = record.ToXml()

            if xml.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) < 0 then
                None
            else
                match SpawnField.parseFields xml with
                | None -> None
                | Some fields ->
                    if imageFilter.Invoke(SpawnField.getValue fields "Image") then
                        Some fields
                    else
                        None

    let netEventRecordWritten (e: EventRecordWrittenEventArgs) =
        try
            match parseIfMatched e xmlKeyword with
            | None -> ()
            | Some fields ->
                let proto = SpawnField.getValue fields "Protocol"

                if not (String.Equals(proto, "tcp", StringComparison.OrdinalIgnoreCase)) then
                    ()
                else
                    let pid = SpawnField.parsePid (SpawnField.getValue fields "ProcessId")

                    if pid > 0 then
                        let fallback =
                            if not (isNull (box e.EventRecord)) then
                                e.EventRecord.TimeCreated
                            else
                                Nullable<DateTime>()

                        onNetworkConnect.Trigger
                            [| box (
                                   SpawnNetworkEvent(
                                       TimeUtc = SpawnField.parseUtcTime (SpawnField.getValue fields "UtcTime") fallback,
                                       Pid = pid,
                                       Image = SpawnField.getValue fields "Image",
                                       SourceIp = SpawnField.getValue fields "SourceIp",
                                       SourcePort = SpawnField.parsePort (SpawnField.getValue fields "SourcePort"),
                                       DestIp = SpawnField.getValue fields "DestinationIp",
                                       DestPort = SpawnField.parsePort (SpawnField.getValue fields "DestinationPort")
                                   )
                               ) |]
        with _ -> ()

    // ── surface ───────────────────────────────────────────────────────

    // F# port: second constructor for the C# optional venvPairing = false.
    new(imageFilter: Func<string, bool>, xmlKeyword: string) =
        new ImageSpawnWatcherService(imageFilter, xmlKeyword, false)

    [<CLIEvent>]
    member _.OnError: IDelegateEvent<Action<string>> = onError.Publish

    [<CLIEvent>]
    member _.OnSpawn: IDelegateEvent<Action<SpawnItem>> = onSpawn.Publish

    [<CLIEvent>]
    member _.OnExited: IDelegateEvent<Action<SpawnItem>> = onExited.Publish

    [<CLIEvent>]
    member _.OnNetworkConnect: IDelegateEvent<Action<SpawnNetworkEvent>> = onNetworkConnect.Publish

    member _.TrackedCount = lock trackedLock (fun () -> tracked.Count)

    /// <summary>
    /// Distinct python image paths seen spawning — the passive discovery
    /// feed for the instrumentation dialog (every python that actually
    /// ran on this machine, wherever it lives).
    /// </summary>
    member _.GetSeenImages() : ResizeArray<string> =
        lock
            trackedLock
            (fun () ->
                tracked.Values
                    .Select(fun (i: SpawnItem) -> i.Image)
                    .Where(fun img -> not (String.IsNullOrEmpty img))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList())

    member _.Start() =
        try
            spawnWatcher <-
                watch
                    "*[System[(EventID=1)]]"
                    (EventHandler<EventRecordWrittenEventArgs>(fun _ e -> spawnEventRecordWritten e))

            exitWatcher <-
                watch
                    "*[System[(EventID=5)]]"
                    (EventHandler<EventRecordWrittenEventArgs>(fun _ e -> exitEventRecordWritten e))

            netWatcher <-
                watch
                    "*[System[(EventID=3)]]"
                    (EventHandler<EventRecordWrittenEventArgs>(fun _ e -> netEventRecordWritten e))
        with
        | :? EventLogNotFoundException ->
            onError.Trigger
                [| box
                    "Sysmon is not installed. Install it from the Sysmon Audit tab — spawn tracing needs it." |]
        | ex ->
            onError.Trigger [| box $"Failed to start python spawn watcher: {ex.Message}" |]

    member _.Stop() =
        if not (isNull spawnWatcher) then
            spawnWatcher.Dispose()
            spawnWatcher <- null

        if not (isNull exitWatcher) then
            exitWatcher.Dispose()
            exitWatcher <- null

        if not (isNull netWatcher) then
            netWatcher.Dispose()
            netWatcher <- null

    // ── Historical replay ────────────────────────────────────────────────

    /// <summary>
    /// Replays the last <paramref name="window"/> of EID 1 / EID 5 records
    /// from the Sysmon channel through the same handlers the live watchers
    /// use — so a tab opened after the fact shows what already ran, with
    /// parentage, venv pairing and Exited stamps intact. Spawns the live
    /// watcher already delivered are skipped (pid-keyed), so racing the
    /// live feed never double-adds a row. Returns the number of spawn rows
    /// replayed.
    /// </summary>
    member _.Backfill(window: TimeSpan, [<Optional; DefaultParameterValue(400)>] maxRows: int) : int =
        let mutable replayed = 0

        try
            let xpath =
                "*[System[(EventID=1 or EventID=5) and TimeCreated[timediff(@SystemTime) <= "
                + string (max 0 (int window.TotalMilliseconds))
                + "]]]"

            let records = ResizeArray<DateTime * EventRecord>()

            let query = EventLogQuery(ChannelName, PathType.LogName, xpath)

            use reader = new EventLogReader(query)
            let mutable evt = reader.ReadEvent()

            while not (isNull evt) do
                let stamp =
                    if evt.TimeCreated.HasValue then
                        evt.TimeCreated.Value.ToUniversalTime()
                    else
                        DateTime.MinValue

                records.Add((stamp, evt))
                evt <- reader.ReadEvent()

            // Newest-first for the cap, oldest-first for the replay
            let spawns =
                records
                    .Where(fun (stamp: DateTime, r: EventRecord) -> r.Id = 1)
                    .OrderByDescending(fun (stamp: DateTime, r: EventRecord) -> stamp)
                    .Take(maxRows)
                    .OrderBy(fun (stamp: DateTime, r: EventRecord) -> stamp)
                    .Select(fun (stamp: DateTime, r: EventRecord) -> r)
                    .ToList()

            let exits =
                records
                    .Where(fun (stamp: DateTime, r: EventRecord) -> r.Id = 5)
                    .Select(fun (stamp: DateTime, r: EventRecord) -> r)

            let replay =
                spawns
                    .Concat(exits)
                    .OrderBy(fun (r: EventRecord) ->
                        if r.TimeCreated.HasValue then
                            r.TimeCreated.Value.ToUniversalTime()
                        else
                            DateTime.MinValue)
                    .ToList()

            for evt in replay do
                if evt.Id = 1 then
                    if handleSpawnRecord evt true then replayed <- replayed + 1
                else
                    handleExitRecord evt

            for (_, evt) in records do
                evt.Dispose()
        with
        | :? EventLogNotFoundException ->
            onError.Trigger
                [| box
                    "Sysmon is not installed. Install it from the Sysmon Audit tab — spawn tracing needs it." |]
        | ex ->
            onError.Trigger [| box $"Spawn history replay failed: {ex.Message}" |]

        replayed

    /// <summary>
    /// Parse a Sysmon EID 1 record into a SpawnItem — null when the record
    /// is not a process-create, fails the image filter, or has no parseable
    /// pid. Shared by the live watcher and the taskhostw tab's historical
    /// backfill (TaskAttributionService.Backfill) so both paths build
    /// identical rows from the same field parsing.
    /// </summary>
    static member ParseSpawnRecord(record: EventRecord, imageFilter: Func<string, bool>, xmlKeyword: string) : SpawnItem =
        try
            if isNull (box record) || record.Id <> 1 then
                Unchecked.defaultof<SpawnItem>
            else
                let xml = record.ToXml()

                if
                    not (isNull xmlKeyword)
                    && xml.IndexOf(xmlKeyword, StringComparison.OrdinalIgnoreCase) < 0
                then
                    Unchecked.defaultof<SpawnItem>
                else
                    match SpawnField.parseFields xml with
                    | None -> Unchecked.defaultof<SpawnItem>
                    | Some fields when not (imageFilter.Invoke(SpawnField.getValue fields "Image")) ->
                        Unchecked.defaultof<SpawnItem>
                    | Some fields ->
                        let pid = SpawnField.parsePid (SpawnField.getValue fields "ProcessId")

                        if pid <= 0 then
                            Unchecked.defaultof<SpawnItem>
                        else
                            SpawnItem(
                                TimeUtc = SpawnField.parseUtcTime (SpawnField.getValue fields "UtcTime") record.TimeCreated,
                                Pid = pid,
                                ProcessGuid =
                                    (match SpawnField.getValue fields "ProcessGuid" with
                                     | null -> null
                                     | g -> g.Trim('{', '}')),
                                Image = SpawnField.getValue fields "Image",
                                CommandLine = SpawnField.getValue fields "CommandLine",
                                ParentPid = SpawnField.parsePid (SpawnField.getValue fields "ParentProcessId"),
                                ParentImage = SpawnField.getValue fields "ParentImage",
                                ParentCommandLine = SpawnField.getValue fields "ParentCommandLine",
                                User = SpawnField.getValue fields "User",
                                IntegrityLevel = SpawnField.getValue fields "IntegrityLevel",
                                Hashes = SpawnField.getValue fields "Hashes",
                                Source = "sysmon"
                            )
        with _ ->
            Unchecked.defaultof<SpawnItem>

    /// <summary>Python family filter: any path containing "python".</summary>
    static member IsPythonImage(image: string) : bool =
        not (String.IsNullOrEmpty image)
        && image.IndexOf("python", StringComparison.OrdinalIgnoreCase) >= 0

    /// <summary>taskhostw filter: the scheduled-task host binary exactly.</summary>
    static member IsTaskhostwImage(image: string) : bool =
        not (String.IsNullOrEmpty image)
        && image.EndsWith("taskhostw.exe", StringComparison.OrdinalIgnoreCase)

    member this.Dispose() =
        if not disposed then
            disposed <- true
            this.Stop()

    interface IDisposable with
        member this.Dispose() = this.Dispose()
