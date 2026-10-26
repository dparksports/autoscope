// F# port of Core\Services\SysmonArchiveService.cs (namespace AutoScope.Services)
// for the Engines library. The on-disk contract is the contract: the JSONL
// day-file format, the state.json watermark and the exact
// newest-first/early-exit search semantics must stay byte-compatible, so
// archive files written by the C# app keep parsing — validated by the
// offline self-test's synthetic-event section (watermark dedupe, rotation,
// search, prune, corrupt-line tolerance).
//
// F# port notes (deviations forced by F#, none behavioral on disk):
//   • C# nested types cannot nest in an F# class: what C# addressed as
//     SysmonArchiveService.ArchiveEvent is the top-level ArchiveEvent here
//     (import the namespace and drop the qualification). The private
//     ArchiveState became a file-private type — still invisible to C#.
//   • The C# default archive root hardcoded %LOCALAPPDATA%\AutoScope —
//     engines are app-agnostic, so the default now derives from
//     WatchConfig.Identity.DataRoot at first use (the property stays
//     settable so the offline self-test can redirect to a temp dir).
//   • The C# `public const int DefaultRetainDays` is a static property
//     backed by a private [<Literal>] — F# classes cannot emit const
//     fields; the value (30) is unchanged and callers read it the same.
//   • Optional parameters (accept = null) use
//     [<Optional; DefaultParameterValue(null)>], not F# `?` optionals —
//     F# optionals surface as FSharpOption<T> in metadata and would be
//     uncallable with the C# source's default-omission shapes.
//   • `int?`/`DateTime?` parameters are Nullable<int>/Nullable<DateTime>,
//     exactly the C# shapes (Search(null, null, null, 100) compiles as-is);
//     Prune()'s parameterless overload replaces the C# = DefaultRetainDays
//     default.
//   • Tuples are ValueTuple, matching the C# tuple returns.
// FS3211 fires on the [<Optional; DefaultParameterValue(null)>] below
// ("default value does not have the same type...") but the emitted
// metadata is what C# needs (IsOptional=true, default null) — see the
// Engines.Diagnosis Probe.fs header for the same note.
#nowarn "3211"

namespace AutoScope.Engines.Watch

open System
open System.Collections.Generic
open System.Diagnostics
open System.Diagnostics.Eventing.Reader
open System.IO
open System.Linq
open System.Runtime.InteropServices
open System.Text.Json
open System.Xml.Linq

/// <summary>An archived Sysmon event, every EventData field verbatim.
/// F# port: was the nested SysmonArchiveService.ArchiveEvent — top-level
/// here; the C# `get; init;` shape is a mutable property so C# object
/// initializers (`new ArchiveEvent { Eid = 1, ... }`) compile unchanged.
/// [<AllowNullLiteral>] keeps the C# `Append(null) == false` guard
/// expressible.</summary>
[<AllowNullLiteral>]
type ArchiveEvent() =
    member val TsUtc: DateTime = DateTime() with get, set
    member val Eid: int = 0 with get, set
    member val RecordId: int64 = 0L with get, set
    member val Data: Dictionary<string, string> = null with get, set

/// <summary>Watermark: the newest event archived, plus a running total.
/// F# port: was the C# private nested class. System.Text.Json's
/// reflection serializer emits {} for non-public F# classes (verified
/// against compiled private AND internal types), so this is public —
/// the one visibility widening the port forces; nothing else uses it.
/// Fields became properties with the same names so state.json
/// round-trips identically.</summary>
[<AllowNullLiteral>]
type ArchiveState() =
    member val LastRecordId: int64 = 0L with get, set
    member val LastUtc: Nullable<DateTime> = Nullable<DateTime>() with get, set
    member val TotalEvents: int64 = 0L with get, set

/// <summary>
/// App-managed archive of the Sysmon Operational channel. The channel
/// itself is a rolling window (192 MB ≈ half a busy day); this archive
/// is what makes "every spawn retroactively traceable" true for weeks:
///
///   - at every app start, the entire retained channel is backfilled
///     (same pattern as the BITS tracer), skipping events already
///     archived via a (recordId, utc) watermark
///   - while the app runs, every new Sysmon event is appended live
///   - storage is one readable, greppable JSONL file per day under
///     &lt;DataRoot&gt;\sysmon-archive, pruned after
///     DefaultRetainDays (disclosed here and on the Sysmon Audit card)
///
/// Every EventData field is preserved verbatim, so an archived EID 1 is
/// a complete substitute for the live one (command line, parent image,
/// hashes…). Unelevated sessions degrade silently: no channel access,
/// no archive writes — nothing crashes, nothing is guessed.
/// F# port: was a C# static class — [<AbstractClass; Sealed>] here; all
/// members stay static members with the same names.
/// </summary>
[<AbstractClass; Sealed>]
type SysmonArchiveService private () =

    [<Literal>]
    static let DefaultRetainDaysValue = 30

    // F# port: C# initialized this field to the hardcoded
    // %LOCALAPPDATA%\AutoScope\sysmon-archive path at type init. Engines
    // resolve the default lazily from the configured identity instead, so
    // nothing identity-dependent runs at type-initialization time and no
    // app name lives here. The override (offline self-test) is honored
    // exactly like the C# settable property.
    static let mutable archiveDirectoryOverride: string = null

    static let archiveDirectory () =
        match archiveDirectoryOverride with
        | null -> Path.Combine(WatchConfig.Identity.DataRoot, "sysmon-archive")
        | d -> d

    static let gate = obj ()

    static let mutable watcher: EventLogWatcher = null

    static let statePath () = Path.Combine(archiveDirectory (), "state.json")

    static let loadState () =
        try
            if File.Exists(statePath ()) then
                match JsonSerializer.Deserialize<ArchiveState>(File.ReadAllText(statePath ())) with
                | null -> ArchiveState()
                | st -> st
            else
                ArchiveState()
        with _ ->
            // corrupt state — an empty watermark just means the next
            // backfill re-reads the live channel; dedupe degrades to
            // "archive may hold a few boundary duplicates", never loss
            ArchiveState()

    static let saveState (st: ArchiveState) =
        try
            Directory.CreateDirectory(archiveDirectory ()) |> ignore
            File.WriteAllText(
                statePath (),
                JsonSerializer.Serialize(
                    st,
                    JsonSerializerOptions(WriteIndented = true)
                )
            )
        with _ ->
            // disk full / permissions — watermark stalls at last
            // good save; worst case is duplicate rows, never loss
            ()

    /// <summary>An event is "past the watermark" when it is newer than
    /// everything archived so far. RecordId alone is not enough: it
    /// resets when the log is cleared or Sysmon reinstalled, so time is
    /// the primary key and the id breaks exact ties.</summary>
    static let isPast (e: ArchiveEvent) (st: ArchiveState) =
        not st.LastUtc.HasValue
        || e.TsUtc > st.LastUtc.Value
        || (e.TsUtc = st.LastUtc.Value && e.RecordId > st.LastRecordId)

    static let fromRecord (rec_: EventRecord) =
        let data = Dictionary<string, string>()

        try
            // Named fields come from the event XML (the same parse the
            // Sysmon watcher uses) — Properties alone is position-only.
            let doc = XDocument.Parse(rec_.ToXml())
            let ns = XNamespace.Get("http://schemas.microsoft.com/win/2004/08/events/event")

            match doc.Root with
            | null -> ()
            | root ->
                match root.Element(ns + "EventData") with
                | null -> ()
                | eventData ->
                    for d in eventData.Elements(ns + "Data") do
                        match d.Attribute(XName.Get "Name") with
                        | null -> ()
                        | a -> data.[a.Value] <- d.Value
        with _ ->
            // unparseable payload — archive what we have
            ()

        // F# port: TimeCreated/RecordId are Nullable<...> — F# needs the
        // explicit HasValue dance where C# wrote `?? / ?? 0`.
        let tsUtc =
            let tc = rec_.TimeCreated
            if tc.HasValue then tc.Value.ToUniversalTime() else DateTime.UtcNow

        let rid =
            let r = rec_.RecordId
            if r.HasValue then r.Value else 0L

        ArchiveEvent(TsUtc = tsUtc, Eid = rec_.Id, RecordId = rid, Data = data)

    static let parseLine (line: string) (eidOverride: Nullable<int>) : ArchiveEvent =
        use doc = JsonDocument.Parse(line)
        let root = doc.RootElement
        let data = Dictionary<string, string>()

        for p in root.GetProperty("data").EnumerateObject() do
            data.[p.Name] <- (match p.Value.GetString() with null -> "" | s -> s)

        ArchiveEvent(
            TsUtc = DateTime
                        .Parse(root.GetProperty("ts").GetString(),
                               Globalization.CultureInfo.InvariantCulture,
                               Globalization.DateTimeStyles.AssumeUniversal)
                        .ToUniversalTime(),
            Eid = (if eidOverride.HasValue then eidOverride.Value else root.GetProperty("eid").GetInt32()),
            RecordId = root.GetProperty("rid").GetInt64(),
            Data = data
        )

    /// <summary>Archive root. Settable so the offline self-test can
    /// redirect persistence to a temp dir (house pattern).</summary>
    static member ArchiveDirectory
        with get () = archiveDirectory ()
        and set (value: string) = archiveDirectoryOverride <- value

    static member DefaultRetainDays = DefaultRetainDaysValue

    static member private DayFilePath(utc: DateTime) : string =
        Path.Combine(archiveDirectory (), "sysmon-archive-" + utc.ToString("yyyy-MM-dd") + ".jsonl")

    // ── append ────────────────────────────────────────────────────────

    /// <summary>Appends one event unless the watermark already covers
    /// it. Returns true when a line was written.</summary>
    static member Append(e: ArchiveEvent) : bool =
        if isNull e then
            false
        else
            lock gate (fun () ->
                let st = loadState ()
                if not (isPast e st) then false
                else
                    try
                        Directory.CreateDirectory(archiveDirectory ()) |> ignore

                        // F# port: same Dictionary<string, object> shape,
                        // same insertion order, same default serializer
                        // options — the emitted JSONL line is byte-identical
                        // to the C# app's, so both writers' files interleave.
                        let line = Dictionary<string, obj>()
                        line.["ts"] <- box (e.TsUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))
                        line.["eid"] <- box e.Eid
                        line.["rid"] <- box e.RecordId
                        line.["data"] <- box (match e.Data with null -> Dictionary<string, string>() | d -> d)

                        File.AppendAllText(
                            SysmonArchiveService.DayFilePath(e.TsUtc),
                            JsonSerializer.Serialize(line) + Environment.NewLine
                        )

                        st.LastRecordId <- e.RecordId
                        st.LastUtc <- Nullable e.TsUtc
                        st.TotalEvents <- st.TotalEvents + 1L
                        saveState st
                        true
                    with ex ->
                        Debug.WriteLine("SysmonArchive append failed: " + ex.Message)
                        false
            )

    // ── live channel → archive events ────────────────────────────────

    /// <summary>
    /// Backfills everything the live channel still holds, oldest→newest,
    /// skipping events the watermark already covers. Cheap precheck: if
    /// the channel's newest record is not past the watermark, returns 0
    /// without scanning. Returns the number of events appended. An
    /// unelevated session gets an unauthorized read and returns 0.
    /// </summary>
    static member Backfill() : int =
        try
            // Precheck: newest live record vs watermark
            let newestQuery = EventLogQuery(
                "Microsoft-Windows-Sysmon/Operational",
                PathType.LogName
            )
            newestQuery.ReverseDirection <- true

            use newestReader = new EventLogReader(newestQuery)
            let newest = newestReader.ReadEvent()

            if isNull newest then
                0
            else
                use _newest = newest

                let skip =
                    lock gate (fun () ->
                        let st0 = loadState ()
                        not (isPast (fromRecord newest) st0))

                if skip then
                    0
                else
                    let mutable appended = 0
                    let query = EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName)
                    use reader = new EventLogReader(query)

                    let mutable current = reader.ReadEvent()

                    while not (isNull current) do
                        let rec_ = current
                        use _rec = rec_

                        if SysmonArchiveService.Append(fromRecord rec_) then
                            appended <- appended + 1

                        current <- reader.ReadEvent()

                    appended
        with
        | :? UnauthorizedAccessException ->
            Debug.WriteLine("SysmonArchive backfill: channel not readable (session not elevated).")
            0
        | ex ->
            Debug.WriteLine("SysmonArchive backfill failed: " + ex.Message)
            0

    /// <summary>Appends every Sysmon event as it arrives. Idempotent;
    /// no-op when the channel is missing or unreadable.</summary>
    static member StartLiveWatch() : unit =
        lock gate (fun () ->
            if not (isNull watcher) then
                ()
            else
                try
                    let w =
                        new EventLogWatcher(
                            EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName)
                        )
                    watcher <- w

                    w.EventRecordWritten.AddHandler(fun _ e ->
                        if isNull e.EventRecord then
                            ()
                        else
                            try
                                SysmonArchiveService.Append(fromRecord e.EventRecord) |> ignore
                            with _ ->
                                // one bad event must not unwind the watcher
                                ())

                    w.Enabled <- true
                with ex ->
                    watcher <- null
                    Debug.WriteLine("SysmonArchive live watch unavailable: " + ex.Message)
        )

    static member StopLiveWatch() : unit =
        lock gate (fun () ->
            if not (isNull watcher) then
                watcher.Dispose()
            watcher <- null
        )

    // ── retention ─────────────────────────────────────────────────────

    /// <summary>Deletes day files older than retainDays and drops their
    /// counts from the state. Returns files removed.</summary>
    static member Prune(retainDays: int) : int =
        try
            if not (Directory.Exists(archiveDirectory ())) then 0
            else
                let cutoff = DateTime.UtcNow.Date.AddDays(float -retainDays)
                let st = loadState ()
                let mutable removed = 0

                for file in Directory.GetFiles(archiveDirectory (), "sysmon-archive-*.jsonl") do
                    let stem =
                        Path.GetFileName(file)
                            .Substring("sysmon-archive-".Length)
                            .Replace(".jsonl", "")

                    match DateTime.TryParseExact(stem, "yyyy-MM-dd", null, Globalization.DateTimeStyles.None) with
                    | true, day when day < cutoff ->
                        try
                            let lines = File.ReadLines(file).Count()
                            File.Delete(file)
                            removed <- removed + 1
                            st.TotalEvents <- Math.Max(0L, st.TotalEvents - int64 lines)
                        with _ ->
                            // in use / locked — try again next start
                            ()
                    | _ -> ()

                if removed > 0 then saveState st
                removed
        with _ ->
            0

    /// <summary>See <c>Prune(retainDays)</c>. F# port: overload for the
    /// C# `Prune()` call shape (was `retainDays = DefaultRetainDays`).</summary>
    static member Prune() : int = SysmonArchiveService.Prune(DefaultRetainDaysValue)

    // ── queries (live channel first is the CALLER's job; these read the
    //    archive only — the overlap case is handled by preferring the
    //    live log and falling back here) ──────────────────────────────

    /// <summary>Newest-first search over archived events. `contains`
    /// matches any data value (case-insensitive).</summary>
    static member Search(eid: Nullable<int>, contains: string, sinceUtc: Nullable<DateTime>, max: int)
                        : ResizeArray<ArchiveEvent> =
        SysmonArchiveService.searchCore (eid, contains, sinceUtc, max, null)

    /// <summary>Newest-first EID 1 create-events for a PID — the
    /// archive-backed twin of the PID Inquiry's live lookup. Streamed:
    /// the pid predicate runs per line, not over a materialized list.</summary>
    static member SearchCreateEvents(pid: int, max: int) : ResizeArray<ArchiveEvent> =
        SysmonArchiveService.searchCore (
            Nullable 1,
            null,
            Nullable<DateTime>(),
            max,
            Func<Dictionary<string, string>, bool>(fun d ->
                match d.TryGetValue("ProcessId") with
                | true, v -> v = pid.ToString()
                | _ -> false)
        )

    /// <summary>
    /// The newest EID-3 connection attempt per requested destination IP —
    /// ONE streaming pass over the archive (newest-first, early-exits
    /// once every requested IP has a hit) instead of a full scan per IP.
    /// Serves the Blocks tab's "last traffic" column and the block
    /// attribution repair: Sysmon logs attempts even when the firewall
    /// drops them, so blocked IPs still resolve. IPs with no archived
    /// attempt are simply absent from the result.
    /// </summary>
    static member NewestConnectionPerIp(ips: IEnumerable<string>,
                                        [<Optional; DefaultParameterValue(null)>] accept: Func<ArchiveEvent, bool>)
                                        : Dictionary<string, ArchiveEvent> =
        SysmonArchiveService.newestBy (
            3,
            HashSet<string>(ips, StringComparer.OrdinalIgnoreCase),
            Func<ArchiveEvent, string>(fun e ->
                match e.Data.TryGetValue("DestinationIp") with
                | true, dip -> dip
                | _ -> null),
            accept
        )

    /// <summary>Same single-pass index, keyed by the connecting image
    /// path — the proc-block twin of NewestConnectionPerIp.</summary>
    static member NewestConnectionPerImage(images: IEnumerable<string>,
                                           [<Optional; DefaultParameterValue(null)>] accept: Func<ArchiveEvent, bool>)
                                           : Dictionary<string, ArchiveEvent> =
        SysmonArchiveService.newestBy (
            3,
            HashSet<string>(images, StringComparer.OrdinalIgnoreCase),
            Func<ArchiveEvent, string>(fun e ->
                match e.Data.TryGetValue("Image") with
                | true, img when img.Length > 0 -> img
                | _ -> null),
            accept
        )

    /// <summary>Newest EID-1 create-event per PID, single pass — the
    /// batched replacement for per-PID SearchCreateEvents scans when a
    /// repair needs creates for many PIDs at once.</summary>
    static member NewestCreateEventPerPid(pids: IEnumerable<int>) : Dictionary<string, ArchiveEvent> =
        SysmonArchiveService.newestBy (
            1,
            HashSet<string>(pids.Select(fun p -> p.ToString()), StringComparer.OrdinalIgnoreCase),
            Func<ArchiveEvent, string>(fun e ->
                match e.Data.TryGetValue("ProcessId") with
                | true, v when v.Length > 0 -> v
                | _ -> null),
            null
        )

    /// <summary>
    /// One streaming newest-first walk of the archive for one event-id,
    /// keeping the newest match per requested key. Early-exits once every
    /// key is found. `contains` prefilter by eid keeps parsing cheap.
    /// </summary>
    static member private newestBy(eid: int,
                                   wanted: HashSet<string>,
                                   keyOf: Func<ArchiveEvent, string>,
                                   accept: Func<ArchiveEvent, bool>) : Dictionary<string, ArchiveEvent> =
        let found = Dictionary<string, ArchiveEvent>(StringComparer.OrdinalIgnoreCase)
        if wanted.Count = 0 then found
        else
            let marker = $"\"eid\":{eid},"

            try
                if not (Directory.Exists(archiveDirectory ())) then found
                else
                    let files =
                        Directory.GetFiles(archiveDirectory (), "sysmon-archive-*.jsonl")
                        |> Array.sortWith (fun a b -> StringComparer.Ordinal.Compare(b, a))

                    let mutable stop = false

                    for file in files do
                        if stop || wanted.Count = 0 then ()
                        else
                            let lines = File.ReadAllLines(file)
                            let mutable li = lines.Length - 1

                            while li >= 0 && wanted.Count > 0 do
                                let line = lines.[li]

                                if line.Length = 0 || line.IndexOf(marker, StringComparison.Ordinal) < 0 then
                                    ()
                                else
                                    try
                                        use doc = JsonDocument.Parse(line)
                                        let root = doc.RootElement

                                        if root.GetProperty("eid").GetInt32() <> eid then ()
                                        else
                                            let data = Dictionary<string, string>()

                                            for p in root.GetProperty("data").EnumerateObject() do
                                                data.[p.Name] <- (match p.Value.GetString() with null -> "" | s -> s)

                                            let e =
                                                ArchiveEvent(
                                                    TsUtc = DateTime
                                                                .Parse(root.GetProperty("ts").GetString(),
                                                                       Globalization.CultureInfo.InvariantCulture,
                                                                       Globalization.DateTimeStyles.AssumeUniversal)
                                                                .ToUniversalTime(),
                                                    Eid = eid,
                                                    RecordId = root.GetProperty("rid").GetInt64(),
                                                    Data = data
                                                )

                                            let key = keyOf.Invoke(e)

                                            if isNull key || not (wanted.Remove key) then
                                                () // already found, or not requested
                                            elif not (isNull accept) && not (accept.Invoke e) then
                                                wanted.Add key |> ignore
                                            else
                                                found.[key] <- e
                                    with _ ->
                                        ()

                                li <- li - 1

                            if wanted.Count = 0 then stop <- true
                    found
            with _ ->
                // unreadable archive — partial result, never a throw
                found

    static member private searchCore(eid: Nullable<int>,
                                     contains: string,
                                     sinceUtc: Nullable<DateTime>,
                                     max: int,
                                     dataFilter: Func<Dictionary<string, string>, bool>) : ResizeArray<ArchiveEvent> =
        let hits = ResizeArray<ArchiveEvent>()

        try
            if not (Directory.Exists(archiveDirectory ())) then hits
            else
                let files =
                    Directory.GetFiles(archiveDirectory (), "sysmon-archive-*.jsonl")
                    |> Array.sortWith (fun a b -> StringComparer.Ordinal.Compare(b, a))

                let mutable stop = false

                for file in files do
                    if stop || hits.Count >= max then ()
                    else
                        // whole-day skip when the file predates the window
                        let stem =
                            Path.GetFileName(file)
                                .Substring("sysmon-archive-".Length)
                                .Replace(".jsonl", "")

                        let daySkip =
                            sinceUtc.HasValue
                            && (match DateTime.TryParseExact(stem, "yyyy-MM-dd", null, Globalization.DateTimeStyles.None) with
                                | true, day -> day < sinceUtc.Value.Date
                                | _ -> false)

                        if daySkip then ()
                        else
                            // lines are appended oldest→newest; newest-first result
                            // means walking each day file bottom-up
                            let lines = File.ReadAllLines(file)
                            let mutable li = lines.Length - 1

                            while li >= 0 && hits.Count < max do
                                let line = lines.[li]

                                if line.Length = 0 then ()
                                else
                                    try
                                        let e = parseLine line (Nullable<int>())

                                        let take =
                                            (not eid.HasValue || e.Eid = eid.Value)
                                            && (not sinceUtc.HasValue || e.TsUtc >= sinceUtc.Value)
                                            && (String.IsNullOrEmpty contains
                                                || e.Data.Values |> Seq.exists (fun v ->
                                                    not (isNull v)
                                                    && v.Contains(contains, StringComparison.OrdinalIgnoreCase)))
                                            && (isNull dataFilter || dataFilter.Invoke e.Data)

                                        if take then hits.Add e
                                    with _ ->
                                        // truncated/corrupt line — skip it, keep the file
                                        ()

                                li <- li - 1

                            if hits.Count >= max then stop <- true
                hits
        with _ ->
            // unreadable archive — empty result, never a throw
            hits

    /// <summary>(day files, total events) for the Sysmon Audit card.</summary>
    static member StatusSummary() : ValueTuple<int, int64> =
        try
            if not (Directory.Exists(archiveDirectory ())) then struct (0, 0L)
            else
                let days = Directory.GetFiles(archiveDirectory (), "sysmon-archive-*.jsonl").Length
                struct (days, (loadState ()).TotalEvents)
        with _ ->
            struct (0, 0L)
