// F# port of Core\Services\TaskAttributionService.cs + Core\Services\
// KnownTaskCatalog.cs (namespace AutoScope.Services) for the Engines.Watch
// library. Behavioral faithfulness is the contract: same two-key join
// (scheduler instance GUID + EID 129 PID), same stitch window, same caps,
// same handler-resolution registry hives, same verdict strings.
//
// F# port notes (deviations forced by F#, none behavioral):
//   • TaskLaunchInfo's C# public FIELDS became properties (member val …
//     with get, set) — same names, same null-able/mutable semantics, and
//     the C# `??=` / object-initializer call shapes keep compiling. The
//     type carries [<AllowNullLiteral>] so F# code can express the C#
//     null semantics ("unknown / not a task host") directly.
//   • C# events (event Action<string> OnError, event Action<TaskLaunchInfo>
//     OnAttributionUpdated) port to [<CLIEvent>] members over
//     DelegateEvent<Action<…>> — from C# the += surface and delegate types
//     are identical.
//   • The C# private instance helpers (ReplayScheduler, ForPid, LinkGuid,
//     ResolveTarget, the watcher handlers, …) are let-bound functions in
//     the constructor scope — same file-private visibility. The two
//     C# private STATIC helpers that only touch their argument
//     (ResolveHandler, UpdateVerdict) stay static members.
//   • The C# private static field helpers (ParseFields/Get/ParseInt/
//     MatchInt) are a private module above the types. FormatDescription
//     is wrapped defensively there (null out, never throw) exactly like
//     C#'s MatchInt null handling.
//   • KnownTaskCatalog: C# read Assets\known-tasks.json from
//     AppContext.BaseDirectory. The directory now routes through an
//     optional baseDir parameter (null → AppContext.BaseDirectory), so a
//     host app can point the catalog at its own install root — the one
//     deliberate path change, per the Engines rule that no engine bakes
//     in an install path.
//   • The C# optional int defaults (Backfill maxRows = 400,
//     GetRecentLaunches max = 50) use [<Optional; DefaultParameterValue>],
//     which surfaces as real C# defaults.
//   • GetTaskForPid keeps its two C# overloads (they are overloads in C#,
//     not default parameters).
//   • Private handler names lost their underscores (F# forbids '_' in
//     member names).

namespace AutoScope.Engines.Watch

open System
open System.Collections.Concurrent
open System.Collections.Generic
open System.Diagnostics
open System.Diagnostics.Eventing.Reader
open System.Globalization
open System.IO
open System.Linq
open System.Runtime.InteropServices
open System.Text.Json
open System.Text.RegularExpressions
open System.Xml.Linq
open Microsoft.Win32

// ── private field plumbing (the C# file's private statics) ─────────

module private TaskParse =

    let parseFields (xml: string) : Dictionary<string, string> option =
        let doc = XDocument.Parse(xml)
        let ns = XNamespace.Get("http://schemas.microsoft.com/win/2004/08/events/event")

        let eventData =
            if isNull (box doc.Root) then null else doc.Root.Element(ns + "EventData")

        if isNull (box eventData) then
            None
        else
            // Case-insensitive on purpose: scheduler events mix spellings
            // (EID 129 says "ProcessID", 100/102 say "ProcessId")
            let fields = Dictionary<string, string>(16, StringComparer.OrdinalIgnoreCase)

            for data in eventData.Elements(ns + "Data") do
                match data.Attribute(XName.Get("Name")) with
                | null -> ()
                | attr when not (fields.ContainsKey(attr.Value)) -> fields.[attr.Value] <- data.Value
                | _ -> ()

            Some fields

    let get (fields: Dictionary<string, string>) (name: string) : string =
        match fields.TryGetValue(name) with
        | true, value -> value
        | _ -> null

    let parseInt (value: string) : int option =
        let mutable v = 0

        if
            not (isNull value)
            && Int32.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, &v)
        then
            Some v
        else
            None

    /// <summary>Field-name fallback for events whose EventData names vary
    /// by build: dig the number out of the formatted message. Never
    /// throws — a null message (or a failing formatter) reads as no
    /// match.</summary>
    let matchInt (message: string) (regex: Regex) : int option =
        try
            let m = regex.Match(match message with null -> String.Empty | msg -> msg)
            let mutable v = 0

            if m.Success && Int32.TryParse(m.Groups.[1].Value, &v) then Some v else None
        with _ ->
            None

    /// <summary>C# called record.FormatDescription() inline; it can throw
    /// for exotic publishers — wrapped so the try in
    /// HandleTaskSchedulerRecord keeps its "one bad record never stops
    /// the watcher" meaning. Null is handled by matchInt.</summary>
    let formatDescription (record: EventRecord) : string =
        try
            record.FormatDescription()
        with _ ->
            null

/// <summary>
/// Attribution for a taskhostw.exe instance: the Task Scheduler events
/// narrating the launch (129 names the task and the PID directly; 100/102
/// carry the instance GUID and user context; 107/108/119 say why it
/// fired; 201 carries the action's return code), plus what code the task
/// actually runs.
/// F# port: the C# public fields are properties with the same names;
/// [<AllowNullLiteral>] so "no attribution yet" is expressible as null,
/// exactly the C# semantics.
/// </summary>
[<AllowNullLiteral>]
type TaskLaunchInfo() =

    member val InstanceGuid: string = null with get, set
    member val TaskPath: string = null with get, set // e.g. "\Microsoft\Windows\Foo\Bar"
    member val UserContext: string = null with get, set // account the task ran as
    member val ProcessId: int = 0 with get, set // taskhostw PID (from Sysmon EID 1 or scheduler EID 129)
    member val ProcessGuid: string = null with get, set // Sysmon's per-boot unique process identity (braces stripped)
    member val CommandLine: string = null with get, set
    member val StartedAt: Nullable<DateTime> = Nullable<DateTime>() with get, set // scheduler EID 100 (or 129 launch time)
    member val CompletedAt: Nullable<DateTime> = Nullable<DateTime>() with get, set // scheduler EID 102

    // Why it fired — scheduler EID 107 (timer), 108 (event), 119 (logon).
    member val TriggerReason: string = null with get, set

    // How it ended — scheduler EID 201 carries the action's return code
    // (0 = nothing to do / success); 203 is the engine's failure record.
    member val ReturnCode: Nullable<int> = Nullable<int>() with get, set
    member val CompletedSuccessfully: Nullable<bool> = Nullable<bool>() with get, set
    member val ActionName: string = null with get, set // scheduler EID 200/201 friendly action name

    // COM-handler evidence: what code the task actually runs. A task with
    // a ClassId whose DLL is missing is an orphan (its software is gone).
    member val HandlerClassId: string = null with get, set
    member val HandlerDll: string = null with get, set
    member val HandlerDllCompany: string = null with get, set
    member val HandlerDllVersion: string = null with get, set
    member val HandlerDllExists: Nullable<bool> = Nullable<bool>() with get, set

    // Inbox / Third-party / Orphaned; null while the task is unresolved.
    member val Verdict: string = null with get, set

    member val FirstSeenUtc: DateTime = DateTime.UtcNow with get, set // prune ordering

    member this.DurationSeconds: Nullable<float> =
        if this.StartedAt.HasValue && this.CompletedAt.HasValue then
            Nullable(Math.Max(0.0, (this.CompletedAt.Value - this.StartedAt.Value).TotalSeconds))
        else
            Nullable<float>()

/// <summary>
/// Answers "who/what/why" for taskhostw processes by stitching two logs
/// together per launch:
///
///   Sysmon EID 1        the spawn itself (pid, command line, parentage)
///   Task Scheduler      107/108/119 why it fired · 129 task name + pid ·
///                      100/102 instance GUID + user context, start/finish ·
///                      200/201/203 action launched / completed (return
///                      code) / failed
///
/// The join has two keys and both are needed: the instance GUID on the
/// command line ("taskhostw.exe {222A245B-…}") and the PID in EID 129.
/// Many ComHandler tasks pass only their handler data —
/// "taskhostw.exe Install $(arg0)" carries no GUID at all — so EID 129 is
/// the only attribution path for them.
///
/// The Task Scheduler operational channel is disabled on many systems; it
/// is enabled here once (requires admin) so future launches can be
/// attributed. Launches before that are unrecoverable live, but Backfill
/// replays whatever the channel retained. Disabling a task for good is
/// handled by the app's TaskSchedulerService.SetTaskEnabledAsync.
/// </summary>
type TaskAttributionService() =

    static let TaskSchedulerLog = "Microsoft-Windows-TaskScheduler/Operational"
    static let SysmonLog = "Microsoft-Windows-Sysmon/Operational"

    static let SchedulerXPath =
        "*[System[(EventID=100 or EventID=102 or EventID=107 or EventID=108 or "
        + "EventID=119 or EventID=129 or EventID=200 or EventID=201 or EventID=203)]]"

    static let InstanceGuidRegex = Regex(@"\{([0-9A-Fa-f\-]{36})\}", RegexOptions.Compiled)
    static let MessagePidRegex = Regex(@"process ID (\d+)", RegexOptions.Compiled)
    static let MessageReturnCodeRegex = Regex(@"return code (-?\d+)", RegexOptions.Compiled)

    let onError = DelegateEvent<Action<string>>()
    let onAttributionUpdated = DelegateEvent<Action<TaskLaunchInfo>>()

    let mutable sysmonProcessWatcher: EventLogWatcher = null // Sysmon EID1 — taskhostw spawns
    let mutable sysmonExitWatcher: EventLogWatcher = null // Sysmon EID5 — dead pids get evicted
    let mutable taskInstanceWatcher: EventLogWatcher = null // Task Scheduler launch narrative

    // Both maps hold the same objects once a launch is fully stitched
    // together; until then linkGuid folds the halves together. The cap
    // bounds a long session — pruned entries only cost late attribution
    // for pids whose rows are long gone from the views anyway.
    let byPid = ConcurrentDictionary<int, TaskLaunchInfo>()
    let byGuid = ConcurrentDictionary<string, TaskLaunchInfo>(StringComparer.OrdinalIgnoreCase)

    // Sysmon's ProcessGuid (kernel-assigned, unique for the whole boot)
    // → launch. A DIFFERENT guid namespace from byGuid's scheduler
    // instance GUIDs; this is the one key PID recycling can never
    // collide on, and its entries are evicted by Sysmon EID 5.
    let byProcGuid = ConcurrentDictionary<string, TaskLaunchInfo>(StringComparer.OrdinalIgnoreCase)

    static let TrackedCap = 20000
    static let StitchWindowSeconds = 30.0

    let mutable historyChannelEnabled = false

    // ── private helpers (the C# private methods, as let functions) ────

    let foldInto (target: TaskLaunchInfo) (source: TaskLaunchInfo) =
        // Copies the GUID-side half's facts onto the PID-side half before
        // the two are linked.
        if isNull source || obj.ReferenceEquals(target, source) then
            ()
        else
            if isNull target.TriggerReason then target.TriggerReason <- source.TriggerReason
            if isNull target.UserContext then target.UserContext <- source.UserContext
            if not target.StartedAt.HasValue then target.StartedAt <- source.StartedAt
            if not target.CompletedAt.HasValue then target.CompletedAt <- source.CompletedAt
            if not target.ReturnCode.HasValue then target.ReturnCode <- source.ReturnCode
            if isNull target.ActionName then target.ActionName <- source.ActionName

    let pruneIfNeeded () =
        if byPid.Count >= TrackedCap then
            let victims =
                byPid
                    .OrderBy(fun (kv: KeyValuePair<int, TaskLaunchInfo>) -> kv.Value.FirstSeenUtc)
                    .Take(max 1 (byPid.Count / 10))
                    .Select(fun (kv: KeyValuePair<int, TaskLaunchInfo>) -> kv.Key)
                    .ToList()

            for key in victims do
                byPid.TryRemove(key) |> ignore

        if byGuid.Count >= TrackedCap then
            let victims =
                byGuid
                    .OrderBy(fun (kv: KeyValuePair<string, TaskLaunchInfo>) -> kv.Value.FirstSeenUtc)
                    .Take(max 1 (byGuid.Count / 10))
                    .Select(fun (kv: KeyValuePair<string, TaskLaunchInfo>) -> kv.Key)
                    .ToList()

            for key in victims do
                byGuid.TryRemove(key) |> ignore

        if byProcGuid.Count >= TrackedCap then
            let victims =
                byProcGuid
                    .OrderBy(fun (kv: KeyValuePair<string, TaskLaunchInfo>) -> kv.Value.FirstSeenUtc)
                    .Take(max 1 (byProcGuid.Count / 10))
                    .Select(fun (kv: KeyValuePair<string, TaskLaunchInfo>) -> kv.Key)
                    .ToList()

            for key in victims do
                byProcGuid.TryRemove(key) |> ignore

    let forPid (pid: int) : TaskLaunchInfo =
        byPid.GetOrAdd(
            pid,
            (fun _ ->
                pruneIfNeeded ()
                TaskLaunchInfo(ProcessId = pid, FirstSeenUtc = DateTime.UtcNow))
        )

    let forGuid (guid: string) : TaskLaunchInfo =
        byGuid.GetOrAdd(
            guid.Trim('{', '}'),
            (fun key ->
                pruneIfNeeded ()
                TaskLaunchInfo(InstanceGuid = key, FirstSeenUtc = DateTime.UtcNow))
        )

    /// <summary>
    /// Fold the pid-keyed object into the guid-keyed one (or register it
    /// as the canonical object). The two maps can hold different objects
    /// for the same launch — Sysmon's create event and the scheduler's
    /// GUID-bearing events each discover the instance independently — and
    /// every later fact must land on the one object the row reads through
    /// GetTaskForPid.
    /// </summary>
    let linkGuid (info: TaskLaunchInfo) (guid: string) =
        if isNull info.InstanceGuid then info.InstanceGuid <- guid.Trim('{', '}')

        let canonical = byGuid.GetOrAdd(info.InstanceGuid, info)

        if not (obj.ReferenceEquals(canonical, info)) then
            canonical.ProcessId <- info.ProcessId

            if isNull canonical.CommandLine then canonical.CommandLine <- info.CommandLine

            if info.ProcessId > 0 then byPid.[info.ProcessId] <- canonical

    /// <summary>
    /// Registers the Sysmon ProcessGuid side of a launch. Live watching
    /// and Backfill can discover the same launch twice; both fold onto
    /// the canonical object and the pid map is re-pointed at it.
    /// </summary>
    let linkProcGuid (info: TaskLaunchInfo) (procGuid: string) =
        if isNull info.ProcessGuid then info.ProcessGuid <- procGuid.Trim('{', '}')

        let canonical = byProcGuid.GetOrAdd(info.ProcessGuid, info)

        if not (obj.ReferenceEquals(canonical, info)) then
            canonical.ProcessId <- info.ProcessId

            if isNull canonical.CommandLine then canonical.CommandLine <- info.CommandLine
            if not canonical.StartedAt.HasValue then canonical.StartedAt <- info.StartedAt

            if info.ProcessId > 0 then byPid.[info.ProcessId] <- canonical

    let notify (info: TaskLaunchInfo) =
        if not (isNull info) && info.ProcessId > 0 then
            onAttributionUpdated.Trigger [| box info |]

    /// <summary>Sysmon-side half of a launch: registers/updates the pid entry and links the command-line GUID when present.</summary>
    let feedSysmonItem (item: SpawnItem) =
        let info = forPid item.Pid

        if isNull info.CommandLine then info.CommandLine <- item.CommandLine

        // The spawn time binds this attribution to THIS tenant of the
        // PID — GetTaskForPid's time guard depends on it once the
        // number gets recycled onto a later process.
        if not info.StartedAt.HasValue then info.StartedAt <- Nullable item.TimeUtc

        if not (String.IsNullOrEmpty item.ProcessGuid) then linkProcGuid info item.ProcessGuid

        let cmdLine = (if isNull item.CommandLine then String.Empty else item.CommandLine)
        let guidMatch = InstanceGuidRegex.Match(cmdLine)

        if guidMatch.Success then linkGuid info guidMatch.Groups.[1].Value

    /// <summary>
    /// Target object for a GUID-bearing scheduler event. EID 129 carries
    /// the taskhostw PID but no InstanceId, so a launch whose command line
    /// had no GUID ("taskhostw.exe Install $(arg0)") splits in two: a
    /// PID-keyed half (task path, handler) and a GUID-keyed half (trigger,
    /// user context, result). Resolution order: already stitched → EnginePID
    /// exact join (200/201 carry the taskhostw PID) → task-path + time
    /// proximity (the scheduler writes a whole launch sequence within a
    /// second or two) → plain GUID side. Null when the event offers no
    /// handle at all.
    /// </summary>
    let resolveTarget (fields: Dictionary<string, string>) (taskName: string) (instanceId: string) (record: EventRecord) : TaskLaunchInfo =
        if String.IsNullOrEmpty instanceId then
            let enginePid = (match TaskParse.parseInt (TaskParse.get fields "EnginePID") with Some v -> v | None -> 0)

            if enginePid > 0 then
                match byPid.TryGetValue(enginePid) with
                | true, tracked -> tracked
                | _ -> null
            else
                null
        else
            let key = instanceId.Trim('{', '}')

            let guidSide =
                match byGuid.TryGetValue(key) with
                | true, side -> Some side
                | _ -> None

            match guidSide with
            | Some side when side.ProcessId > 0 ->
                side // already stitched to a pid
            | _ ->
                let guidSideValue = (match guidSide with Some g -> g | None -> null)

                // Exact join first: 200/201's EnginePID is the taskhostw process.
                // Only adopt an already-tracked pid — untracked engine pids belong
                // to non-taskhostw task actions (cmd.exe…) and must not pollute.
                let ep = (match TaskParse.parseInt (TaskParse.get fields "EnginePID") with Some v -> v | None -> 0)

                let pidSide =
                    if ep > 0 then
                        match byPid.TryGetValue(ep) with
                        | true, side when isNull side.InstanceGuid -> Some side
                        | _ -> None
                    else
                        None

                let exactJoined =
                    match pidSide with
                    | Some byPidSide ->
                        foldInto byPidSide guidSideValue
                        byPidSide.InstanceGuid <- key
                        byGuid.[key] <- byPidSide
                        Some byPidSide
                    | None -> None

                let proximityJoined =
                    if exactJoined.IsSome then
                        exactJoined
                    else
                        // Proximity join: same task, launch sequence in flight,
                        // pid half not yet GUID-linked.
                        if
                            not (String.IsNullOrEmpty taskName)
                            && record.TimeCreated.HasValue
                        then
                            let t = record.TimeCreated.Value
                            let mutable best: TaskLaunchInfo = null
                            let mutable bestDelta = StitchWindowSeconds

                            for candidate in byPid.Values do
                                if
                                    isNull candidate.InstanceGuid
                                    && String.Equals(candidate.TaskPath, taskName, StringComparison.OrdinalIgnoreCase)
                                then
                                    let stamp =
                                        if candidate.StartedAt.HasValue then
                                            candidate.StartedAt.Value
                                        else
                                            candidate.FirstSeenUtc

                                    let delta = abs ((t.ToUniversalTime() - stamp).TotalSeconds)

                                    if delta <= bestDelta then
                                        best <- candidate
                                        bestDelta <- delta

                            if not (isNull best) then
                                foldInto best guidSideValue
                                best.InstanceGuid <- key
                                byGuid.[key] <- best
                                Some best
                            else
                                None
                        else
                            None

                match proximityJoined with
                | Some target -> target
                | None ->
                    (match guidSide with
                     | Some side -> side
                     | None -> forGuid key)

    let sysmonProcessCreate (e: EventRecordWrittenEventArgs) =
        try
            let item =
                ImageSpawnWatcherService.ParseSpawnRecord(
                    e.EventRecord,
                    Func<string, bool>(ImageSpawnWatcherService.IsTaskhostwImage),
                    "taskhostw"
                )

            if not (isNull (box item)) then
                feedSysmonItem item

                notify (
                    match byPid.TryGetValue(item.Pid) with
                    | true, info -> info
                    | _ -> null
                )
        with _ ->
            ()

    /// <summary>
    /// A tracked taskhostw exited (Sysmon EID 5): drop its PID-keyed
    /// attribution so the number cannot hand this task to whatever
    /// process inherits it next. The scheduler-GUID and ProcessGuid maps
    /// keep their entries — those keys are unique and rows already
    /// holding the object keep enriching until the last completion
    /// events land. Eviction happens in the live watcher and in the
    /// backfill replay, so even a freshly opened tab never attributes
    /// through an exited pid.
    /// </summary>
    let handleProcessStopped (fields: Dictionary<string, string> option) =
        match fields with
        | None -> ()
        | Some fields ->
            let rawGuid = TaskParse.get fields "ProcessGuid"
            let key = (if isNull rawGuid then String.Empty else rawGuid).Trim('{', '}')

            if key.Length > 0 then
                match byProcGuid.TryRemove(key) with
                | true, info ->
                    let rawUtc = TaskParse.get fields "UtcTime"
                    let mutable exited = DateTime()

                    if
                        not (isNull rawUtc)
                        && DateTime.TryParse(
                            rawUtc,
                            null,
                            DateTimeStyles.AssumeUniversal ||| DateTimeStyles.AdjustToUniversal,
                            &exited
                        )
                        && not info.CompletedAt.HasValue
                    then
                        info.CompletedAt <- Nullable exited

                    // Only evict the pid mapping while it still points at THIS
                    // tenant — if the number was already recycled onto a newer
                    // launch, that launch owns the mapping now.
                    if info.ProcessId > 0 then
                        match byPid.TryGetValue(info.ProcessId) with
                        | true, current when obj.ReferenceEquals(current, info) ->
                            byPid.TryRemove(info.ProcessId) |> ignore
                        | _ -> ()
                | _ -> ()

    let sysmonProcessStopped (e: EventRecordWrittenEventArgs) =
        try
            if not (isNull (box e.EventRecord)) then
                handleProcessStopped (TaskParse.parseFields (e.EventRecord.ToXml()))
        with _ ->
            ()

    let handleTaskSchedulerRecord (record: EventRecord) =
        try
            match TaskParse.parseFields (record.ToXml()) with
            | None -> ()
            | Some fields ->
                let taskName = TaskParse.get fields "TaskName"

                // 100-series events call it InstanceId; 200/201 say TaskInstanceId
                let rawInstanceId = TaskParse.get fields "InstanceId"

                let instanceIdRaw =
                    (if isNull rawInstanceId then TaskParse.get fields "TaskInstanceId" else rawInstanceId)

                let instanceId = (if isNull instanceIdRaw then null else instanceIdRaw.Trim('{', '}'))

                let mutable info: TaskLaunchInfo = null
                let mutable handled = true

                match record.Id with
                | 107 // triggered by its schedule
                | 108 // triggered by an event
                | 119 -> // triggered by a user logon
                    let resolved = resolveTarget fields taskName instanceId record

                    if isNull resolved then handled <- false
                    else
                        info <- resolved

                        info.TriggerReason <-
                            (match record.Id with
                             | 107 -> "timer (schedule)"
                             | 108 -> "event"
                             | _ -> "user logon")
                | 129 ->
                    // 129 fires for every task action — cmd.exe, powershell.exe…
                    // Only taskhostw instances belong on this tab.
                    let rawPath = TaskParse.get fields "Path"
                    let instanceName = (if isNull rawPath then TaskParse.get fields "InstanceName" else rawPath)

                    if
                        not (isNull instanceName)
                        && instanceName.IndexOf("taskhostw", StringComparison.OrdinalIgnoreCase) < 0
                    then
                        handled <- false
                    else
                        let pid =
                            match TaskParse.parseInt (TaskParse.get fields "ProcessId") with
                            | Some v -> v
                            | None ->
                                (match TaskParse.matchInt (TaskParse.formatDescription record) MessagePidRegex with
                                 | Some v -> v
                                 | None -> 0)

                        if pid <= 0 then handled <- false
                        else
                            info <- forPid pid
                            let launched = record.TimeCreated

                            if launched.HasValue && not info.StartedAt.HasValue then
                                info.StartedAt <- Nullable(launched.Value.ToUniversalTime())
                | 100 ->
                    let resolved = resolveTarget fields taskName instanceId record

                    if isNull resolved then handled <- false
                    else
                        info <- resolved
                        let started = record.TimeCreated

                        if started.HasValue then info.StartedAt <- Nullable(started.Value.ToUniversalTime())
                | 102 ->
                    let resolved = resolveTarget fields taskName instanceId record

                    if isNull resolved then handled <- false
                    else
                        info <- resolved
                        let finished = record.TimeCreated

                        if finished.HasValue then
                            info.CompletedAt <- Nullable(finished.Value.ToUniversalTime())
                | 200 ->
                    let resolved = resolveTarget fields taskName instanceId record

                    if isNull resolved then handled <- false
                    else
                        info <- resolved

                        if isNull info.ActionName then info.ActionName <- TaskParse.get fields "ActionName"
                | 201 // action completed — "with return code 0"
                | 203 -> // action failed
                    let resolved = resolveTarget fields taskName instanceId record

                    if isNull resolved then handled <- false
                    else
                        info <- resolved

                        if isNull info.ActionName then info.ActionName <- TaskParse.get fields "ActionName"

                        let rawResult = TaskParse.get fields "ResultCode"
                        let rawCode = (if isNull rawResult then TaskParse.get fields "ErrorCode" else rawResult)

                        info.ReturnCode <-
                            (match TaskParse.parseInt rawCode with
                             | Some v -> Nullable v
                             | None ->
                                 (match TaskParse.matchInt (TaskParse.formatDescription record) MessageReturnCodeRegex with
                                  | Some v -> Nullable v
                                  | None -> info.ReturnCode))

                        if record.Id = 201 then
                            info.CompletedSuccessfully <- Nullable true
                            let finished = record.TimeCreated

                            if finished.HasValue && not info.CompletedAt.HasValue then
                                info.CompletedAt <- Nullable(finished.Value.ToUniversalTime())
                        elif not (info.CompletedSuccessfully.HasValue && info.CompletedSuccessfully.Value) then
                            info.CompletedSuccessfully <- Nullable false
                | _ -> handled <- false

                if handled then
                    if
                        not (String.IsNullOrEmpty taskName)
                        && String.IsNullOrEmpty info.TaskPath
                    then
                        info.TaskPath <- taskName

                    if String.IsNullOrEmpty info.UserContext then
                        let rawUserContext = TaskParse.get fields "UserContext"
                        let user = (if isNull rawUserContext then TaskParse.get fields "UserName" else rawUserContext)

                        if not (String.IsNullOrEmpty user) then info.UserContext <- user

                    // Knowing the task path, resolve what code a COM-handler task
                    // runs: the task XML carries the ClassId, and the registry maps
                    // ClassId → DLL. This is the "what does taskhostw actually
                    // execute" answer for DLL tasks, which have no command line.
                    if
                        not (String.IsNullOrEmpty info.TaskPath)
                        && isNull info.HandlerDll
                        && not info.HandlerDllExists.HasValue
                    then
                        TaskAttributionService.ResolveHandler info

                    TaskAttributionService.UpdateVerdict info
                    notify info
        with _ ->
            () // attribution is best-effort; one bad record never stops the watcher

    let taskSchedulerInstanceRecorded (e: EventRecordWrittenEventArgs) =
        if not (isNull (box e.EventRecord)) then handleTaskSchedulerRecord e.EventRecord

    let replayScheduler (cutoff: DateTime) : int =
        let mutable processed = 0

        try
            // Oldest-first so timestamps fill in chronological order; skip
            // what predates the window, guard against unbounded logs.
            let query = EventLogQuery(TaskSchedulerLog, PathType.LogName, SchedulerXPath)

            use reader = new EventLogReader(query)
            let mutable guard = 20000
            let mutable evt = reader.ReadEvent()

            while not (isNull evt) && guard > 0 do
                guard <- guard - 1
                use _ = evt
                let stamp = evt.TimeCreated

                if stamp.HasValue && stamp.Value.ToUniversalTime() >= cutoff then
                    handleTaskSchedulerRecord evt
                    processed <- processed + 1

                evt <- reader.ReadEvent()
        with _ ->
            ()

        processed

    /// <summary>Backfill half of EID 5: evicts pid mappings for launches that exited within the replayed window.</summary>
    let replayExits (cutoff: DateTime) =
        try
            let query = EventLogQuery(SysmonLog, PathType.LogName, "*[System[(EventID=5)]]")

            use reader = new EventLogReader(query)
            let mutable guard = 20000
            let mutable evt = reader.ReadEvent()
            let mutable stop = false

            while not stop && not (isNull evt) && guard > 0 do
                if byProcGuid.IsEmpty then
                    stop <- true // nothing tracked left to evict
                else
                    guard <- guard - 1

                    use _ = evt
                    let stamp = evt.TimeCreated

                    if stamp.HasValue && stamp.Value.ToUniversalTime() >= cutoff then
                        handleProcessStopped (TaskParse.parseFields (evt.ToXml()))

                    evt <- reader.ReadEvent()
        with _ ->
            () // exit replay is a bonus — scheduler events still bound CompletedAt

    let enableHistoryChannel () =
        try
            use config = new EventLogConfiguration(TaskSchedulerLog)

            if not config.IsEnabled then
                config.IsEnabled <- true
                config.SaveChanges()

            historyChannelEnabled <- true
        with ex ->
            historyChannelEnabled <- false
            onError.Trigger [| box $"Task Scheduler history could not be enabled: {ex.Message}" |]

    // ── surface ───────────────────────────────────────────────────────

    [<CLIEvent>]
    member _.OnError: IDelegateEvent<Action<string>> = onError.Publish

    /// <summary>Raised (on a watcher thread) whenever an instance gained an
    /// attribution fact. ProcessId > 0 is guaranteed.</summary>
    [<CLIEvent>]
    member _.OnAttributionUpdated: IDelegateEvent<Action<TaskLaunchInfo>> =
        onAttributionUpdated.Publish

    /// <summary>False when the history channel could not be enabled (attribution then degrades to GUID-only).</summary>
    member _.HistoryChannelEnabled
        with get () = historyChannelEnabled
        and private set (value) = historyChannelEnabled <- value

    member _.Start() =
        enableHistoryChannel ()

        try
            let query = EventLogQuery(SysmonLog, PathType.LogName, "*[System[(EventID=1)]]")
            sysmonProcessWatcher <- new EventLogWatcher(query)
            sysmonProcessWatcher.EventRecordWritten.Add sysmonProcessCreate
            sysmonProcessWatcher.Enabled <- true
        with
        | :? EventLogNotFoundException ->
            onError.Trigger [| box "Sysmon is not installed — taskhostw instances cannot be detected." |]
        | ex ->
            onError.Trigger [| box $"Failed to watch Sysmon process events: {ex.Message}" |]

        try
            let query = EventLogQuery(SysmonLog, PathType.LogName, "*[System[(EventID=5)]]")
            sysmonExitWatcher <- new EventLogWatcher(query)
            sysmonExitWatcher.EventRecordWritten.Add sysmonProcessStopped
            sysmonExitWatcher.Enabled <- true
        with ex ->
            onError.Trigger [| box $"Failed to watch Sysmon exit events: {ex.Message}" |]

        try
            let query = EventLogQuery(TaskSchedulerLog, PathType.LogName, SchedulerXPath)
            taskInstanceWatcher <- new EventLogWatcher(query)
            taskInstanceWatcher.EventRecordWritten.Add taskSchedulerInstanceRecorded
            taskInstanceWatcher.Enabled <- true
        with ex ->
            onError.Trigger [| box $"Failed to watch the Task Scheduler log: {ex.Message}" |]

    member _.Stop() =
        if not (isNull sysmonProcessWatcher) then
            sysmonProcessWatcher.Enabled <- false
            sysmonProcessWatcher.Dispose()
            sysmonProcessWatcher <- null

        if not (isNull sysmonExitWatcher) then
            sysmonExitWatcher.Enabled <- false
            sysmonExitWatcher.Dispose()
            sysmonExitWatcher <- null

        if not (isNull taskInstanceWatcher) then
            taskInstanceWatcher.Enabled <- false
            taskInstanceWatcher.Dispose()
            taskInstanceWatcher <- null

    /// <summary>Attribution for a taskhostw PID, or null when unknown/not a task host.</summary>
    member _.GetTaskForPid(pid: int) : TaskLaunchInfo =
        match byPid.TryGetValue(pid) with
        | true, info -> info
        | _ -> null

    /// <summary>
    /// Attribution for a taskhostw PID, checked against the asking
    /// process's own start time. Attribution is a fact about ONE tenant
    /// of a PID; once Windows recycles the number onto an unrelated
    /// process, handing that task over would blame an innocent process.
    /// Returns null when the start times don't line up (±5s) or nothing
    /// is known for the PID.
    /// </summary>
    member _.GetTaskForPid(pid: int, subjectStartedUtc: Nullable<DateTime>) : TaskLaunchInfo =
        match byPid.TryGetValue(pid) with
        | false, _ -> null
        | true, info ->
            if
                subjectStartedUtc.HasValue
                && info.StartedAt.HasValue
                && (subjectStartedUtc.Value.ToUniversalTime() - info.StartedAt.Value).Duration()
                   > TimeSpan.FromSeconds 5.0
            then
                null // attribution belongs to an earlier tenant of this PID
            else
                info

    /// <summary>
    /// Attribution for a spawn row: the Sysmon ProcessGuid first — the one
    /// key immune to PID recycling, no time heuristic needed — falling
    /// back to the time-guarded pid lookup when the guid is unavailable.
    /// </summary>
    member this.GetTaskFor(item: SpawnItem) : TaskLaunchInfo =
        if isNull (box item) then
            null
        else
            match item.ProcessGuid with
            | guid when not (String.IsNullOrEmpty guid) ->
                (match byProcGuid.TryGetValue(guid) with
                 | true, byGuidHit -> byGuidHit
                 | _ -> this.GetTaskForPid(item.Pid, Nullable(item.TimeUtc)))
            | _ -> this.GetTaskForPid(item.Pid, Nullable(item.TimeUtc))

    /// <summary>
    /// Replay the recent past so a freshly opened tab shows spawns that
    /// happened before it: Sysmon EID 1 taskhostw records become rows,
    /// and the scheduler events for the same window are stitched onto
    /// them by the same merge logic the live watchers use. Rows come
    /// back oldest-first; attribution keeps refining afterwards through
    /// the normal live paths.
    /// </summary>
    member _.Backfill(window: TimeSpan, [<Optional; DefaultParameterValue(400)>] maxRows: int) : ResizeArray<SpawnItem> =
        let cutoff = DateTime.UtcNow - window
        let spawns = ResizeArray<SpawnItem>()

        try
            // Newest-first: stop at the window edge. EID 1 fires for every
            // process on the machine, so the substring pre-filter inside
            // ParseSpawnRecord keeps the DOM parses to the taskhostw few.
            let query = EventLogQuery(SysmonLog, PathType.LogName, "*[System[(EventID=1)]]")
            query.ReverseDirection <- true

            use reader = new EventLogReader(query)
            let mutable evt = reader.ReadEvent()
            let mutable stop = false

            while not stop && not (isNull evt) && spawns.Count < maxRows do
                use _ = evt
                let stamp = evt.TimeCreated

                if stamp.HasValue && stamp.Value.ToUniversalTime() < cutoff then
                    stop <- true
                else
                    let item =
                        ImageSpawnWatcherService.ParseSpawnRecord(
                            evt,
                            Func<string, bool>(ImageSpawnWatcherService.IsTaskhostwImage),
                            "taskhostw"
                        )

                    if not (isNull (box item)) then spawns.Add item

                // C# breaks out of the read loop as soon as either edge is hit;
                // only pull the next record while the loop continues.
                if not stop && spawns.Count < maxRows then
                    evt <- reader.ReadEvent()
                else
                    evt <- null
        with _ ->
            () // history is a bonus; a missing log just yields nothing

        replayScheduler cutoff |> ignore

        spawns.Sort(fun a b -> a.TimeUtc.CompareTo(b.TimeUtc))

        for item in spawns do
            feedSysmonItem item

        // Exits inside the window evict their pid mappings too — a
        // backfilled launch that already exited must not stay
        // attributable through its (possibly since-recycled) pid.
        replayExits cutoff
        spawns

    /// <summary>
    /// Scheduler-only replay: fills the attribution map without Sysmon
    /// (whose log denies reads to non-elevated callers). EID 129 carries
    /// the taskhostw PID, so launches still attribute — only the grid
    // rows are missing. Returns the number of records processed.
    /// </summary>
    member _.BackfillSchedulerOnly(window: TimeSpan) : int =
        replayScheduler(DateTime.UtcNow - window)

    /// <summary>Fully or partially attributed launches seen (live or backfilled), newest first — diagnostic enumeration.</summary>
    member _.GetRecentLaunches([<Optional; DefaultParameterValue(50)>] max: int) : ResizeArray<TaskLaunchInfo> =
        byPid.Values
            .Where(fun (i: TaskLaunchInfo) -> not (String.IsNullOrEmpty i.TaskPath))
            .OrderByDescending(fun (i: TaskLaunchInfo) ->
                if i.StartedAt.HasValue then i.StartedAt.Value else i.FirstSeenUtc)
            .Take(max)
            .ToList()

    // ── handler resolution + verdict (private statics, argument-only) ──

    /// <summary>
    /// Fills HandlerClassId/HandlerDll for a task whose path is known.
    /// Scheduled-task files live under %WINDIR%\System32\Tasks\<path>; a
    /// ComHandler action's XML contains the ClassId, which resolves to the
    /// DLL through HKCR\CLSID\{...}\InprocServer32. Exec/spawn tasks have
    /// no ClassId and are left null — their command line already says
    /// what they run.
    /// </summary>
    static member private ResolveHandler(info: TaskLaunchInfo) =
        try
            let tasksRoot =
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks")

            let taskFile = tasksRoot + info.TaskPath

            if not (File.Exists taskFile) then
                ()
            else
                let xml = File.ReadAllText taskFile
                let openIdx = xml.IndexOf("<ClassId>", StringComparison.OrdinalIgnoreCase)
                let closeIdx = xml.IndexOf("</ClassId>", StringComparison.OrdinalIgnoreCase)

                if openIdx < 0 || closeIdx <= openIdx then
                    ()
                else
                    let classId = xml.Substring(openIdx + 9, closeIdx - openIdx - 9).Trim()

                    if not (classId.StartsWith("{", StringComparison.Ordinal)) then
                        ()
                    else
                        info.HandlerClassId <- classId

                        // HKCR merges HKLM\Software\Classes and HKCU\Software\Classes;
                        // check the 64-bit view first, then WOW6432Node for 32-bit DLLs
                        let hives =
                            [ @"Software\Classes\CLSID\" + classId + @"\InprocServer32"
                              @"Software\Classes\WOW6432Node\CLSID\" + classId + @"\InprocServer32" ]

                        let mutable found = false

                        for hive in hives do
                            if not found then
                                use key = Registry.LocalMachine.OpenSubKey(hive)

                                let dll =
                                    if isNull (box key) then
                                        null
                                    else
                                        (match key.GetValue(null) with
                                         | null -> null
                                         | v -> v.ToString())

                                if not (String.IsNullOrEmpty dll) then
                                    found <- true
                                    info.HandlerDll <- Environment.ExpandEnvironmentVariables(dll)
                                    info.HandlerDllExists <- Nullable(File.Exists info.HandlerDll)

                                    if info.HandlerDllExists.HasValue && info.HandlerDllExists.Value then
                                        try
                                            // .NET 10 renamed the factory: GetFileVersionInfo → GetVersionInfo
                                            let fv = FileVersionInfo.GetVersionInfo(info.HandlerDll)
                                            info.HandlerDllCompany <- fv.CompanyName
                                            info.HandlerDllVersion <- fv.FileVersion
                                        with _ -> ()

                        // Registered nowhere: the task fires but its DLL is gone —
                        // classic leftover of uninstalled software
                        if not found then info.HandlerDllExists <- Nullable false
        with _ ->
            () // attribution extras are best-effort

    /// <summary>
    /// Inbox: Microsoft-shipped task path running code from the system
    /// directories. Third-party: task outside \Microsoft\, or an inbox
    /// task whose handler DLL lives elsewhere. Orphaned: the handler DLL
    /// is gone — leftover of uninstalled software. Null while the task is
    /// still unresolved.
    /// </summary>
    static member private UpdateVerdict(info: TaskLaunchInfo) =
        if String.IsNullOrEmpty info.TaskPath then
            info.Verdict <- null
        else
            let inboxPath = info.TaskPath.StartsWith("\\Microsoft\\", StringComparison.OrdinalIgnoreCase)

            // A classic-COM miss (handler DLL not registered) is the "leftover
            // of uninstalled software" signature for third-party tasks. Inbox
            // tasks also resolve handlers through stores the classic lookup
            // doesn't cover (packaged COM et al.) — they run fine unregistered
            // in HKCR — so they stay Inbox with an unresolved handler.
            if info.HandlerDllExists.HasValue && not info.HandlerDllExists.Value then
                info.Verdict <- (if inboxPath then "Inbox" else "Orphaned")
            else
                let mutable systemCode = true

                if not (String.IsNullOrEmpty info.HandlerDll) then
                    systemCode <-
                        info.HandlerDll.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase)
                        || info.HandlerDll.StartsWith(
                            Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
                            StringComparison.OrdinalIgnoreCase
                        )

                info.Verdict <- (if inboxPath && systemCode then "Inbox" else "Third-party")

/// <summary>One Assets/known-tasks.json entry: the plain-English half of an investigation.
/// F# port: [<AllowNullLiteral>] so "unknown task" reads as null, the C# semantics.</summary>
[<AllowNullLiteral>]
type KnownTaskEntry() =
    member val Title: string = null with get, set
    member val Explanation: string = null with get, set
    member val Note: string = null with get, set

/// <summary>
/// Plain-English explanations for well-known scheduled tasks, shipped as
/// Assets/known-tasks.json so the corpus grows without a rebuild: add a
/// path-keyed entry, restart, and every future spawn of that task carries
/// its explanation in the Taskhostw Spawns tab. The catalog is lookup-only
/// enrichment — unknown tasks are not errors, they simply fall back to the
/// task XML's own Description/Author in the summary pane.
/// F# port: C# read the json from AppContext.BaseDirectory; the directory
/// now routes through the optional baseDir parameter (null →
/// AppContext.BaseDirectory) — the engine no longer bakes in an install
/// path, and the host app can point the catalog at its own root.
/// </summary>
[<AbstractClass; Sealed>]
type KnownTaskCatalog private () =

    static let mutable entries: Dictionary<string, KnownTaskEntry> = null
    static let mutable loaded = false

    static let normalize (path: string) =
        path.Trim().TrimEnd('\\').ToLowerInvariant()

    static let loadIfNeeded (baseDir: string) =
        if loaded then
            ()
        else
            loaded <- true
            entries <- Dictionary<string, KnownTaskEntry>(StringComparer.Ordinal)

            try
                let dir =
                    if String.IsNullOrEmpty baseDir then
                        AppContext.BaseDirectory
                    else
                        baseDir

                let file = Path.Combine(dir, "Assets", "known-tasks.json")

                if File.Exists file then
                    let parsed =
                        JsonSerializer.Deserialize<Dictionary<string, KnownTaskEntry>>(File.ReadAllText file)

                    if not (isNull (box parsed)) then
                        for kv in parsed do
                            if
                                not (isNull (box kv.Value))
                                && not (String.IsNullOrEmpty kv.Value.Title)
                            then
                                entries.[normalize kv.Key] <- kv.Value
            with _ ->
                () // the catalog is best-effort enrichment, never fatal

    /// <summary>Lookup by task path (e.g. "\Microsoft\Windows\Foo\Bar"), or null when unknown.</summary>
    static member Lookup(taskPath: string, [<Optional; DefaultParameterValue(null: string)>] baseDir: string) : KnownTaskEntry =
        if String.IsNullOrEmpty taskPath then
            null
        else
            loadIfNeeded baseDir

            match entries.TryGetValue(normalize taskPath) with
            | true, entry -> entry
            | _ -> null
