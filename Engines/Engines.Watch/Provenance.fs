// F# port of Core\Services\ProcessProvenanceService.cs (namespace
// AutoScope.Services) for the Engines.Watch library. Behavioral
// faithfulness is the contract: same PID-reuse guards, same preference
// rules for recorded create-events, same warning/evidence strings, same
// verdict table — the app's report renderer (BuildReportText lives in the
// app, not here) and the AI tools read these types field-for-field.
//
// F# port notes (deviations forced by F#, none behavioral):
//   • ChainLink/EvidenceItem/ProvenanceReport C# public FIELDS became
//     properties (member val … with get, set) — same names, same
//     DateTime? (Nullable<DateTime>) shapes, and the C# object-initializer
//     / mutation call shapes keep compiling.
//   • ProcSnap (the C# private nested ProcSnap class) is a file-private
//     record before the service; its DateTime? became a private option —
//     invisible outside this file, so the public surface carries no F#
//     optionals.
//   • Optional parameters use [<Optional; DefaultParameterValue>], not
//     F# `?` optionals — F# optionals surface as FSharpOption<T> in
//     metadata and would be uncallable with the C# source's
//     default-omission shapes (ProcessTraceWindow passes all six
//     arguments positionally, AgentToolRegistry passes only the pid).
//   • The C# dead local `exeName` in ScanShellHistory (computed, never
//     read) was dropped rather than ported as a warning.
//   • Private helpers are static let functions (file-private), not
//     surface; F# needs them defined before use, so they appear in
//     dependency order above Collect.

// FS3211 fires on every [<Optional; DefaultParameterValue(null)>] below
// ("default value does not have the same type ... will be ignored"), but
// the emitted metadata is exactly what C# needs — every such parameter
// reflects as IsOptional=true with default null (i.e. default(T), the
// same semantics as the C# source's `= null`) — the same pattern the
// Diagnosis engine's Probe.fs validated.
#nowarn "3211"

namespace AutoScope.Engines.Watch

open System
open System.Collections.Generic
open System.Diagnostics
open System.Diagnostics.Eventing.Reader
open System.Globalization
open System.IO
open System.Runtime.InteropServices
open System.Xml.Linq
open System.Management

/// <summary>One hop in the ancestry chain, ordered child → root.</summary>
type ChainLink() =
    member val Pid: int = 0 with get, set
    member val Name: string = null with get, set
    member val ExePath: string = null with get, set
    member val CommandLine: string = null with get, set
    member val Owner: string = null with get, set
    member val Created: Nullable<DateTime> = Nullable<DateTime>() with get, set

    /// <summary>
    /// False when this PID could not have been the real parent — Windows
    /// recycled it (the current owner started AFTER the child), or the
    /// process is already gone and only hints/events identify it.
    /// </summary>
    member val Verified: bool = true with get, set

    /// <summary>Why the link is unverified / how it was observed.</summary>
    member val Note: string = null with get, set

/// <summary>
/// One corroborating record in the report. F# port: C# public fields are
/// properties with the same names.
/// </summary>
type EvidenceItem() =
    member val Source: string = null with get, set
    member val Detail: string = null with get, set

/// <summary>
/// Everything the PID inquiry could establish about one process: live
/// identity, parent chain, spawn mechanism and corroborating records.
/// F# port: C# public fields are properties with the same names.
/// </summary>
type ProvenanceReport() =
    member val Pid: int = 0 with get, set
    member val Alive: bool = false with get, set
    member val Name: string = null with get, set
    member val ExePath: string = null with get, set
    member val CommandLine: string = null with get, set
    member val Owner: string = null with get, set
    member val Session: string = null with get, set
    member val Memory: string = null with get, set
    member val Created: Nullable<DateTime> = Nullable<DateTime>() with get, set

    /// <summary>
    /// True when the live PID is NOT the process the caller asked about:
    /// the hinted identity disagrees with the live snapshot, so Windows
    /// recycled the PID and the subject has exited. Identity, chain and
    /// verdict then describe the exited subject; the unrelated current
    /// owner of the number is reported separately (CurrentOwner*).
    /// </summary>
    member val Recycled: bool = false with get, set

    /// <summary>Name of the unrelated process that now owns the recycled PID.</summary>
    member val CurrentOwnerName: string = null with get, set

    /// <summary>Start time of the unrelated process that now owns the recycled PID.</summary>
    member val CurrentOwnerCreated: Nullable<DateTime> = Nullable<DateTime>() with get, set

    /// <summary>One-line identity of the current PID owner, for report text.</summary>
    member val CurrentOwnerSummary: string = null with get, set

    member val Verdict: string = null with get, set
    member val VerdictDetail: string = null with get, set

    member val Chain: ResizeArray<ChainLink> = ResizeArray<ChainLink>() with get, set
    member val Evidence: ResizeArray<EvidenceItem> = ResizeArray<EvidenceItem>() with get, set
    member val Warnings: ResizeArray<string> = ResizeArray<string>() with get, set
    member val Elapsed: TimeSpan = TimeSpan() with get, set

// F# port: the C# private nested ProcSnap class — file-private record;
// Created is an option only internally, never exposed.
type private ProcSnap =
    { Pid: int
      ParentPid: int
      SessionId: int
      Name: string
      ExePath: string
      CommandLine: string
      Owner: string
      Created: DateTime option
      WorkingSet: int64 }

/// <summary>
/// Answers "how was this PID spawned?" for any process — the machine
/// forensics playbook behind the Process Monitor's PID inquiry:
///
///   1. Live WMI snapshot (identity, owner, command line, creation time)
///   2. Parent-chain walk with a PID-reuse guard: a parent only counts
///      when its creation time predates the child's. Windows recycles
///      PIDs aggressively; a naive PPID lookup blames an innocent process.
///      The same guard covers the TARGET itself: when the caller's hints
///      (capture-time name/image, the subject's start time, the last
///      sighting) disagree with the live snapshot, the PID was recycled —
///      the report describes the EXITED subject and never merges it with
///      the unrelated process that inherited the number.
///   3. Corroboration from recorded create-events: Sysmon EID 1 (ground
///      truth that survives process exit), Security 4688 as fallback
///   4. Interactive-shell evidence: PSReadLine history matches for the
///      typed command line
///   5. Autostart surface: Run keys / Startup folder / services hosted
///
/// All I/O is synchronous and intended to run on a background thread —
/// the whole collection takes a moment (several WMI roundtrips + event
/// log queries) and must never block the UI.
/// </summary>
[<AbstractClass; Sealed>]
type ProcessProvenanceService private () =

    static let SysmonLog = "Microsoft-Windows-Sysmon/Operational"

    static let InteractiveShells =
        [| "powershell.exe"
           "pwsh.exe"
           "cmd.exe"
           "bash.exe"
           "wt.exe"
           "windowsterminal.exe"
           "conhost.exe"
           "openconsole.exe" |]

    // Chain walk stops once one of these is on it — everything above
    // them is session/OS infrastructure that adds no spawn information.
    static let RootNames =
        HashSet<string>(
            [ "explorer.exe"
              "services.exe"
              "wininit.exe"
              "smss.exe"
              "winlogon.exe"
              "lsass.exe"
              "csrss.exe" ],
            StringComparer.OrdinalIgnoreCase
        )

    // ── small shared helpers ──────────────────────────────────────────

    // C# `$"{dateTimeNullable:format}"` prints "" for null — same here.
    static let fmtN (value: Nullable<DateTime>) (format: string) =
        if value.HasValue then value.Value.ToString(format) else ""

    static let optToNullable (value: DateTime option) =
        match value with
        | Some v -> Nullable v
        | None -> Nullable<DateTime>()

    static let getOrDefault (fields: Dictionary<string, string>) (name: string) : string =
        match fields.TryGetValue(name) with
        | true, v -> v
        | _ -> null

    static let toStr (v: obj) =
        match v with
        | null -> null
        | x -> x.ToString()

    static let parseDmtf (dmtf: string) : DateTime option =
        try
            Some(ManagementDateTimeConverter.ToDateTime(dmtf))
        with _ ->
            None

    // ── PID-tenant identity helpers ───────────────────────────────────

    /// <summary>
    /// Case-insensitive process-name compare with .exe normalization —
    /// "taskhostw", "taskhostw.exe" and "TASKHOSTW.EXE" are the same
    /// process. Null/empty sides constrain nothing (no hint, no veto).
    /// </summary>
    static let namesMatch (hinted: string) (live: string) =
        if String.IsNullOrEmpty hinted || String.IsNullOrEmpty live then
            true
        else
            let normalize (s: string) =
                let s = s.Trim().ToLowerInvariant()

                if s.EndsWith(".exe", StringComparison.Ordinal) then s else s + ".exe"

            normalize hinted = normalize live

    /// <summary>
    /// Image-path compare tolerant of spelling differences between
    /// sources (Sysmon paths vs WMI paths): exact path first, file name
    /// as fallback. Null/empty sides constrain nothing.
    /// </summary>
    static let imagesMatch (hinted: string) (live: string) =
        if String.IsNullOrEmpty hinted || String.IsNullOrEmpty live then
            true
        elif String.Equals(hinted.Trim(), live.Trim(), StringComparison.OrdinalIgnoreCase) then
            true
        else
            String.Equals(
                Path.GetFileName(hinted.Trim()),
                Path.GetFileName(live.Trim()),
                StringComparison.OrdinalIgnoreCase
            )

    // ── event plumbing ─────────────────────────────────────────────────

    /// <summary>Sysmon's UtcTime field ("2026-10-10 18:56:42.123") as a UTC DateTime.</summary>
    static let tryParseSysmonUtc (fields: Dictionary<string, string>) : DateTime option =
        match fields.TryGetValue("UtcTime") with
        | false, _ -> None
        | true, raw ->
            let mutable utc = DateTime()

            if
                DateTime.TryParse(
                    raw,
                    null,
                    DateTimeStyles.AssumeUniversal ||| DateTimeStyles.AdjustToUniversal,
                    &utc
                )
            then
                Some utc
            else
                None

    /// <summary>EventData of an event record as a Name → Value dictionary.</summary>
    static let parseEventData (evt: EventRecord) : Dictionary<string, string> =
        let fields = Dictionary<string, string>()
        let doc = XDocument.Parse(evt.ToXml())
        let ns = XNamespace.Get("http://schemas.microsoft.com/win/2004/08/events/event")

        let eventData =
            if isNull (box doc.Root) then null else doc.Root.Element(ns + "EventData")

        if not (isNull (box eventData)) then
            for data in eventData.Elements(ns + "Data") do
                match data.Attribute(XName.Get("Name")) with
                | null -> ()
                | nameAttr -> fields.[nameAttr.Value] <- data.Value

        fields

    // ── WMI plumbing ───────────────────────────────────────────────────

    static let queryProcess (pid: int) : ProcSnap option =
        try
            // SELECT * (not a column projection): GetOwner invocation on
            // projected objects fails in this System.Management build.
            use searcher =
                new ManagementObjectSearcher(sprintf "SELECT * FROM Win32_Process WHERE ProcessId = %d" pid)

            let mutable found: ProcSnap option = None

            for o in searcher.Get() do
                if found.IsNone then
                    let mo = o :?> ManagementObject

                    let owner =
                        try
                            // 3-arg overload: the 2-arg (string, object[]) path is
                            // broken in this System.Management build and throws
                            // InvalidOperationException on every invoke.
                            let ownerInfo =
                                mo.InvokeMethod(
                                    "GetOwner",
                                    (null: ManagementBaseObject),
                                    (null: InvokeMethodOptions)
                                )

                            if
                                not (isNull (box ownerInfo))
                                && not (isNull (box ownerInfo.["User"]))
                            then
                                let domain = ownerInfo.["Domain"]
                                let user = ownerInfo.["User"]
                                sprintf "%O\\%O" domain user
                            else
                                null
                        with _ ->
                            null // protected system processes have no readable owner

                    found <-
                        Some
                            { Pid = pid
                              ParentPid =
                                (match o.["ParentProcessId"] with
                                 | null -> 0
                                 | v -> Convert.ToInt32 v)
                              SessionId =
                                (match o.["SessionId"] with
                                 | null -> 0
                                 | v -> Convert.ToInt32 v)
                              Name = toStr (o.["Name"])
                              ExePath = toStr (o.["ExecutablePath"])
                              CommandLine = toStr (o.["CommandLine"])
                              Owner = owner
                              Created =
                                (match toStr (o.["CreationDate"]) with
                                 | null -> None
                                 | dmtf -> parseDmtf dmtf)
                              WorkingSet =
                                (match o.["WorkingSetSize"] with
                                 | null -> 0L
                                 | v -> Convert.ToInt64 v) }

            found
        with _ ->
            None // access denied / RPC failure — caller treats as "not running"

    static let rootNamesContains (name: string) =
        RootNames.Contains(
            (match name with
             | null -> String.Empty
             | n -> n)
        )

    // ── chain walk ────────────────────────────────────────────────────

    static let buildChain (r: ProvenanceReport) (target: ProcSnap option) =
        match target with
        | None ->
            r.Chain.Add(
                ChainLink(
                    Pid = r.Pid,
                    Name = r.Name,
                    ExePath = r.ExePath,
                    CommandLine = r.CommandLine,
                    Created = r.Created,
                    Verified = false,
                    Note =
                        (if r.Recycled then
                             "subject exited before this inquiry — the PID now belongs to a different, unrelated process (see evidence)"
                         else
                             "not running at inquiry time")
                )
            )
        | Some first ->
            let mutable current = first
            let seen = HashSet<int>([ first.Pid ])

            let mutable hop = 0
            let mutable keepWalking = true

            while keepWalking && hop < 12 do
                hop <- hop + 1

                r.Chain.Add(
                    ChainLink(
                        Pid = current.Pid,
                        Name = current.Name,
                        ExePath = current.ExePath,
                        CommandLine = current.CommandLine,
                        Owner = current.Owner,
                        Created = optToNullable current.Created
                    )
                )

                if rootNamesContains current.Name then keepWalking <- false

                let ppid = current.ParentPid

                if ppid <= 0 || seen.Contains ppid then keepWalking <- false
                else
                    match queryProcess ppid with
                    | None ->
                        r.Chain.Add(
                            ChainLink(
                                Pid = ppid,
                                Name = "<exited>",
                                Verified = false,
                                Note =
                                    "parent exited before this inquiry — lineage beyond this point is "
                                    + "unrecoverable from live data (the PID may meanwhile have been recycled)"
                            )
                        )

                        keepWalking <- false
                    | Some parent when
                        current.Created.IsSome
                        && parent.Created.IsSome
                        && parent.Created.Value > current.Created.Value
                        ->
                        // PID-reuse guard: the PID now names a process that started
                        // AFTER the child — it cannot be the real parent.
                        r.Chain.Add(
                            ChainLink(
                                Pid = ppid,
                                Name = parent.Name,
                                ExePath = parent.ExePath,
                                CommandLine = parent.CommandLine,
                                Owner = parent.Owner,
                                Created = optToNullable parent.Created,
                                Verified = false,
                                Note =
                                    sprintf
                                        "PID reuse: PID %d now belongs to a process started at %s, AFTER this child — not the real parent"
                                        ppid
                                        (parent.Created.Value.ToString("HH:mm:ss"))
                            )
                        )

                        r.Warnings.Add(
                            (sprintf "Parent PID %d was recycled (its current owner is newer than " ppid)
                            + "the child). True parent unknown from live data — check the recorded create-events."
                        )

                        keepWalking <- false
                    | Some parent ->
                        seen.Add ppid |> ignore
                        current <- parent

    // ── recorded create-events (survive process exit) ──────────────────

    /// <summary>Sysmon Event ID 1 — the authoritative record of the spawn.</summary>
    static let corroborateSysmon (r: ProvenanceReport) (hintSeenUtc: Nullable<DateTime>) =
        try
            let query =
                EventLogQuery(
                    SysmonLog,
                    PathType.LogName,
                    sprintf
                        "*[System[(EventID=1)]] and *[EventData[Data[@Name='ProcessId']='%d']]"
                        r.Pid
                )

            query.ReverseDirection <- true // newest first

            use reader = new EventLogReader(query)

            // Up to 5 newest create-events: a recycled PID can have
            // several tenants in the log. Which record speaks for the
            // SUBJECT is decided by preference, not recency alone:
            //   1. the record matching the subject's known creation time
            //      (the alive / same-tenant case)
            //   2. a record for the hinted image at/before the last
            //      sighting — a dead subject, never a later tenant
            //   3. any record at/before the last sighting
            //   4. the newest record (legacy behavior when no hints exist)
            let records = ResizeArray<Dictionary<string, string> * DateTime option>()
            let mutable stop = false
            let mutable i = 0

            while not stop && i < 5 do
                i <- i + 1

                match reader.ReadEvent() with
                | null -> stop <- true
                | ev ->
                    use _ = ev
                    let fields = parseEventData ev
                    let utc = tryParseSysmonUtc fields
                    records.Add((fields, utc))

                    match utc, r.Created with
                    | Some u, created when
                        created.HasValue
                        && (u.ToLocalTime() - created.Value).Duration() <= TimeSpan.FromSeconds 5.0
                        ->
                        records.Clear() // authoritative match —
                        records.Add((fields, Some u)) // nothing else competes
                        stop <- true
                    | _ -> ()

            // The live channel is a rolling window — an old spawn can
            // have wrapped out of it. The app's Sysmon archive holds
            // every event it ever backfilled or watched, so fall back to
            // it before declaring ancestry unrecoverable. Same record
            // shape, same preference rules below.
            let fromArchive =
                if records.Count = 0 then
                    for a in SysmonArchiveService.SearchCreateEvents(r.Pid, 5) do
                        records.Add(a.Data, Some a.TsUtc)

                    records.Count > 0
                else
                    false

            let mutable bestFields: Dictionary<string, string> = null
            let mutable bestUtc: DateTime option = None
            let mutable bestScore = -1
            let windowUtc = if hintSeenUtc.HasValue then Some(hintSeenUtc.Value.ToUniversalTime()) else None

            for (fields, utc) in records do
                let inWindow =
                    match utc, windowUtc with
                    | Some u, Some w when u <= w + TimeSpan.FromSeconds 5.0 -> true
                    | _ -> false

                let imageMatch =
                    not (isNull r.ExePath)
                    && (match fields.TryGetValue("Image") with
                        | true, img -> imagesMatch r.ExePath img
                        | _ -> false)

                let score =
                    if inWindow && imageMatch then 3
                    elif inWindow then 2
                    elif imageMatch && windowUtc.IsNone then 1
                    else 0

                if score > bestScore then
                    bestScore <- score
                    bestFields <- fields
                    bestUtc <- utc

            if not (isNull (box bestFields)) then
                if bestUtc.IsNone then bestUtc <- tryParseSysmonUtc bestFields

                // Dead process with no hints: the event IS the identity
                if not r.Alive then
                    match bestFields.TryGetValue("Image") with
                    | true, img ->
                        r.Name <- Path.GetFileName img

                        if isNull r.ExePath then r.ExePath <- img
                    | _ -> ()

                    if isNull r.CommandLine then
                        r.CommandLine <-
                            (match bestFields.TryGetValue("CommandLine") with
                             | true, cl -> cl
                             | _ -> null)

                    if isNull r.Owner then
                        r.Owner <-
                            (match bestFields.TryGetValue("User") with
                             | true, usr -> usr
                             | _ -> null)

                    match bestUtc, r.Created with
                    | Some u, created when not created.HasValue -> r.Created <- Nullable(u.ToLocalTime())
                    | _ -> ()

                let whenText =
                    match bestUtc with
                    | Some u -> u.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
                    | None -> "time unknown"

                let mutable detail =
                    (sprintf "created %s · image %s" whenText (getOrDefault bestFields "Image"))
                    + (sprintf
                        " · parent %s (PID %s)"
                        (getOrDefault bestFields "ParentImage")
                        (getOrDefault bestFields "ParentProcessId"))
                    + (sprintf " · user %s" (getOrDefault bestFields "User"))

                match bestFields.TryGetValue("CommandLine") with
                | true, cl2 when not (String.IsNullOrEmpty cl2) ->
                    detail <- detail + (sprintf "\r\n      command line: %s" cl2)
                | _ -> ()

                match bestFields.TryGetValue("ParentCommandLine") with
                | true, pcl when not (String.IsNullOrEmpty pcl) ->
                    detail <- detail + (sprintf "\r\n      parent command line: %s" pcl)
                | _ -> ()

                r.Evidence.Add(
                    EvidenceItem(
                        Source =
                            (if fromArchive then
                                 "Sysmon archive create-event (EID 1) — wrapped out of the live log"
                             else
                                 "Sysmon create-event (EID 1)"),
                        Detail = detail
                    )
                )
        with
        | :? EventLogNotFoundException ->
            r.Warnings.Add(
                "Sysmon is not installed — no recorded create-events. Live data only; "
                + "exited processes become untraceable."
            )
        | ex ->
            r.Warnings.Add("Sysmon create-event lookup failed: " + ex.Message)

    /// <summary>Security 4688 fallback when Sysmon is absent (needs audit policy + admin).</summary>
    static let corroborateAudit4688 (r: ProvenanceReport) =
        let hasSysmonEvidence =
            r.Evidence
            |> Seq.exists (fun (e: EvidenceItem) ->
                match e.Source with
                | null -> false
                | s -> s.StartsWith("Sysmon", StringComparison.Ordinal))

        if hasSysmonEvidence then
            ()
        else
            try
                let hex = sprintf "0x%X" r.Pid

                let query =
                    EventLogQuery(
                        "Security",
                        PathType.LogName,
                        sprintf
                            "*[System[(EventID=4688)]] and *[EventData[Data[@Name='NewProcessId']='%s']]"
                            hex
                    )

                query.ReverseDirection <- true

                use reader = new EventLogReader(query)

                match reader.ReadEvent() with
                | null -> ()
                | ev ->
                    use _ = ev
                    let fields = parseEventData ev

                    if not r.Alive then
                        r.Name <-
                            (match fields.TryGetValue("NewProcessName") with
                             | true, np -> Path.GetFileName np
                             | _ -> r.Name)

                        r.ExePath <-
                            (if isNull r.ExePath then
                                 (match fields.TryGetValue("NewProcessName") with
                                  | true, np -> np
                                  | _ -> null)
                             else
                                 r.ExePath)

                    r.Evidence.Add(
                        EvidenceItem(
                            Source = "Security audit 4688",
                            Detail =
                                (sprintf
                                    "created %s · image %s · creator process ID %s"
                                    (fmtN ev.TimeCreated "yyyy-MM-dd HH:mm:ss")
                                    (getOrDefault fields "NewProcessName")
                                    (getOrDefault fields "ProcessId"))
                        )
                    )
            with _ ->
                // Security log is admin-only and 4688 auditing is off by
                // default — absence of this evidence is the normal case.
                ()

    // ── interactive-shell evidence ─────────────────────────────────────

    /// <summary>First script-looking token of a command line ("x.py", "y.ps1", …).</summary>
    static let extractScriptToken (commandLine: string) =
        if String.IsNullOrEmpty commandLine then
            null
        else
            let isScriptExt (ext: string) =
                match ext with
                | ".py"
                | ".ps1"
                | ".bat"
                | ".cmd"
                | ".js"
                | ".vbs"
                | ".pl"
                | ".rb"
                | ".sh" -> true
                | _ -> false

            let mutable result = null
            let mutable keep = true

            for token in commandLine.Split(' ', '\t') do
                if keep then
                    let t = token.Trim('"')
                    let ext = Path.GetExtension t

                    if isScriptExt ext then
                        result <- Path.GetFileName t
                        keep <- false

            result

    /// <summary>
    /// PSReadLine persists every command typed in an interactive
    /// PowerShell session (no timestamps). A history line containing the
    /// process's script/executable is strong "typed by a human" evidence —
    /// it is what settles interactive launches.
    /// </summary>
    static let scanShellHistory (r: ProvenanceReport) =
        try
            let file =
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Microsoft",
                    "Windows",
                    "PowerShell",
                    "PSReadLine",
                    "ConsoleHost_history.txt"
                )

            if File.Exists file then
                let script = extractScriptToken r.CommandLine
                let hits = ResizeArray<string>()
                let lines = File.ReadAllLines file
                let mutable i = 0
                let mutable keep = true

                while keep && i < lines.Length do
                    let line = lines.[i].Trim()
                    i <- i + 1

                    if line.Length = 0 || line.StartsWith("#", StringComparison.Ordinal) then
                        ()
                    else
                        let strong =
                            (not (String.IsNullOrEmpty r.ExePath)
                             && line.Contains(r.ExePath, StringComparison.OrdinalIgnoreCase))
                            || (not (String.IsNullOrEmpty script)
                                && line.IndexOf(script, StringComparison.OrdinalIgnoreCase) >= 0)

                        if strong then hits.Add line

                        if hits.Count >= 3 then keep <- false

                for hit in hits do
                    r.Evidence.Add(
                        EvidenceItem(
                            Source = "PowerShell history (PSReadLine)",
                            Detail = sprintf "typed in an interactive session:\r\n      %s" hit
                        )
                    )
        with _ ->
            () // history unreadable/absent — evidence simply not available

    // ── autostart surface ──────────────────────────────────────────────

    /// <summary>Run keys + Startup folder via Win32_StartupCommand, matched against the image.</summary>
    static let scanStartupEntries (r: ProvenanceReport) =
        if String.IsNullOrEmpty r.ExePath then
            ()
        else
            try
                let exeName = Path.GetFileName r.ExePath

                use searcher =
                    new ManagementObjectSearcher("SELECT Name, Command, Location FROM Win32_StartupCommand")

                for o in searcher.Get() do
                    let cmd =
                        (match o.["Command"] with
                         | null -> String.Empty
                         | v -> v.ToString())

                    if
                        cmd.IndexOf(exeName, StringComparison.OrdinalIgnoreCase) >= 0
                        || cmd.IndexOf(r.ExePath, StringComparison.OrdinalIgnoreCase) >= 0
                    then
                        r.Evidence.Add(
                            EvidenceItem(
                                Source = "Autostart (logon)",
                                Detail =
                                    sprintf
                                        "%s: '%s' → %s"
                                        (toStr (o.["Location"]))
                                        (toStr (o.["Name"]))
                                        cmd
                            )
                        )
            with _ ->
                () // best-effort evidence only

    /// <summary>
    /// Services hosted by the target itself (svchost rows; also flags any
    /// process hosting one). Returns the service names for the identity
    /// cross-check.
    /// </summary>
    static let enumerateHostedServices (r: ProvenanceReport) (target: ProcSnap option) : ResizeArray<string> =
        match target with
        | None -> ResizeArray<string>()
        | Some _ ->
            try
                use searcher =
                    new ManagementObjectSearcher(
                        sprintf "SELECT Name, DisplayName, State FROM Win32_Service WHERE ProcessId = %d" r.Pid
                    )

                let names = ResizeArray<string>()
                let lines = ResizeArray<string>()

                for o in searcher.Get() do
                    let name = toStr (o.["Name"])

                    if not (String.IsNullOrEmpty name) then
                        names.Add name
                        lines.Add(sprintf "%s — %s (%s)" name (toStr (o.["DisplayName"])) (toStr (o.["State"])))

                if names.Count > 0 then
                    r.Evidence.Add(
                        EvidenceItem(Source = "Services hosted", Detail = String.Join("\r\n      ", lines))
                    )

                names
            with _ ->
                // best-effort evidence only
                ResizeArray<string>()

    /// <summary>
    /// Decodes a svchost subject's command line ("-k netsvcs -p -s
    /// WpnService") into its identity: the -k service group (a pool dozens
    /// of instances share) and the -s single tenant, corroborated against
    /// the SCM-resident services — the ground truth a genuine instance
    /// always matches. A hidden command line (standard users cannot read
    /// SYSTEM svchost lines) is disclosed, never guessed.
    /// </summary>
    static let analyzeSvchostIdentity (r: ProvenanceReport) (target: ProcSnap option) (hostedServices: ResizeArray<string>) =
        let isSvchost =
            String.Equals(r.Name, "svchost.exe", StringComparison.OrdinalIgnoreCase)
            || (match r.ExePath with
                | null -> false
                | p -> p.EndsWith("\\svchost.exe", StringComparison.OrdinalIgnoreCase))

        if not isSvchost then
            ()
        else
            // F# port: C# SvchostAnalyzer.Core.SvchostIdentity — the parallel
            // Engines.Watch port (SvchostIdentity.fs) is assumed to expose the
            // same Parse/Group/DeclaredService/Mismatches surface here.
            let id = SvchostIdentity.Parse r.CommandLine

            if String.IsNullOrEmpty r.CommandLine then
                r.Warnings.Add(
                    "svchost command line hidden — standard users cannot read SYSTEM svchost command lines. "
                    + "Rerun elevated to corroborate the -k group / -s service against the SCM services above."
                )
            else
                let group = (if isNull id.Group then "<none>" else id.Group)
                let declared = (if isNull id.DeclaredService then "<none — grouped host>" else id.DeclaredService)
                let mutable detail = sprintf "-k group: %s (the service pool) · -s service: %s" group declared

                // Corroborate only against the live SCM map while the subject is
                // the PID's live tenant — a recycled PID hosts someone else now.
                match target with
                | Some _ when hostedServices.Count > 0 ->
                    let csv = String.Join(",", hostedServices)

                    if SvchostIdentity.Mismatches(id.DeclaredService, csv) then
                        detail <-
                            detail
                            + (sprintf
                                "\r\n      ⚠ -s '%s' is NOT among the SCM services for this PID (%s) — masquerade signal"
                                id.DeclaredService
                                csv)
                    else
                        detail <- detail + "\r\n      command line corroborates the SCM services ✓"
                | _ ->
                    detail <- detail + "\r\n      SCM corroboration unavailable (subject exited — PID may host other services now)"

                r.Evidence.Add(EvidenceItem(Source = "Svchost identity", Detail = detail))

                if isNull id.Group then
                    r.Warnings.Add(
                        "svchost command line has no -k service group — the SCM always passes -k to a real service host; "
                        + "this is a masquerade signal (see audit-svchost.ps1)."
                    )

    static let addTaskHintEvidence (r: ProvenanceReport) (taskHint: TaskLaunchInfo) =
        if isNull (box taskHint) || String.IsNullOrEmpty taskHint.TaskPath then
            ()
        else
            let mutable detail = sprintf "task '%s'" taskHint.TaskPath

            if not (String.IsNullOrEmpty taskHint.UserContext) then
                detail <- detail + (sprintf " running as %s" taskHint.UserContext)

            if not (String.IsNullOrEmpty taskHint.HandlerDll) then
                if taskHint.HandlerDllExists.HasValue && taskHint.HandlerDllExists.Value then
                    detail <- detail + (sprintf "\r\n      COM handler: %s" taskHint.HandlerDll)
                else
                    detail <-
                        detail
                        + (sprintf
                            "\r\n      COM handler CLSID %s — DLL missing (orphaned task of uninstalled software)"
                            taskHint.HandlerClassId)

            r.Evidence.Add(EvidenceItem(Source = "Task Scheduler attribution", Detail = detail))

    // ── verdict ────────────────────────────────────────────────────────

    static let classify (r: ProvenanceReport) (taskHint: TaskLaunchInfo) : string * string =
        let parent = if r.Chain.Count > 1 then Some r.Chain.[1] else None

        let pn =
            match parent with
            | Some p ->
                (match p.Name with
                 | null -> None
                 | n -> Some(n.ToLowerInvariant()))
            | None -> None

        let hasTaskHint = not (isNull (box taskHint)) && not (String.IsNullOrEmpty taskHint.TaskPath)

        if r.Alive && String.Equals(r.Name, "System", StringComparison.OrdinalIgnoreCase) then
            ("Kernel process", "PID 4 is the Windows kernel process — the root every chain ends at.")
        elif r.Recycled then
            let nowOwns =
                sprintf "%s (started %s)" r.CurrentOwnerName (fmtN r.CurrentOwnerCreated "yyyy-MM-dd HH:mm:ss")

            if hasTaskHint then
                ( "Scheduled task (PID since recycled)",
                  (sprintf "Launched by scheduled task '%s'" taskHint.TaskPath)
                  + (if String.IsNullOrEmpty taskHint.UserContext then
                         ""
                     else
                         sprintf ", running as %s" taskHint.UserContext)
                  + (sprintf
                      ". That process has exited; PID %d now belongs to %s — an unrelated "
                      r.Pid
                      nowOwns)
                  + "process that inherited the recycled PID. Everything below describes the exited subject." )
            else
                ( "PID recycled (process exited)",
                  (sprintf
                      "The subject has exited and PID %d was reused — it now belongs to %s, which "
                      r.Pid
                      nowOwns)
                  + "is unrelated to the spawn being traced. Identity and chain below describe the exited "
                  + "subject, reconstructed from recorded create-events." )
        elif hasTaskHint then
            ( "Scheduled task",
              (sprintf "Launched by scheduled task '%s'" taskHint.TaskPath)
              + (if String.IsNullOrEmpty taskHint.UserContext then
                     ""
                 else
                     sprintf ", running as %s" taskHint.UserContext) )
        elif pn = Some "taskhostw.exe" then
            ( "Scheduled task",
              "Parent is taskhostw.exe — the Task Scheduler's host process. No task name was "
              + "captured for this instance (task history may have been disabled at launch time)." )
        elif pn = Some "services.exe" then
            ( "Windows service",
              "Parent is services.exe — the Service Control Manager. See 'Services hosted' in the evidence." )
        elif pn = Some "explorer.exe" then
            ( "User-launched (interactive)",
              "Parent is the shell (explorer.exe) — started by direct user action: double-click, "
              + "Start menu, or a shortcut." )
        elif (match pn with
              | Some p -> InteractiveShells |> Array.contains p
              | None -> false) then
            ( "User-launched from a terminal",
              (sprintf "Parent is %s — typed or scripted in a console session; see the " parent.Value.Name)
              + "PowerShell-history evidence below when present." )
        elif pn = Some "winlogon.exe" || pn = Some "userinit.exe" then
            ( "Logon autostart",
              "Parent is the logon chain — started automatically at sign-in. Check the autostart "
              + "evidence below (Run keys / Startup folder)." )
        elif r.Alive && String.Equals(r.Name, "svchost.exe", StringComparison.OrdinalIgnoreCase) then
            ("Windows service host", "svchost instance hosting the services listed in the evidence section.")
        elif
            (match parent with
             | None -> true
             | Some p ->
                 (match p.Name with
                  | null -> false
                  | n -> n = "<exited>"))
        then
            ( "Parent unknown (exited)",
              "The parent exited before this inquiry and no create-event was found — ancestry "
              + "is unrecoverable. Sysmon (Process Monitor → Setup Sysmon) makes every future "
              + "spawn retroactively traceable." )
        elif not parent.Value.Verified then
            ("Parent unverifiable", parent.Value.Note)
        else
            ( "Spawned by another process",
              (sprintf "Parent: %s (PID %d). Follow the chain upward — intermediates " parent.Value.Name parent.Value.Pid)
              + "like venv/python launchers legitimately re-spawn the real interpreter as a child." )

    static let formatBytes (bytes: int64) =
        if bytes < 1024L then
            sprintf "%d B" bytes
        elif bytes < 1048576L then
            (double bytes / 1024.0).ToString("F1") + " KB"
        else
            (double bytes / 1048576.0).ToString("F1") + " MB"

    /// <summary>
    /// Collect the full provenance of one PID. Any hint may be null —
    /// null hints constrain nothing (no hint, no veto). The C# optional
    /// parameters surface as real C# defaults (null) here.
    /// </summary>
    static member Collect(pid: int,
                          [<Optional; DefaultParameterValue(null: string)>] knownName: string,
                          [<Optional; DefaultParameterValue(null: string)>] knownImagePath: string,
                          [<Optional; DefaultParameterValue(null: TaskLaunchInfo)>] taskHint: TaskLaunchInfo,
                          [<Optional; DefaultParameterValue(null)>] hintSeenUtc: Nullable<DateTime>,
                          [<Optional; DefaultParameterValue(null)>] knownCreatedUtc: Nullable<DateTime>) : ProvenanceReport =
        let sw = Stopwatch.StartNew()

        let r =
            ProvenanceReport(
                Pid = pid,
                Name = (if isNull knownName then sprintf "<PID %d>" pid else knownName),
                ExePath = knownImagePath
            )

        let target = queryProcess pid

        // Target-PID reuse guard. The hints describe the process the
        // caller SAW (capture-time name/image, the subject's own start
        // time, the last traffic sighting); the live snapshot describes
        // whoever owns the PID NOW. When they disagree, Windows recycled
        // the PID in between: the subject has exited and the live process
        // is an unrelated bystander. Merging the two tenants is exactly
        // how a report ends up claiming bash.exe was launched by a
        // SYSTEM scheduled task.
        let mutable recycled = false

        (match target with
         | Some t ->
             let createdMismatch =
                 knownCreatedUtc.HasValue
                 && t.Created.IsSome
                 && (t.Created.Value.ToUniversalTime() - knownCreatedUtc.Value.ToUniversalTime()).Duration()
                    > TimeSpan.FromSeconds 5.0

             let newerThanLastSighting =
                 hintSeenUtc.HasValue
                 && t.Created.IsSome
                 && t.Created.Value.ToUniversalTime() > hintSeenUtc.Value.ToUniversalTime()

             recycled <-
                 createdMismatch
                 || newerThanLastSighting
                 || not (namesMatch knownName t.Name)
                 || not (imagesMatch knownImagePath t.ExePath)
         | None -> ())

        // Everything downstream must treat the subject as a dead process
        // when recycled: a None subject keeps the chain walk, the hosted-
        // service scan and the Sysmon record preference from reading the
        // bystander as the subject.
        let subject =
            match target, recycled with
            | Some t, false -> Some t
            | _, _ -> None

        match subject with
        | Some t ->
            r.Alive <- true
            r.Name <- t.Name

            if isNull r.ExePath then r.ExePath <- t.ExePath

            r.CommandLine <- t.CommandLine
            r.Owner <- t.Owner
            r.Created <- optToNullable t.Created
            r.Session <- if t.SessionId = 1 then "1 (console)" else string t.SessionId
            r.Memory <- formatBytes t.WorkingSet
        | None when recycled ->
            // the SUBJECT is dead — only its PID lives on
            let t = target.Value

            r.Recycled <- true
            r.Alive <- false

            r.CurrentOwnerName <- t.Name
            r.CurrentOwnerCreated <- optToNullable t.Created

            let mutable ownerCmd = t.CommandLine

            if not (String.IsNullOrEmpty ownerCmd) && ownerCmd.Length > 240 then
                ownerCmd <- ownerCmd.Substring(0, 240) + "…"

            r.CurrentOwnerSummary <-
                sprintf
                    "%s · image %s · started %s · owner %s · session %d"
                    t.Name
                    (if isNull t.ExePath then "?" else t.ExePath)
                    (fmtN (optToNullable t.Created) "yyyy-MM-dd HH:mm:ss")
                    (if isNull t.Owner then "?" else t.Owner)
                    t.SessionId

            r.Warnings.Add(
                (sprintf
                    "PID %d was recycled: the process this inquiry is about (%s) has exited. "
                    pid
                    r.Name)
                + (sprintf "The PID now belongs to %s (started %s) — an " t.Name (fmtN (optToNullable t.Created) "yyyy-MM-dd HH:mm:ss"))
                + "unrelated process. Identity, chain and verdict describe the exited subject; the current "
                + "PID owner is listed separately in the evidence."
            )

            let ownerCmdText = (if isNull ownerCmd then "(unreadable)" else ownerCmd)

            r.Evidence.Add(
                EvidenceItem(
                    Source = "Current PID owner (unrelated)",
                    Detail =
                        (sprintf
                            "PID %d now belongs to %s, started %s, owner %s.\r\n"
                            pid
                            t.Name
                            (fmtN (optToNullable t.Created) "yyyy-MM-dd HH:mm:ss")
                            (if isNull t.Owner then "?" else t.Owner))
                        + (sprintf "      image: %s\r\n" (if isNull t.ExePath then "?" else t.ExePath))
                        + (sprintf "      command line: %s" ownerCmdText)
                )
            )
        | None ->
            r.Warnings.Add(
                "Process is not running — live snapshot unavailable. "
                + "Identity comes from Process Monitor hints and recorded create-events."
            )

        buildChain r subject
        corroborateSysmon r hintSeenUtc
        corroborateAudit4688 r
        scanShellHistory r
        scanStartupEntries r

        let hostedServices = enumerateHostedServices r subject
        analyzeSvchostIdentity r subject hostedServices
        addTaskHintEvidence r taskHint

        let (verdict, verdictDetail) = classify r taskHint
        r.Verdict <- verdict
        r.VerdictDetail <- verdictDetail

        sw.Stop()
        r.Elapsed <- sw.Elapsed
        r
