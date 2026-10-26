// F# port of Core\Services\SysmonConnectWatcherService.cs (namespace
// AutoScope.Services) for the Engines library.
//
// F# port notes (deviations forced by F#/C# interop, none behavioral):
//   • C# events (OnError, OnConnect) are DelegateEvent fields exposed with
//     [<CLIEvent>] — C# `svc.OnConnect += handler` compiles unchanged with
//     the same Action<...> delegate shapes (verified: F#'s two-parameter
//     Event<'Del,'Args> rejects Action<'T> as a non-standard delegate, so
//     DelegateEvent is the one F# facility that preserves the C# shape).
//   • SysmonConnectEvent (nested in nothing — a top-level class in C#
//     too) keeps the same name; fields were already properties in C#.

namespace AutoScope.Engines.Watch

open System
open System.Diagnostics.Eventing.Reader
open System.Globalization
open System.Xml.Linq

/// <summary>A TCP/UDP connect as seen by Sysmon EID 3, full 4-tuple, any process.</summary>
type SysmonConnectEvent() =
    member val TimeUtc: DateTime = DateTime() with get, set
    member val Pid: int = 0 with get, set
    member val Image: string = null with get, set
    member val SourceIp: string = null with get, set
    member val SourcePort: int = 0 with get, set
    member val DestIp: string = null with get, set
    member val DestPort: int = 0 with get, set
    member val Protocol: string = null with get, set

    member this.IsTcp =
        String.Equals(this.Protocol, "tcp", StringComparison.OrdinalIgnoreCase)

/// <summary>
/// Watches Sysmon EID 3 (network connect) for ALL processes — no image
/// filter, no spawn tracking — and raises the full 4-tuple. Used by the
/// Traffic Patterns tab to attribute captured TCP flows to their pid/image
/// via TcpStreamCaptureService.TagFlow. The python-focused watcher in
/// ImageSpawnWatcherService stays separate; TagFlow is first-writer-wins,
/// so both watching at once is harmless.
/// </summary>
type SysmonConnectWatcherService() =

    let mutable watcher: EventLogWatcher = null

    let onError = DelegateEvent<Action<string>>()
    let onConnect = DelegateEvent<Action<SysmonConnectEvent>>()

    /// <summary>Sysmon PIDs are decimal in most EID 3 versions but hex (0x…) in some.</summary>
    static let parsePid (value: string) : int =
        if String.IsNullOrEmpty value then
            0
        else
            match Int32.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture) with
            | true, dec -> dec
            | _ ->
                if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
                    match
                        Int32.TryParse(value.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture)
                    with
                    | true, hex -> hex
                    | _ -> 0
                else
                    0

    static let parsePort (value: string) : int =
        match Int32.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture) with
        | true, port -> port
        | _ -> 0

    /// <summary>F# port: the C# field-like events; C# subscribers attach
    /// with += exactly as before.</summary>
    [<CLIEvent>]
    member _.OnError = onError.Publish

    [<CLIEvent>]
    member _.OnConnect = onConnect.Publish
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
            onError.Trigger [| box "Sysmon is not installed. Install it from the Sysmon Audit tab — process attribution needs it." |]
        | ex ->
            onError.Trigger [| box $"Failed to start connect watcher: {ex.Message}" |]

    member _.Stop() =
        if not (isNull watcher) then watcher.Dispose()
        watcher <- null

    member private _.WatcherEventRecordWritten(e: EventRecordWrittenEventArgs) =
        try
            if isNull e.EventRecord then ()
            else
                // EventData is parsed BY NAME, never by property index — the
                // field order varies across Sysmon versions.
                let doc = XDocument.Parse(e.EventRecord.ToXml())
                let ns = XNamespace.Get("http://schemas.microsoft.com/win/2004/08/events/event")

                match doc.Root with
                | null -> ()
                | root ->
                    match root.Element(ns + "EventData") with
                    | null -> ()
                    | eventData ->
                        let mutable image = ""
                        let mutable pidRaw = ""
                        let mutable srcIp = ""
                        let mutable srcPort = ""
                        let mutable dstIp = ""
                        let mutable dstPort = ""
                        let mutable proto = "tcp"

                        for data in eventData.Elements(ns + "Data") do
                            match data.Attribute(XName.Get "Name") with
                            | null -> ()
                            | a ->
                                (match a.Value with
                                 | "Image" -> image <- data.Value
                                 | "ProcessId" -> pidRaw <- data.Value
                                 | "SourceIp" -> srcIp <- data.Value
                                 | "SourcePort" -> srcPort <- data.Value
                                 | "DestinationIp" -> dstIp <- data.Value
                                 | "DestinationPort" -> dstPort <- data.Value
                                 | "Protocol" -> proto <- data.Value
                                 | _ -> ())

                        let pid = parsePid pidRaw
                        if pid <= 0 || String.IsNullOrEmpty image then ()
                        else
                            // F# port: TimeCreated is Nullable<DateTime> —
                            // the C# `?? DateTime.UtcNow` as HasValue.
                            let timeUtc =
                                let tc = e.EventRecord.TimeCreated
                                if tc.HasValue then tc.Value.ToUniversalTime() else DateTime.UtcNow

                            let evt =
                                SysmonConnectEvent(
                                    TimeUtc = timeUtc,
                                    Pid = pid,
                                    Image = image,
                                    SourceIp = srcIp,
                                    SourcePort = parsePort srcPort,
                                    DestIp = dstIp,
                                    DestPort = parsePort dstPort,
                                    Protocol = proto
                                )

                            onConnect.Trigger [| box evt |]
        with _ ->
            // a malformed record never takes the watcher down
            ()
