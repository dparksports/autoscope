// F# port of Core\Models\TransmissionRecord.cs and
// Core\Services\TransmissionsArchiveService.cs (namespaces
// AutoScope.Models / AutoScope.Services) for the Engines library.
//
// F# port notes (deviations forced by F#/C# interop, none behavioral):
//   • TransmissionRecord stays a mutable class implementing
//     INotifyPropertyChanged with the same property names — the app UI
//     binds it. The public event and the interface implementation share
//     one Event cell, so subscribers via either route see the same
//     notifications. F# classes are sealed (C# classes are not); nothing
//     binds or subclasses it.
//   • SetField/OnPropertyChanged keep the C# shapes but take the property
//     name explicitly instead of [CallerMemberName] (same strings, no
//     dependence on F# caller-name plumbing in setters).
//   • Optional parameters use [<Optional; DefaultParameterValue>], not
//     F# `?` optionals — F# optionals surface as FSharpOption<T> and
//     would be uncallable with the C# source's default-omission shapes
//     (Read(4000, null, null, sinceUtc), Read(max: 2000, sinceUtc: ...)).
//   • The archive root defaults to WatchConfig.Identity.DataRoot
//     \transmissions (the C# hardcoded %LOCALAPPDATA%\AutoScope
//     \transmissions — the identical physical path for the AutoScope
//     app); the settable ArchiveDirectory self-test seam stays. The
//     on-disk format is IDENTICAL: same JSONL line shape via the same
//     System.Text.Json call, same bodies\<day>\<id>.<direction>.bin
//     layout — existing archives keep parsing.

// FS3211 fires on [<Optional; DefaultParameterValue(null)>] below, but the
// emitted metadata is exactly what C# needs (same pattern as Probe.fs —
// verified there by reflection and by ported call shapes compiling).
#nowarn "3211"

namespace AutoScope.Engines.Watch

open System
open System.Collections.Generic
open System.ComponentModel
open System.IO
open System.Runtime.InteropServices
open System.Security.Cryptography
open System.Text.Json

// ── record model (C# Core\Models\TransmissionRecord.cs) ───────────

/// <summary>
/// One finalized outbound TLS conversation as the Transmissions tab sees
/// it: the decrypted view when session keys existed, the honest status
/// ("encrypted — no keys", "not TLS") when they did not. The wire facts
/// (endpoints, sizes, pid via Sysmon EID 3) are always present; the
/// content lives in the archive's body files, referenced by Id.
/// </summary>
type TransmissionRecord() =

    let propertyChanged = Event<PropertyChangedEventHandler, PropertyChangedEventArgs>()
    let mutable provider = "Unclassified"

    member val Id = Guid.NewGuid().ToString("N") with get, set
    member val TsUtc = DateTime() with get, set

    member val Pid = 0 with get, set
    member val Image: string = null with get, set
    member this.ProcessDisplay =
        if String.IsNullOrEmpty this.Image then
            (if this.Pid > 0 then $"pid {this.Pid}" else "unattributed")
        else Path.GetFileName this.Image

    member val RemoteIp: string = null with get, set
    member val RemotePort = 0 with get, set
    member this.ServerEndpoint = $"{this.RemoteIp}:{this.RemotePort}"
    member val LocalEndpoint: string = null with get, set

    member val Sni: string = null with get, set
    member this.HostDisplay = if String.IsNullOrEmpty this.Sni then "(no SNI)" else this.Sni

    member val TlsVersion: string = null with get, set
    member val Alpn: string = null with get, set
    member val CipherSuite: string = null with get, set

    /// <summary>RDAP netname/org when known, else the static range
    /// classification, else "Unclassified". Late-bound: RDAP answers
    /// asynchronously and the grid row updates in place.</summary>
    member this.Provider
        with get () = provider
        and set value =
            if this.SetField(&provider, value, "Provider") then
                this.OnPropertyChanged "ProviderAndCountry"
    member val ProviderCountry: string = null with get, set
    member this.ProviderAndCountry =
        if String.IsNullOrEmpty this.ProviderCountry then this.Provider
        else $"{this.Provider} ({this.ProviderCountry})"

    member val ClientBytes = 0L with get, set       // wire, reassembled
    member val ServerBytes = 0L with get, set
    member val ClientAppBytes = 0L with get, set    // decrypted plaintext
    member val ServerAppBytes = 0L with get, set

    /// <summary>"decrypted" · "encrypted (no keys)" · "not TLS" ·
    /// "no handshake" · "unsupported cipher" · "undecryptable", with an
    /// optional " · truncated" suffix when the capture dropped bytes.
    /// Intercept-sourced rows use "decrypted · intercept …" variants.</summary>
    member val Status: string = null with get, set
    member this.Decrypted =
        this.Status <> null &&
        (this.Status = "decrypted" || this.Status.StartsWith("decrypted", StringComparison.Ordinal))

    /// <summary>The user-facing threshold this tab exists for: an upload
    /// larger than 10 KB deserves a row even when no keys existed.</summary>
    member this.BigUpload = this.ClientBytes > 10L * 1024L
    member this.BigUploadVisibility = if this.BigUpload then "Visible" else "Collapsed"

    member val HasContent = false with get, set
    member val Sha256: string = null with get, set
    member val MessageCount = 0 with get, set
    member val ContentKinds: string = null with get, set

    member val ArchiveDay: string = null with get, set

    // ── display helpers ──────────────────────────────────────────────

    member this.TimeDisplay = if this.TsUtc = DateTime() then "" else this.TsUtc.ToLocalTime().ToString("MM-dd HH:mm:ss")
    member this.UpDisplay = TransmissionRecord.FormatBytes this.ClientBytes
    member this.DownDisplay = TransmissionRecord.FormatBytes this.ServerBytes
    member this.AppBytesDisplay =
        if this.Decrypted then
            $"{TransmissionRecord.FormatBytes this.ClientAppBytes} / {TransmissionRecord.FormatBytes this.ServerAppBytes}"
        else "—"

    static member private FormatBytes(bytes: int64) =
        if bytes < 1024L then $"{bytes}B"
        elif bytes < 1048576L then $"{float bytes / 1024.0:F1}KB"
        else $"{float bytes / 1048576.0:F1}MB"

    [<CLIEvent>]
    member _.PropertyChanged = propertyChanged.Publish

    interface INotifyPropertyChanged with
        [<CLIEvent>]
        member _.PropertyChanged = propertyChanged.Publish

    member private this.OnPropertyChanged(name: string) =
        propertyChanged.Trigger(this, PropertyChangedEventArgs(name))

    // F# port: the C# SetField<T>(ref field, ...) is spelled with a
    // concrete byref<string> — F# does not permit byref<'T> in generic
    // members, and Provider is the only property with change tracking.
    member private this.SetField(backing: byref<string>, value: string, name: string) =
        if EqualityComparer<string>.Default.Equals(backing, value) then false
        else
            backing <- value
            this.OnPropertyChanged name
            true

// ── archive service (C# Core\Services\TransmissionsArchiveService.cs) ──

/// <summary>
/// On-disk store behind the Transmissions tab, mirroring the Sysmon
/// archive's shape: one readable, greppable JSONL index file per day
/// under DataRoot\transmissions, plus full-request / full-response body
/// blobs in bodies\ — no truncation, the >10 KB cases are exactly the
/// ones that must be complete on disk. Each row carries a SHA-256 over
/// both plaintext directions so "what was sent" stays provable after
/// the fact.
///
/// Retention: day files prune after DefaultRetainDays; the bodies
/// folder additionally rotates oldest-day directories out once it
/// exceeds BodiesBudgetBytes. Everything stays local — the AI bridge
/// exposes metadata only, never these files.
/// </summary>
[<AbstractClass; Sealed>]
type TransmissionsArchiveService private () =

    static let gate = obj()
    static let mutable lastPruneUtc = DateTime.MinValue

    static member DefaultRetainDays = 30
    static member BodiesBudgetBytes = 256L * 1024L * 1024L

    /// <summary>Archive root; settable for offline self-tests (house pattern).
    /// F# port: defaults to DataRoot\transmissions instead of the C#
    /// %LOCALAPPDATA%\AutoScope\transmissions — same physical path for the
    /// AutoScope app, no app name hardcoded in the engine.</summary>
    static member val ArchiveDirectory =
        Path.Combine(WatchConfig.Identity.DataRoot, "transmissions") with get, set

    static member private BodiesRoot =
        Path.Combine(TransmissionsArchiveService.ArchiveDirectory, "bodies")

    static member DayFilePath(utc: DateTime) =
        Path.Combine(TransmissionsArchiveService.ArchiveDirectory, "transmissions-" + utc.ToString("yyyy-MM-dd") + ".jsonl")

    // ── append ────────────────────────────────────────────────────────

    /// <summary>
    /// Writes one row's index line and (when the flow decrypted to
    /// content) its body blobs. Returns true when anything was written.
    /// The pair (request, response) are the decrypted plaintext streams;
    /// either may be null/empty.
    /// </summary>
    static member Append(record: TransmissionRecord, requestStream: byte[], responseStream: byte[]) : bool =
        if isNull (box record) then false
        else
        try
            lock gate (fun () ->
                Directory.CreateDirectory TransmissionsArchiveService.ArchiveDirectory |> ignore

                let hasContent =
                    (requestStream <> null && requestStream.Length > 0) ||
                    (responseStream <> null && responseStream.Length > 0)
                record.HasContent <- hasContent

                if hasContent then
                    record.Sha256 <- TransmissionsArchiveService.ComputeSha256(requestStream, responseStream)
                    Directory.CreateDirectory TransmissionsArchiveService.BodiesRoot |> ignore
                    if requestStream <> null && requestStream.Length > 0 then
                        File.WriteAllBytes(TransmissionsArchiveService.BodyPath(record, "request"), requestStream)
                    if responseStream <> null && responseStream.Length > 0 then
                        File.WriteAllBytes(TransmissionsArchiveService.BodyPath(record, "response"), responseStream)
                record.ArchiveDay <- record.TsUtc.ToString("yyyy-MM-dd")

                // F# port: same keys, same insertion order, same
                // JsonSerializer call — byte-identical JSONL lines, so
                // archives written by the C# service and this one are one
                // format.
                let fields = Dictionary<string, obj>()
                let add (key: string) (value: obj) = fields[key] <- value
                add "id" record.Id
                add "ts" (record.TsUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))
                add "pid" record.Pid
                add "image" record.Image
                add "remote" record.ServerEndpoint
                add "local" record.LocalEndpoint
                add "sni" record.Sni
                add "tls" record.TlsVersion
                add "alpn" record.Alpn
                add "cipher" record.CipherSuite
                add "provider" record.Provider
                add "provider_country" record.ProviderCountry
                add "client_bytes" record.ClientBytes
                add "server_bytes" record.ServerBytes
                add "client_app_bytes" record.ClientAppBytes
                add "server_app_bytes" record.ServerAppBytes
                add "status" record.Status
                add "has_content" hasContent
                add "sha256" record.Sha256
                add "message_count" record.MessageCount
                add "content_kinds" record.ContentKinds
                let line = JsonSerializer.Serialize fields
                File.AppendAllText(TransmissionsArchiveService.DayFilePath record.TsUtc, line + Environment.NewLine)

                TransmissionsArchiveService.MaybePrune()
                true)
        with _ ->
            false // archive is best-effort; the live row still showed in the UI

    static member LoadBody(id: string, day: string, direction: string) : byte[] =
        try
            let path = TransmissionsArchiveService.BodyPath(id, day, direction)
            if File.Exists path then File.ReadAllBytes path else null
        with _ -> null

    static member private BodyPath(record: TransmissionRecord, direction: string) =
        TransmissionsArchiveService.BodyPath(record.Id, record.ArchiveDay, direction)

    static member private BodyPath(id: string, day: string, direction: string) =
        let dir = Path.Combine(TransmissionsArchiveService.BodiesRoot, (if String.IsNullOrEmpty day then "unknown" else day))
        Path.Combine(dir, $"{id}.{direction}.bin")

    static member private ComputeSha256(request: byte[], response: byte[]) : string =
        use sha = SHA256.Create()
        use combined = new MemoryStream(
                (if isNull request then 0 else request.Length) +
                (if isNull response then 0 else response.Length) + 1)
        if request <> null && request.Length > 0 then
            combined.Write(request, 0, request.Length)
            combined.WriteByte(byte '\n')
        if response <> null && response.Length > 0 then
            combined.Write(response, 0, response.Length)
        combined.Position <- 0L
        (Convert.ToHexString(sha.ComputeHash combined)).ToLowerInvariant()

    // ── retention ─────────────────────────────────────────────────────

    /// <summary>Runs at most hourly: day-file age prune + bodies budget
    /// rotation. Public for the tab's "prune now" and self-tests.</summary>
    static member Prune([<Optional; DefaultParameterValue(30)>] retainDays: int) =
        try
            if not (Directory.Exists TransmissionsArchiveService.ArchiveDirectory) then ()
            else
            let cutoff = DateTime.UtcNow.Date.AddDays(float -retainDays)
            for file in Directory.GetFiles(TransmissionsArchiveService.ArchiveDirectory, "transmissions-*.jsonl") do
                let stem = Path.GetFileName(file).Substring("transmissions-".Length).Replace(".jsonl", "")
                match DateTime.TryParseExact(stem, "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.None) with
                | true, day when day < cutoff ->
                    try File.Delete file with _ -> () // locked — next prune
                | _ -> ()

            if Directory.Exists TransmissionsArchiveService.BodiesRoot then
                let dayDirs =
                    Directory.GetDirectories TransmissionsArchiveService.BodiesRoot
                    |> Seq.map (fun d -> (d, TransmissionsArchiveService.ParseDay d))
                    |> Seq.choose (fun (path, day) -> day |> Option.map (fun day -> (path, day)))
                    |> Seq.sortBy snd
                    |> Seq.toList
                for (path, day) in dayDirs do
                    if day < cutoff then
                        try Directory.Delete(path, true) with _ -> ()

                let mutable used = dayDirs |> List.sumBy (fun (path, _) -> TransmissionsArchiveService.DirSize path)
                let mutable oldest = 0
                let mutable stopRotating = false
                while not stopRotating && used > TransmissionsArchiveService.BodiesBudgetBytes && oldest < dayDirs.Length do
                    let victim = dayDirs[oldest]
                    oldest <- oldest + 1
                    let size = TransmissionsArchiveService.DirSize(fst victim)
                    try
                        Directory.Delete(fst victim, true)
                        used <- used - size
                    with _ ->
                        stopRotating <- true
        with _ -> () // retention is opportunistic

    static member private MaybePrune() =
        if (DateTime.UtcNow - lastPruneUtc).TotalMinutes < 60.0 then ()
        else
            lastPruneUtc <- DateTime.UtcNow
            TransmissionsArchiveService.Prune()

    static member private ParseDay(dir: string) : DateTime option =
        let stem = Path.GetFileName dir
        match DateTime.TryParseExact(stem, "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.None) with
        | true, day -> Some day
        | _ -> None

    static member private DirSize(dir: string) : int64 =
        try
            Directory.GetFiles(dir, "*", SearchOption.AllDirectories)
            |> Seq.sumBy (fun f -> (FileInfo f).Length)
        with _ -> 0L

    // ── queries ───────────────────────────────────────────────────────

    /// <summary>Newest-first read of archived rows. Filters are applied
    /// in-memory per line; `contains` matches any field.</summary>
    static member Read(
        [<Optional; DefaultParameterValue(200)>] max: int,
        [<Optional; DefaultParameterValue(null)>] pid: Nullable<int>,
        [<Optional; DefaultParameterValue(null)>] contains: string,
        [<Optional; DefaultParameterValue(null)>] sinceUtc: Nullable<DateTime>) : ResizeArray<TransmissionRecord> =
        let hits = ResizeArray<TransmissionRecord>()
        try
            if not (Directory.Exists TransmissionsArchiveService.ArchiveDirectory) then ()
            else
            // F# port: C# OrderByDescending(f => f, StringComparer.Ordinal) —
            // ordinal string compare, descending, via sortWith.
            let files =
                Directory.GetFiles(TransmissionsArchiveService.ArchiveDirectory, "transmissions-*.jsonl")
                |> Array.sortWith (fun a b -> String.CompareOrdinal(b, a))
                |> Array.toList

            for file in files do
                if hits.Count >= max then ()
                else
                let stem = Path.GetFileName(file).Substring("transmissions-".Length).Replace(".jsonl", "")
                let skipByDay =
                    sinceUtc.HasValue &&
                    (match DateTime.TryParseExact(stem, "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.None) with
                     | true, day -> day < sinceUtc.Value.Date
                     | _ -> false)
                if skipByDay then ()
                else
                let lines = File.ReadAllLines file
                let mutable li = lines.Length - 1
                while li >= 0 && hits.Count < max do
                    let line = lines[li]
                    li <- li - 1
                    if line.Length = 0 then ()
                    else
                    try
                        use doc = JsonDocument.Parse line
                        let root = doc.RootElement
                        let rowPid =
                            match root.TryGetProperty("pid") with
                            | true, p -> p.GetInt32()
                            | _ -> 0
                        if pid.HasValue && rowPid <> pid.Value then ()
                        else
                        let record =
                            TransmissionRecord(
                                Id = TransmissionsArchiveService.GetString(root, "id"),
                                TsUtc = DateTime.Parse(TransmissionsArchiveService.GetString(root, "ts"),
                                                        System.Globalization.CultureInfo.InvariantCulture,
                                                        System.Globalization.DateTimeStyles.AssumeUniversal).ToUniversalTime(),
                                Pid = rowPid,
                                Image = TransmissionsArchiveService.GetString(root, "image"),
                                RemoteIp = TransmissionsArchiveService.RemoteIpOf(TransmissionsArchiveService.GetString(root, "remote")),
                                RemotePort = TransmissionsArchiveService.RemotePortOf(TransmissionsArchiveService.GetString(root, "remote")),
                                LocalEndpoint = TransmissionsArchiveService.GetString(root, "local"),
                                Sni = TransmissionsArchiveService.GetString(root, "sni"),
                                TlsVersion = TransmissionsArchiveService.GetString(root, "tls"),
                                Alpn = TransmissionsArchiveService.GetString(root, "alpn"),
                                CipherSuite = TransmissionsArchiveService.GetString(root, "cipher"),
                                Provider = (match TransmissionsArchiveService.GetString(root, "provider") with
                                            | null -> "Unclassified"
                                            | v -> v),
                                ProviderCountry = TransmissionsArchiveService.GetString(root, "provider_country"),
                                ClientBytes = TransmissionsArchiveService.GetLong(root, "client_bytes"),
                                ServerBytes = TransmissionsArchiveService.GetLong(root, "server_bytes"),
                                ClientAppBytes = TransmissionsArchiveService.GetLong(root, "client_app_bytes"),
                                ServerAppBytes = TransmissionsArchiveService.GetLong(root, "server_app_bytes"),
                                Status = TransmissionsArchiveService.GetString(root, "status"),
                                HasContent = (match root.TryGetProperty("has_content") with
                                              | true, hc -> hc.GetBoolean()
                                              | _ -> false),
                                Sha256 = TransmissionsArchiveService.GetString(root, "sha256"),
                                MessageCount = int (TransmissionsArchiveService.GetLong(root, "message_count")),
                                ContentKinds = TransmissionsArchiveService.GetString(root, "content_kinds"),
                                ArchiveDay = stem)

                        if not (String.IsNullOrEmpty contains) then
                            let haystack = $"{record.Image} {record.Sni} {record.RemoteIp} {record.Provider} {record.Status}"
                            if not (haystack.Contains(contains, StringComparison.OrdinalIgnoreCase)) then ()
                            else hits.Add record
                        else hits.Add record
                    with _ -> () // truncated/corrupt line — skip, keep the file
        with _ -> () // unreadable archive — partial result, never a throw
        hits

    /// <summary>(day files, bytes on disk) for the tab's status line.</summary>
    static member StatusSummary() : struct (int * int64) =
        try
            if not (Directory.Exists TransmissionsArchiveService.ArchiveDirectory) then struct (0, 0L)
            else
            let days =
                Directory.GetFiles(TransmissionsArchiveService.ArchiveDirectory, "transmissions-*.jsonl").Length
            let bytes = TransmissionsArchiveService.DirSize TransmissionsArchiveService.ArchiveDirectory
            struct (days, bytes)
        with _ -> struct (0, 0L)

    static member private GetString(root: JsonElement, prop: string) : string =
        match root.TryGetProperty(prop) with
        | true, v when v.ValueKind = JsonValueKind.String -> v.GetString()
        | _ -> null

    static member private GetLong(root: JsonElement, prop: string) : int64 =
        match root.TryGetProperty(prop) with
        | true, v when v.ValueKind = JsonValueKind.Number ->
            match v.TryGetInt64() with
            | true, n -> n
            | _ -> 0L
        | _ -> 0L

    static member private RemoteIpOf(endpoint: string) : string =
        if endpoint <> null && endpoint.LastIndexOf(':') > 0 then endpoint[..endpoint.LastIndexOf(':') - 1]
        else endpoint

    static member private RemotePortOf(endpoint: string) : int =
        if endpoint <> null && endpoint.LastIndexOf(':') > 0 then
            match Int32.TryParse(endpoint[endpoint.LastIndexOf(':') + 1..]) with
            | true, port -> port
            | _ -> 0
        else 0
