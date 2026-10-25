namespace AutoScope.Engines.Diagnosis

open System
open System.Collections.Generic
open System.Runtime.InteropServices
open AutoScope.Engines.Core

// F# port of Core\Services\SiteFingerprintService.cs — pure logic only,
// same numbers, same strings, same ordering. The C# nested data classes
// (EdgeStat, SiteFingerprint) become flat records; the static class becomes
// the SiteFingerprintService static holder below.

/// One server address this host talked to, with how many conversations
/// landed on it (C#: SiteFingerprintService.EdgeStat).
type EdgeStat =
    { Ip: string
      Conversations: int }

/// Behavioral fingerprint of one hostname's recorded traffic (C#:
/// SiteFingerprintService.SiteFingerprint). Immutable — the C# original had
/// settable properties that Fingerprint() mutated while building; this port
/// computes every field first and constructs the record once, so the final
/// values are identical with no mutation-after-construction.
type SiteFingerprint =
    { Host: string
      FirstUtc: DateTime
      LastUtc: DateTime
      Conversations: int
      ClientBytes: int64
      Edges: ResizeArray<EdgeStat>
      Processes: ResizeArray<string>
      /// 5-second windows containing 3+ conversation starts.
      BurstWindows: int
      FirstBurstUtc: Nullable<DateTime>
      /// Most conversations opened to a single edge in any one minute.
      MaxSameEdgePerMinute: int
      /// Plain-English observations — one line per signal that fired.
      Signals: ResizeArray<string> }

    /// True when at least one signal fired. Evidence for the verdict
    /// engine; never shown to the user as a conclusion.
    member this.LooksStruggling = this.Signals.Count > 0

    member this.SpanDisplay =
        // C#: FirstUtc == default(DateTime) — tick comparison, Kind
        // ignored; F# DateTime equality does the same.
        if this.FirstUtc = DateTime.MinValue || this.LastUtc = DateTime.MinValue then ""
        else
            this.FirstUtc.ToLocalTime().ToString("MM-dd HH:mm") + " → " +
            this.LastUtc.ToLocalTime().ToString("HH:mm")

module private FpUtil =

    // F# port of LINQ GroupBy(keySelector, comparer): groups come out in
    // first-appearance order and each group is keyed by its first-seen
    // casing — exactly what the C# GroupBy guarantees.
    let groupByString (comparer: IEqualityComparer<string>) (keyOf: 'T -> string) (items: seq<'T>) =
        let index = Dictionary<string, int>(comparer)
        let groups = ResizeArray<string * ResizeArray<'T>>()
        for item in items do
            let key = keyOf item
            match index.TryGetValue(key) with
            | true, i -> (snd groups.[i]).Add(item)
            | _ ->
                index.Add(key, groups.Count)
                let g = ResizeArray<'T>()
                g.Add(item)
                groups.Add(key, g)
        groups |> Seq.toList

    // F# port of LINQ Distinct(StringComparer.OrdinalIgnoreCase): keeps the
    // first occurrence (and its casing), preserves order.
    let distinctIgnoreCase (items: string seq) =
        let seen = HashSet<string>(StringComparer.OrdinalIgnoreCase)
        let out = ResizeArray<string>()
        for s in items do
            if seen.Add(s) then out.Add(s)
        out |> Seq.toList

/// Passive evidence engine behind the Site Doctor tab (C#:
/// SiteFingerprintService): groups the Transmissions archive by SNI
/// hostname and reads the behavioral fingerprint out of what is already on
/// disk — no packets sent, nothing guessed. Three signals, each one
/// observed in the wild while diagnosing a real "this site refreshes
/// slowly" report:
///
///   • Edge dispersion — a browser that keeps landing on fresh server
///     addresses (4+ in an hour) is being steered around, usually by
///     short-TTL CDN DNS. Healthy sites sit on 1–2 addresses; the baseline
///     is computed from the machine's own other traffic.
///   • Connection bursts — 3+ conversations to one hostname opened within
///     the same five seconds is a browser racing retries after a stall,
///     not normal keep-alive usage.
///   • Single-edge churn — repeated new connections to the same address
///     within a minute, the shape of handshakes that complete and then die
///     before the browser will reuse them.
///
/// Evidence, not verdict: the archive only records conversations worth
/// keeping, so counts are a sample, never the whole story. The verdict
/// engine weighs this fingerprint together with active probe results.
[<AbstractClass; Sealed>]
type SiteFingerprintService() =

    // Browser process names recognized for the tab's "sites from" filter.
    // Matched case-insensitively against the row's process filename with or
    // without .exe — any other process is "apps", never a browser.
    static let knownBrowsers =
        [| "chrome"; "brave"; "firefox"; "msedge"; "edge"; "opera"; "vivaldi"
           "librewolf"; "waterfox"; "thorium"; "chromium"; "iron"; "avastbrowser"
           "duckduckgo"; "arc"; "zen" |]

    /// Burst window: 3+ conversation starts this close together.
    static member BurstWindow = TimeSpan.FromSeconds 5.0

    /// Dispersion floor: this many distinct edges flags steering even when
    /// the machine-wide baseline is unusually high.
    static member EdgeDispersionFloor = 4

    /// Minimum conversations before a host is worth judging.
    static member MinConversations = 3

    // C# internal — public here so the C# self-test can exercise it.
    static member IsBrowserProcess(processDisplay: string) =
        if String.IsNullOrEmpty(processDisplay) then false
        else
            let mutable name = processDisplay.Trim().ToLowerInvariant()
            if name.EndsWith(".exe") then name <- name.Substring(0, name.Length - 4)
            knownBrowsers |> Array.contains name

    /// Browsers with recorded conversations, busiest first — the tab's
    /// "sites from" filter list. Every user's list is their own: it comes
    /// from what they actually browse, never a hard-coded site roster.
    static member BrowsersSeen(rows: IReadOnlyList<TrafficRow>,
                               [<Optional; DefaultParameterValue(8)>] max: int) : ResizeArray<string> =
        let source =
            if isNull (box rows) then Seq.empty
            else
                rows
                |> Seq.filter (fun r ->
                    not (String.IsNullOrEmpty(r.Sni)) &&
                    SiteFingerprintService.IsBrowserProcess(r.Process))
        source
        |> FpUtil.groupByString EqualityComparer<string>.Default (fun r ->
            // C# group key: Replace(".exe", "") strips EVERY occurrence,
            // not just a trailing one — keep that exact behavior.
            r.Process.Trim().ToLowerInvariant().Replace(".exe", ""))
        |> List.sortByDescending (fun (_, g) -> g.Count) // stable, like LINQ OrderByDescending
        |> List.truncate max
        |> List.map fst
        |> ResizeArray<string>

    /// Hostnames worth offering in the tab's picker, busiest first. With
    /// browser set, only that browser's recorded traffic counts — "the
    /// sites I actually visit in Chrome" instead of someone else's idea of
    /// popular.
    static member TopHosts(rows: IReadOnlyList<TrafficRow>,
                           [<Optional; DefaultParameterValue(25)>] maxHosts: int,
                           [<Optional; DefaultParameterValue(null: string)>] browser: string) : ResizeArray<string> =
        let source =
            if isNull (box rows) then Seq.empty
            else rows |> Seq.filter (fun r -> not (String.IsNullOrEmpty(r.Sni)))
        let source =
            if String.IsNullOrEmpty(browser) then source
            else
                let want = browser.Trim().ToLowerInvariant()
                source
                |> Seq.filter (fun r ->
                    let name = (if isNull r.Process then "" else r.Process).Trim().ToLowerInvariant()
                    name = want || name = want + ".exe")
        source
        |> FpUtil.groupByString StringComparer.OrdinalIgnoreCase (fun r -> r.Sni)
        // F# port: OrderByDescending(count).ThenByDescending(maxTs) — sort
        // by the secondary key first, then stable-sort by the primary.
        |> List.sortByDescending (fun (_, g) -> g |> Seq.map (fun r -> r.TsUtc) |> Seq.max)
        |> List.sortByDescending (fun (_, g) -> g.Count)
        |> List.truncate maxHosts
        |> List.map fst
        |> ResizeArray<string>

    /// Every host's fingerprint; the input to the machine-wide baseline.
    static member AllFingerprints(rows: IReadOnlyList<TrafficRow>) : Dictionary<string, SiteFingerprint> =
        let all = Dictionary<string, SiteFingerprint>(StringComparer.OrdinalIgnoreCase)
        if isNull (box rows) then all
        else
            let groups =
                rows
                |> Seq.filter (fun r -> not (String.IsNullOrEmpty(r.Sni)))
                |> FpUtil.groupByString StringComparer.OrdinalIgnoreCase (fun r -> r.Sni)
            for (key, group) in groups do
                // F# port: Fingerprint(group.ToList()) — i.e. the C# default
                // baselineEdges of 1 for every per-host fingerprint here.
                let fp = SiteFingerprintService.Fingerprint(group, 1)
                if fp.Conversations > 0 then all.[key] <- fp
            all

    /// The machine-wide control: median distinct-edge count across every
    /// host with enough conversations to judge. A site using many times
    /// more edges than the machine's own norm is the dispersion signal.
    static member BaselineEdgeCount(all: IReadOnlyDictionary<string, SiteFingerprint>) : int =
        let counts =
            all.Values
            |> Seq.filter (fun f -> f.Conversations >= SiteFingerprintService.MinConversations)
            |> Seq.map (fun f -> f.Edges.Count)
            |> Seq.toList
            |> List.sort
        if counts.IsEmpty then 1
        elif counts.Length % 2 = 1 then counts.[counts.Length / 2]
        else max 1 ((counts.[counts.Length / 2 - 1] + counts.[counts.Length / 2]) / 2)

    /// Fingerprint one host's rows (callers filter by SNI; the method is
    /// pure so the offline self-test can feed synthetic records).
    static member Fingerprint(siteRows: IReadOnlyList<TrafficRow>,
                              [<Optional; DefaultParameterValue(1)>] baselineEdges: int) : SiteFingerprint =
        let rows = if isNull (box siteRows) then [] else siteRows |> Seq.toList
        let processes =
            rows
            |> List.filter (fun r -> not (String.IsNullOrEmpty(r.Process)))
            |> List.map (fun r -> r.Process)
            |> FpUtil.distinctIgnoreCase
            |> ResizeArray<string>
        let clientBytes = rows |> List.sumBy (fun r -> r.ClientBytes)
        if rows.IsEmpty then
            // C# early return: Host/FirstUtc/LastUtc never set, lists empty.
            { Host = null
              FirstUtc = DateTime.MinValue
              LastUtc = DateTime.MinValue
              Conversations = 0
              ClientBytes = clientBytes
              Edges = ResizeArray<EdgeStat>()
              Processes = processes
              BurstWindows = 0
              FirstBurstUtc = Nullable<DateTime>()
              MaxSameEdgePerMinute = 0
              Signals = ResizeArray<string>() }
        else
            // C# OrderBy(TsUtc) is stable; so is F# List.sortBy — equal
            // timestamps keep source order.
            let byTime = rows |> List.sortBy (fun r -> r.TsUtc)
            let host = byTime.[0].Sni
            let firstUtc = byTime.[0].TsUtc
            let lastUtc = byTime.[byTime.Length - 1].TsUtc

            let edges =
                byTime
                |> FpUtil.groupByString StringComparer.OrdinalIgnoreCase (fun r -> r.RemoteIp)
                |> List.map (fun (ip, g) -> { Ip = ip; Conversations = g.Count })
                |> List.sortByDescending (fun e -> e.Conversations)
                |> ResizeArray<EdgeStat>

            // Bursts: sliding 5-second windows with 3+ starts (same host).
            let burstWindow = SiteFingerprintService.BurstWindow
            let mutable burst = 0
            let mutable firstBurst = Nullable<DateTime>()
            let mutable i = 0
            while i < byTime.Length do
                let mutable j = i
                while j < byTime.Length && byTime.[j].TsUtc - byTime.[i].TsUtc <= burstWindow do
                    j <- j + 1
                if j - i >= 3 then
                    burst <- burst + 1
                    if not firstBurst.HasValue then firstBurst <- Nullable(byTime.[i].TsUtc)
                    i <- j - 1 // skip past the burst; overlapping windows count once
                i <- i + 1

            // Single-edge churn: busiest rolling minute for any one edge.
            let oneMinute = TimeSpan.FromMinutes 1.0
            let mutable maxSameEdge = 0
            for (_, edgeGroup) in FpUtil.groupByString StringComparer.OrdinalIgnoreCase (fun r -> r.RemoteIp) byTime do
                let times = edgeGroup |> Seq.map (fun r -> r.TsUtc) |> Seq.toList |> List.sort
                let mutable i = 0
                while i < times.Length do
                    let mutable j = i
                    while j < times.Length && times.[j] - times.[i] <= oneMinute do
                        j <- j + 1
                    maxSameEdge <- max maxSameEdge (j - i)
                    i <- i + 1

            // Signals — same thresholds and wording as C# BuildSignals.
            let signals = ResizeArray<string>()
            if rows.Length >= SiteFingerprintService.MinConversations then
                let spanMinutes = int (lastUtc - firstUtc).TotalMinutes
                let dispersionBar = max SiteFingerprintService.EdgeDispersionFloor (baselineEdges + 2)
                if edges.Count >= dispersionBar then
                    signals.Add(
                        $"Used {edges.Count} different server addresses in {spanMinutes} minutes " +
                        $"(this machine's other sites typically sit on {baselineEdges}).")
                if burst > 0 && firstBurst.HasValue then
                    let plural = if burst = 1 then "" else "s"
                    let firstAt = firstBurst.Value.ToLocalTime().ToString("HH:mm:ss")
                    signals.Add(
                        $"{burst} burst{plural} of 3+ connections within five seconds (first at {firstAt}) " +
                        "— the shape of a browser retrying after a stall.")
                if maxSameEdge >= 4 then
                    signals.Add(
                        $"Opened {maxSameEdge} connections to one server address within a minute — " +
                        "healthy keep-alive reuses a connection instead of replacing it.")

            { Host = host
              FirstUtc = firstUtc
              LastUtc = lastUtc
              Conversations = rows.Length
              ClientBytes = clientBytes
              Edges = edges
              Processes = processes
              BurstWindows = burst
              FirstBurstUtc = firstBurst
              MaxSameEdgePerMinute = maxSameEdge
              Signals = signals }
