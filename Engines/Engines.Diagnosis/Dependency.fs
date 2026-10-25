namespace AutoScope.Engines.Diagnosis

open System
open System.Collections.Generic
open System.IO
open System.Runtime.InteropServices
open AutoScope.Engines.Core

// F# port of Core\Services\DependencyBlockService.cs — the PURE CORE only.
// The live half (AnalyzeLiveAsync, DependencyBlockService.Live.cs) stays C#.
// This is the evidence pass behind the DependencyBlocked verdict: "the
// site's own servers are fine — something the PAGE depends on is on this
// machine's own block list."
//
// Why this exists: Windows Firewall blocks silently in the kernel, and a
// login page whose captcha or asset host is blocked shows a generic error
// while the site's own servers answer perfectly. The decisive evidence
// carries no hostname at all — a blocked connect dies before the TLS
// ClientHello, so it never enters the transmissions archive with an SNI.
// The only record is Sysmon EID 3 joined against the block inventory. This
// pass makes that join visible: it anchors on the archive's page loads
// ("browser X fetched host H at T"), pulls blocked connects from the same
// browser inside ±2 minutes of those loads, and attributes each blocked
// address by what it has served on this machine (recorded SNI history).
//
// Honesty rules, same as every engine: a blocked connect is called causal
// only when it falls inside a visit window; hits outside it are kept as
// context and never drive the verdict; attribution never guesses past
// recorded history.

/// Feed-row shape the core join accepts — decoupled from the live feed's
/// own types (C#: DependencyBlockService.BlockHitLite).
type BlockHitLite =
    { TimeUtc: DateTime
      Image: string
      Pid: int
      DestIp: string
      /// "ip" | "app"
      MatchKind: string }

/// Block-inventory answer shape, same decoupling (C#:
/// DependencyBlockService.BlockInfoLite).
type BlockInfoLite =
    { Class: string
      Created: Nullable<DateTime> }

/// One blocked address's story (C#: DependencyBlockService.Hit).
type Hit =
    { Ip: string
      /// connecting process filename
      Process: string
      Attempts: int
      FirstUtc: DateTime
      LastUtc: DateTime
      /// inventory class, when known
      BlockClass: string
      /// rule provenance, when known
      BlockedSince: Nullable<DateTime>
      /// Hostnames recorded traffic shows this address serving on THIS
      /// machine — attribution, never a guess.
      ServedHosts: ResizeArray<string> }

/// A dependency host whose current DNS answers partly land on the block
/// list (C#: DependencyBlockService.RotationFact). A class, not a record,
/// because MeasureRotation returns null exactly where the C# does — F#
/// records cannot produce a null value.
[<AllowNullLiteral>]
type RotationFact(host: string, blockedAddresses: int, totalAddresses: int) =
    member this.Host = host
    member this.BlockedAddresses = blockedAddresses
    member this.TotalAddresses = totalAddresses

/// The join's output (C#: DependencyBlockService.Report). Immutable record
/// — the C# class exposed mutable public fields, but everything is built
/// once here; consumers only read.
type Report =
    { Host: string
      VisitTimesUtc: ResizeArray<DateTime>
      /// Blocked connects inside a visit window — the causal set.
      InWindow: ResizeArray<Hit>
      /// Same browsers, same lookback, outside every window — context only.
      Nearby: ResizeArray<Hit>
      /// Hosts the visiting browser fetched within seconds of a page load —
      /// the page's recorded dependencies.
      CoVisitedHosts: ResizeArray<string>
      /// Dependency hosts whose current DNS answers partly land on the
      /// block list — the intermittency explanation (filled by the live
      /// half, which stays in C#).
      Rotations: ResizeArray<RotationFact> }

    member this.Any = this.InWindow.Count > 0

module private DepUtil =

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

/// Static entry points for the dependency-block core join (C#:
/// DependencyBlockService's pure methods; the live half keeps its C# name).
[<AbstractClass; Sealed>]
type DependencyAnalysis() =

    /// How close to a recorded page load a blocked connect must fall to
    /// count as part of that visit.
    static member VisitWindowSeconds = 120.0

    /// How close in time (and same PID) another fetched host must be to
    /// count as a dependency of the page being loaded.
    static member CoVisitSeconds = 5.0

    /// Offline core: the whole join over caller-supplied inputs, so the
    /// self-test can prove it against synthetic fixtures. Anchors are page
    /// loads of host inside the archive rows (optionally gated by
    /// anchorSinceUtc); hits are block-feed rows for the same browsers.
    static member Analyze(host: string,
                          rows: IReadOnlyList<TrafficRow>,
                          hits: IReadOnlyList<BlockHitLite>,
                          blockedLookup: Func<string, BlockInfoLite>,
                          // F# port: C# default anchorSinceUtc = null — [Optional]
                          // alone gives C# omission the same null default.
                          [<Optional>] anchorSinceUtc: Nullable<DateTime>) : Report =
        let emptyReport =
            { Host = host
              VisitTimesUtc = ResizeArray<DateTime>()
              InWindow = ResizeArray<Hit>()
              Nearby = ResizeArray<Hit>()
              CoVisitedHosts = ResizeArray<string>()
              Rotations = ResizeArray<RotationFact>() }
        if String.IsNullOrEmpty(host) || isNull (box rows) || rows.Count = 0 then emptyReport
        else
            let siteRows =
                rows
                |> Seq.filter (fun r ->
                    String.Equals(r.Sni, host, StringComparison.OrdinalIgnoreCase) &&
                    (not anchorSinceUtc.HasValue || r.TsUtc >= anchorSinceUtc.Value))
                |> Seq.toList
            if siteRows.IsEmpty then emptyReport // no recorded visit → nothing to anchor on
            else
                let visitTimes =
                    siteRows
                    |> List.map (fun r -> r.TsUtc)
                    |> List.distinct
                    |> List.sort
                    |> ResizeArray<DateTime>

                // The browsers that made those page loads — matched by full
                // image path, with the filename as the portable fallback.
                let visitorImages =
                    HashSet<string>(
                        siteRows
                        |> Seq.filter (fun r -> not (String.IsNullOrEmpty(r.Image)))
                        |> Seq.map (fun r -> r.Image),
                        StringComparer.OrdinalIgnoreCase)
                let visitorStems =
                    HashSet<string>(
                        visitorImages
                        |> Seq.map Path.GetFileName
                        |> Seq.filter (fun n -> not (String.IsNullOrEmpty(n)))
                        |> Seq.map (fun n -> n.ToLowerInvariant()))

                let fromVisitor (h: BlockHitLite) =
                    visitorImages.Contains(h.Image) ||
                    visitorStems.Contains((match Path.GetFileName(h.Image) with null -> "" | f -> f).ToLowerInvariant())

                let inVisitWindow (t: DateTime) =
                    visitTimes
                    |> Seq.exists (fun v -> abs ((t - v).TotalSeconds) <= DependencyAnalysis.VisitWindowSeconds)

                let relevantHits =
                    (if isNull (box hits) then Seq.empty else hits :> seq<_>)
                    |> Seq.filter (fun h ->
                        h.MatchKind = "ip" && not (String.IsNullOrEmpty(h.DestIp)) && fromVisitor h)

                let inWindow = ResizeArray<Hit>()
                let nearby = ResizeArray<Hit>()
                for (destIp, g) in DepUtil.groupByString StringComparer.OrdinalIgnoreCase (fun h -> h.DestIp) relevantHits do
                    // C# OrderByDescending(TimeUtc) is stable; so is F#
                    // List.sortByDescending — equal timestamps keep order.
                    let list = g |> Seq.toList |> List.sortByDescending (fun h -> h.TimeUtc)
                    // F# port: C# info?.Class / info?.Created — an inner
                    // option avoids ever materializing a null BlockInfoLite.
                    let infoOpt =
                        if isNull (box blockedLookup) then None
                        else
                            match blockedLookup.Invoke(destIp) with
                            | info when isNull (box info) -> None
                            | info -> Some info
                    let hit =
                        { Ip = destIp
                          Process = (match Path.GetFileName(list.[0].Image) with null -> list.[0].Image | f -> f)
                          Attempts = list.Length
                          FirstUtc = list |> List.map (fun h -> h.TimeUtc) |> List.min
                          LastUtc = list |> List.map (fun h -> h.TimeUtc) |> List.max
                          BlockClass = (match infoOpt with Some i -> i.Class | None -> null)
                          BlockedSince = (match infoOpt with Some i -> i.Created | None -> Nullable<DateTime>())
                          ServedHosts =
                            rows
                            |> Seq.filter (fun r ->
                                String.Equals(r.RemoteIp, destIp, StringComparison.OrdinalIgnoreCase) &&
                                not (String.IsNullOrEmpty(r.Sni)))
                            |> DepUtil.groupByString StringComparer.OrdinalIgnoreCase (fun r -> r.Sni)
                            |> List.sortByDescending (fun (_, gg) -> gg.Count) // stable, like LINQ
                            |> List.truncate 3
                            |> List.map fst
                            |> ResizeArray<string> }
                    if list |> List.exists (fun h -> inVisitWindow h.TimeUtc) then inWindow.Add(hit)
                    else nearby.Add(hit)

                // C# re-sorts both lists by Attempts descending (stable).
                let inWindowSorted =
                    inWindow |> Seq.toList |> List.sortByDescending (fun h -> h.Attempts) |> ResizeArray<Hit>
                let nearbySorted =
                    nearby |> Seq.toList |> List.sortByDescending (fun h -> h.Attempts) |> ResizeArray<Hit>

                // The page's recorded dependencies: hosts the same browser
                // fetched within seconds of a page load of the site under
                // test.
                let visitorPids =
                    HashSet<int>(siteRows |> Seq.filter (fun r -> r.Pid > 0) |> Seq.map (fun r -> r.Pid))
                let coVisited =
                    rows
                    |> Seq.filter (fun r ->
                        not (String.IsNullOrEmpty(r.Sni)) &&
                        not (String.Equals(r.Sni, host, StringComparison.OrdinalIgnoreCase)) &&
                        r.Pid > 0 && visitorPids.Contains(r.Pid) &&
                        siteRows
                        |> List.exists (fun s ->
                            s.Pid = r.Pid && abs ((s.TsUtc - r.TsUtc).TotalSeconds) <= DependencyAnalysis.CoVisitSeconds))
                    |> DepUtil.groupByString StringComparer.OrdinalIgnoreCase (fun r -> r.Sni)
                    |> List.sortByDescending (fun (_, g) -> g.Count) // stable, like LINQ
                    |> List.truncate 6
                    |> List.map fst
                    |> ResizeArray<string>

                { Host = host
                  VisitTimesUtc = visitTimes
                  InWindow = inWindowSorted
                  Nearby = nearbySorted
                  CoVisitedHosts = coVisited
                  Rotations = ResizeArray<RotationFact>() }

    /// Count how many of a dependency host's current addresses are on the
    /// block list — the "2 of 8 addresses blocked, so it works sometimes"
    /// fact. Pure, so the self-test covers it offline. Returns null (like
    /// the C#) when the host is empty, nothing is blocked, or no lookup is
    /// supplied.
    static member MeasureRotation(depHost: string,
                                  addresses: IEnumerable<string>,
                                  blockedLookup: Func<string, BlockInfoLite>) : RotationFact =
        if String.IsNullOrEmpty(depHost) || isNull (box blockedLookup) then
            null
        else
            // C# Distinct() — default (case-sensitive ordinal) comparer,
            // NOT ignore-case.
            let distinct =
                (if isNull (box addresses) then Seq.empty else addresses)
                |> Seq.distinct
                |> Seq.toList
            if distinct.IsEmpty then null
            else
                let blocked =
                    distinct
                    |> List.filter (fun ip -> not (isNull (box (blockedLookup.Invoke(ip)))))
                    |> List.length
                if blocked > 0 then
                    RotationFact(depHost, blocked, distinct.Length)
                else null
