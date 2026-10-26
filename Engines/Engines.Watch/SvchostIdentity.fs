// F# port of Core\Services\SvchostIdentityService.cs (namespace
// AutoScope.Services) plus its dependency, the shared svchost command-line
// parser from Core\SvchostAnalyzer\SvchostIdentity.cs (namespace
// SvchostAnalyzer.Core), for the Engines library.
//
// F# port notes (deviations forced by F#/C# interop, none behavioral):
//   • Engines.Watch does not reference the SvchostAnalyzer CLI project, so
//     the parser is ported INTO this file. It keeps the C# type name
//     (SvchostIdentity) and members (Parse/Mismatches/None) but lives in
//     AutoScope.Engines.Watch — C# callers switch with a one-line rename
//     (SvchostAnalyzer.Core → AutoScope.Engines.Watch).
//   • SvchostPidIdentity's C# PUBLIC FIELDS became properties with the
//     same names (house pattern) — `id.ServicesCsv` reads and object
//     initializers compile unchanged.
//   • The C# record SvchostIdentity became a sealed-style class with a
//     positional constructor; nothing anywhere relies on its value
//     equality, only on Group/DeclaredService reads.

namespace AutoScope.Engines.Watch

open System
open System.Collections.Generic
open System.Management
open System.Text

/// <summary>
/// The identity tokens of a svchost.exe command line. A line like
/// "svchost.exe -k netsvcs -p -s WpnService" means: drawn from the netsvcs
/// service group (-k — a compatibility pool dozens of instances share),
/// launched under per-service isolation (-p), hosting exactly one service
/// (-s — the actual identity). The SCM's PID→service map is the ground
/// truth; -s is self-identification that must corroborate it.
/// F# port of SvchostAnalyzer.Core.SvchostIdentity — see the header note.
/// </summary>
type SvchostIdentity(group: string, declaredService: string) =

    /// <summary>Splits on whitespace outside double quotes (svchost never quotes its flags).
    /// F# port: a let-bound helper (was C#'s private static Tokenize) so
    /// Parse can call it bare.</summary>
    static let tokenize (s: string) : List<string> =
        let tokens = List<string>()
        let sb = StringBuilder()
        let mutable inQuotes = false

        for c in s do
            if c = '"' then
                inQuotes <- not inQuotes
            elif Char.IsWhiteSpace c && not inQuotes then
                if sb.Length > 0 then
                    tokens.Add(sb.ToString())
                    sb.Clear() |> ignore
            else
                sb.Append c |> ignore

        if sb.Length > 0 then tokens.Add(sb.ToString())
        tokens

    /// <summary>-k group ("netsvcs") — null when absent.</summary>
    member _.Group: string = group

    /// <summary>-s self-declared service — null for grouped hosts.</summary>
    member _.DeclaredService: string = declaredService

    static member None: SvchostIdentity = SvchostIdentity(null, null)

    /// <summary>
    /// Extracts -k/-s from a svchost command line. Quoting-aware token
    /// walk; a value that is itself a flag (or end of line) reads as null.
    /// </summary>
    static member Parse(commandLine: string) : SvchostIdentity =
        if String.IsNullOrWhiteSpace commandLine then
            SvchostIdentity.None
        else
            let mutable grp = null
            let mutable declared = null
            let tokens = tokenize commandLine

            let mutable i = 0

            while i < tokens.Count do
                if not (tokens.[i].StartsWith("-")) then
                    ()
                else
                    let value =
                        if i + 1 < tokens.Count && not (tokens.[i + 1].StartsWith("-")) then
                            tokens.[i + 1]
                        else
                            null

                    if tokens.[i].Equals("-k", StringComparison.OrdinalIgnoreCase) then grp <- value
                    elif tokens.[i].Equals("-s", StringComparison.OrdinalIgnoreCase) then declared <- value

                i <- i + 1

            if isNull grp && isNull declared then SvchostIdentity.None
            else SvchostIdentity(grp, declared)

    /// <summary>
    /// True when the command line's -s service is NOT among the SCM-resident
    /// services for the same PID — a genuine isolated svchost always matches;
    /// a mismatch (or an unmatchable claim) is a masquerade signal. Empty
    /// inputs never mismatch: there is nothing to corroborate.
    ///
    /// Per-user services (LPS) instantiate under a suffixed name — the
    /// command line hosts "-s CDPUserSvc" while the SCM registers
    /// "CDPUserSvc_56ec2" — so "template_" prefixed names count as matches.
    /// </summary>
    static member Mismatches(declaredService: string, scmServicesCsv: string) : bool =
        if String.IsNullOrEmpty declaredService || String.IsNullOrEmpty scmServicesCsv then
            false
        else
            let mutable mismatch = true

            for hosted in scmServicesCsv.Split(',') do
                let name = hosted.Trim()

                if name.Length = 0 then ()
                elif
                    name.Equals(declaredService, StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith(declaredService + "_", StringComparison.OrdinalIgnoreCase)
                then
                    mismatch <- false

            mismatch

/// <summary>Resolved svchost identity for one PID: SCM services + -k/-s tokens.
/// F# port: the C# public fields are properties with the same names.</summary>
type SvchostPidIdentity() =
    /// <summary>SCM-resident service names, csv ("WpnService") — the ground truth.</summary>
    member val ServicesCsv: string = null with get, set

    /// <summary>Names + display names + state, one per line, for tooltips.</summary>
    member val ServicesDetail: string = null with get, set

    /// <summary>-k group ("netsvcs") — null when the command line is unreadable.</summary>
    member val Group: string = null with get, set

    /// <summary>-s self-declared service — null for grouped hosts and hidden lines.</summary>
    member val DeclaredService: string = null with get, set

    /// <summary>False when WMI could not read the command line (SYSTEM process, non-elevated).</summary>
    member val CommandLineVisible: bool = false with get, set

    /// <summary>-s claim contradicts the SCM-resident services — masquerade signal.</summary>
    member val Mismatch: bool = false with get, set

    /// <summary>Readable command line without -k — the SCM always passes -k.</summary>
    member val NoK: bool = false with get, set

/// <summary>
/// One-shot svchost identity resolution per PID: the SCM's Win32_Service
/// map (ground truth, readable non-elevated) plus the Win32_Process
/// command line (often hidden for SYSTEM instances — surfaced as such,
/// never guessed). Parsed with the shared tokens (SvchostIdentity above,
/// ported from SvchostAnalyzer.Core) so the CLI, the analyzer and this
/// app agree on what -k/-s mean.
/// F# port: was a C# static class — [<AbstractClass; Sealed>] here;
/// Resolve(pid) keeps its name and shape.
/// </summary>
[<AbstractClass; Sealed>]
type SvchostIdentityService private () =

    // F# port: C# `o["Name"]?.ToString()` — null stays null instead of
    // becoming the string "null".
    static let moProp (mo: ManagementObject) (key: string) : string =
        match mo.[key] with
        | null -> null
        | v -> v.ToString()

    static member Resolve(pid: int) : SvchostPidIdentity =
        let id = SvchostPidIdentity()

        let names = List<string>()
        let details = List<string>()

        try
            use s =
                new ManagementObjectSearcher(
                    sprintf "SELECT Name, DisplayName, State FROM Win32_Service WHERE ProcessId = %d" pid
                )

            for o in s.Get() do
                let mo = o :?> ManagementObject
                let name = moProp mo "Name"

                if not (String.IsNullOrEmpty name) then
                    names.Add name
                    details.Add(sprintf "%s — %s (%s)" name (moProp mo "DisplayName") (moProp mo "State"))
        with _ ->
            // best-effort: SCM map unreadable → no corroboration, no false claim
            ()

        id.ServicesCsv <- String.Join(",", names)
        id.ServicesDetail <- String.Join("\n", details)

        let mutable cmd = null

        try
            use s =
                new ManagementObjectSearcher(
                    sprintf "SELECT CommandLine FROM Win32_Process WHERE ProcessId = %d" pid
                )

            let mutable taken = false

            for o in s.Get() do
                if not taken then
                    // C# reads the FIRST row and breaks — even a null
                    // CommandLine wins over later rows (there is only ever one).
                    taken <- true
                    cmd <- moProp (o :?> ManagementObject) "CommandLine"
        with _ ->
            // best-effort: hidden line is the normal non-elevated case
            ()

        id.CommandLineVisible <- not (String.IsNullOrEmpty cmd)

        let parsed = SvchostIdentity.Parse(cmd)
        id.Group <- parsed.Group
        id.DeclaredService <- parsed.DeclaredService
        id.Mismatch <- SvchostIdentity.Mismatches(id.DeclaredService, id.ServicesCsv)
        id.NoK <- id.CommandLineVisible && isNull parsed.Group
        id
