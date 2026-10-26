namespace AutoScope.Engines.Firewall

open System
open System.Collections.Generic
open System.IO
open System.Reflection
open System.Runtime.InteropServices
open System.Text.Json
open System.Threading.Tasks

/// <summary>
/// COM late-binding helpers for INetFwPolicy2 — F# has no C# `dynamic`, so
/// IDispatch property reads/writes go through Type.InvokeMember (the
/// pre-dynamic interop route; same IDispatch dispatch under the hood).
/// F# port: private per-file copy so this file stays independent of whatever
/// shared COM module Com.fs / Service.fs end up exposing.
/// </summary>
module private BaselineCom =

    let getProp (o: obj) (name: string) : obj =
        o.GetType().InvokeMember(name, BindingFlags.GetProperty, null, o, [||])

    let private setProp (o: obj) (name: string) (value: obj) : unit =
        o.GetType().InvokeMember(name, BindingFlags.SetProperty, null, o, [| value |])
        |> ignore

    let create () : obj =
        let t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
        Activator.CreateInstance(t)

    /// The Rules collection is a plain COM enumerable (INetFwRules).
    let rules (policy: obj) : obj seq =
        Seq.cast<obj> (getProp policy "Rules" :?> System.Collections.IEnumerable)

    /// rule.Grouping ?? "" — null or non-string variants come back as "".
    let groupingOrEmpty (rule: obj) : string =
        match getProp rule "Grouping" with
        | :? string as s -> s
        | _ -> ""

    let isEnabled (rule: obj) : bool = getProp rule "Enabled" :?> bool

    let setEnabled (rule: obj) (value: bool) : unit = setProp rule "Enabled" value

    let name (rule: obj) : string = getProp rule "Name" :?> string

/// <summary>
/// Persisted JSON shape of the baseline file.
/// F# port: was a private nested C# class. It must stay public here: F#
/// compiles members of non-public types with non-public setters, which
/// System.Text.Json reflection silently skips (the file would deserialize
/// as an all-defaults object). Treat as engine-internal plumbing — the JSON
/// format matches the C# BaselineFile byte-for-byte.
/// </summary>
[<AllowNullLiteral>]
type FirewallBaselineFile() =
    member val CapturedAt: DateTime = DateTime.MinValue with get, set
    member val Rules: Dictionary<string, bool> = Dictionary<string, bool>() with get, set

/// <summary>
/// Drift report comparing live firewall state against the captured baseline.
/// F# port: was the nested FirewallBaselineManager.DriftReport — top-level here.
/// </summary>
type DriftReport() =
    /// <summary>Rules the baseline expects disabled but which are now enabled.</summary>
    member val ReEnabled: ResizeArray<string> = ResizeArray<string>() with get
    /// <summary>Rules the baseline expects enabled but which are now disabled.</summary>
    member val UnexpectedlyDisabled: ResizeArray<string> = ResizeArray<string>() with get
    /// <summary>New rules not present in the baseline that are enabled.</summary>
    member val SneakedIn: ResizeArray<Tuple<string, string>> = ResizeArray<Tuple<string, string>>() with get
    member val BaselineCount: int = 0 with get, set
    member val LiveCount: int = 0 with get, set

/// <summary>
/// Whole-firewall baseline: the expected enabled/disabled state of every rule,
/// captured after applying a profile (or manually via Re-baseline). Windows
/// Update and reboots re-enable disabled rules and provision new ones —
/// comparing live state against the baseline detects both.
/// F# port: static → instance, and the hardcoded C:\ProgramData\AutoScope
/// path now routes under the injected dataRoot. Passive by design — the
/// enforcer polls; this class only captures/adopts state.
/// </summary>
type BaselineManager(dataRoot: string) =

    // F# port: was Path.Combine(@"C:\ProgramData\AutoScope", "firewall_baseline.json")
    // (hardcoded) — all persistence now routes under the injected dataRoot.
    let baselinePath = Path.Combine(dataRoot, "firewall_baseline.json")
    let mutable cache: FirewallBaselineFile = Unchecked.defaultof<FirewallBaselineFile>
    let mutable pausedUntilUtc = DateTime.MinValue

    let cachedBaseline () : FirewallBaselineFile =
        match cache with
        | null ->
            try
                if File.Exists(baselinePath) then
                    match JsonSerializer.Deserialize<FirewallBaselineFile>(File.ReadAllText(baselinePath)) with
                    | null -> ()
                    | b -> cache <- b
            with _ -> ()
            cache
        | c -> c

    let saveBaseline (file: FirewallBaselineFile) : unit =
        try
            let dir = Path.GetDirectoryName(baselinePath)
            if not (Directory.Exists(dir)) then Directory.CreateDirectory(dir) |> ignore
            File.WriteAllText(baselinePath, JsonSerializer.Serialize(file, JsonSerializerOptions(WriteIndented = true)))
        with _ -> ()

    let setEnabledState (ruleNames: IEnumerable<string>) (enabled: bool) : int =
        let targets = HashSet<string>(ruleNames, StringComparer.Ordinal)
        let mutable changed = 0
        try
            let fwPolicy = BaselineCom.create ()
            for rule in BaselineCom.rules fwPolicy do
                try
                    if targets.Contains(BaselineCom.name rule) then
                        if BaselineCom.isEnabled rule <> enabled then
                            BaselineCom.setEnabled rule enabled
                            changed <- changed + 1
                with _ -> ()
        with ex ->
            System.Diagnostics.Debug.WriteLine($"FirewallBaseline set-state error: {ex.Message}")
        changed

    member _.HasBaseline: bool =
        match cachedBaseline () with
        | null -> false
        | _ -> true

    // While paused, baseline drift is neither fixed nor alerted — for users who
    // want to edit rules externally (wf.msc / netsh) without being fought. The
    // pause auto-expires; re-baseline afterwards to adopt the new state.
    member _.PausedUntilUtc: DateTime = pausedUntilUtc

    member _.IsPaused: bool = DateTime.UtcNow < pausedUntilUtc

    member _.PauseForMinutes(minutes: int) : unit =
        pausedUntilUtc <- DateTime.UtcNow.AddMinutes(minutes)

    /// <summary>
    /// Adopts a single-rule change made inside the app into the baseline, so the
    /// enforcer enforces the user's intent instead of reverting it.
    /// </summary>
    member _.UpdateRuleState(ruleName: string, enabled: bool) : unit =
        match cachedBaseline () with
        | null -> () // no baseline yet — nothing to adopt into
        | b ->
            b.Rules.[ruleName] <- enabled
            saveBaseline b

    /// <summary>
    /// Adopts a group-wide change made inside the app: every live rule in the
    /// group gets its baseline entry set to the new state.
    /// </summary>
    member _.UpdateGroupStateAsync(group: string, enabled: bool) : Task =
        Task.Run(fun () ->
            match cachedBaseline () with
            | null -> ()
            | b when String.IsNullOrEmpty(group) -> ()
            | b ->
                try
                    let fwPolicy = BaselineCom.create ()
                    for rule in BaselineCom.rules fwPolicy do
                        try
                            let rawGroup = BaselineCom.groupingOrEmpty rule
                            let resolved =
                                if String.IsNullOrEmpty(rawGroup) then ""
                                else FirewallService.ResolveGroupName rawGroup
                            if String.Equals(resolved, group, StringComparison.OrdinalIgnoreCase)
                               || String.Equals(rawGroup, group, StringComparison.OrdinalIgnoreCase) then
                                b.Rules.[BaselineCom.name rule] <- enabled
                        with _ -> ()
                    saveBaseline b
                with ex ->
                    System.Diagnostics.Debug.WriteLine($"FirewallBaseline group-update error: {ex.Message}"))

    member _.BaselineInfo: Nullable<ValueTuple<DateTime, int>> =
        match cachedBaseline () with
        | null -> Nullable<ValueTuple<DateTime, int>>()
        | b ->
            let t: ValueTuple<DateTime, int> = struct (b.CapturedAt, b.Rules.Count)
            Nullable<ValueTuple<DateTime, int>>(t)

    /// F# port: Try-pattern helper for the C# nullable-tuple BaselineInfo —
    /// friendlier than deconstructing `(_, _)?` for callers that branch on it.
    member _.TryGetBaselineInfo([<Out>] capturedAt: byref<DateTime>, [<Out>] count: byref<int>) : bool =
        match cachedBaseline () with
        | null -> false
        | b ->
            capturedAt <- b.CapturedAt
            count <- b.Rules.Count
            true

    /// <summary>
    /// Captures the current enabled/disabled state of every firewall rule as the
    /// expected baseline. Call after applying a profile or arranging rules manually.
    /// </summary>
    member _.CaptureBaselineAsync() : Task<ValueTuple<int, DateTime>> =
        Task.Run(fun () ->
            let rules = Dictionary<string, bool>(StringComparer.Ordinal)
            let fwPolicy = BaselineCom.create ()
            for rule in BaselineCom.rules fwPolicy do
                try
                    rules.[BaselineCom.name rule] <- BaselineCom.isEnabled rule
                with _ -> ()

            let file = FirewallBaselineFile()
            file.CapturedAt <- DateTime.Now
            file.Rules <- rules
            saveBaseline file
            cache <- file
            struct (rules.Count, file.CapturedAt))

    /// <summary>
    /// Compares live rule state against the baseline. Always returns a report;
    /// without a baseline the lists stay empty.
    /// </summary>
    member _.GetDriftAsync() : Task<DriftReport> =
        Task.Run(fun () ->
            let report = DriftReport()
            match cachedBaseline () with
            | null -> report
            | baseline ->
                report.BaselineCount <- baseline.Rules.Count
                try
                    let fwPolicy = BaselineCom.create ()
                    let seen = HashSet<string>(StringComparer.Ordinal)
                    for rule in BaselineCom.rules fwPolicy do
                        try
                            let name = BaselineCom.name rule
                            let enabled = BaselineCom.isEnabled rule
                            if seen.Add(name) then
                                let mutable expected = false
                                if not (baseline.Rules.TryGetValue(name, &expected)) then
                                    if enabled then
                                        let mutable group = ""
                                        try
                                            group <- BaselineCom.groupingOrEmpty rule
                                        with _ -> ()
                                        report.SneakedIn.Add(Tuple.Create(name, group))
                                elif not expected && enabled then
                                    report.ReEnabled.Add(name)
                                elif expected && not enabled then
                                    report.UnexpectedlyDisabled.Add(name)
                        with _ -> ()
                    report.LiveCount <- seen.Count
                with ex ->
                    System.Diagnostics.Debug.WriteLine($"FirewallBaseline drift error: {ex.Message}")
                report)

    /// <summary>Disables the named rules back to their baseline state. Returns how many were flipped.</summary>
    member _.ReDisableAsync(ruleNames: IEnumerable<string>) : Task<int> =
        Task.Run(fun () -> setEnabledState ruleNames false)

    /// <summary>Re-enables the named rules back to their baseline state. Returns how many were flipped.</summary>
    member _.RestoreEnableAsync(ruleNames: IEnumerable<string>) : Task<int> =
        Task.Run(fun () -> setEnabledState ruleNames true)
