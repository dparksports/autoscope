namespace AutoScope.Engines.Firewall

open System
open System.Collections.Generic
open System.ComponentModel
open System.Diagnostics
open System.IO
open System.Linq
open System.Net
open System.Text
open System.Threading.Tasks
open AutoScope.Engines.Core

/// <summary>
/// Outcome of a group-wide enable/disable so callers can show what actually
/// happened.
/// F# port: was the nested FirewallService.GroupToggleResult — top-level
/// here; fields became properties.
/// </summary>
type GroupToggleResult() =
    member val GroupName: string = null with get, set
    member val Matched: int = 0 with get, set
    member val Changed: int = 0 with get, set
    member val Failed: int = 0 with get, set
    member val FirstError: string = null with get, set
    member val FailedCompletely: bool = false with get, set
    member val Notes: string = null with get, set

/// <summary>
/// One blocked target (IP or app) in the block-rule inventory.
/// F# port: was the nested FirewallService.BlockedTarget — top-level here;
/// public fields became properties; DateTime? stays Nullable&lt;DateTime&gt;.
/// </summary>
type BlockedTarget() =
    member val Target: string = null with get, set // IP or exe name for display
    member val Kind: string = null with get, set // "ip" | "app"
    member val Key: string = null with get, set // grouping key (ip or lowercased full path)
    member val AppPath: string = null with get, set
    member val Ip: string = null with get, set
    member val Rules: int = 0 with get, set
    member val EnabledRules: int = 0 with get, set
    member val Description: string = "" with get, set
    /// Microsoft/Azure, Akamai, Gcore, Windows component, Application, Unclassified
    member val Class: string = null with get, set
    /// parsed from v2 description; null for legacy rules
    member val Created: Nullable<DateTime> = Nullable<DateTime>() with get, set

/// <summary>Fleet-wide toggle outcome (panic button / restore).</summary>
type FleetToggleResult() =
    member val Matched: int = 0 with get, set
    member val Changed: int = 0 with get, set
    member val SkippedRisky: int = 0 with get, set
    member val FirstError: string = null with get, set

/// <summary>Recent DROP hit from pfirewall.log, aggregated per destination.</summary>
type FirewallLogHit() =
    member val Count: int = 0 with get, set
    member val FirstSeen: DateTime = DateTime() with get, set
    member val LastSeen: DateTime = DateTime() with get, set
    member val Processes: HashSet<string> = HashSet<string>(StringComparer.OrdinalIgnoreCase) with get

/// <summary>
/// One firewall rule for the rules view.
/// F# port of the C# FirewallRuleItem (renamed): INotifyPropertyChanged is
/// kept because the rules DataGrid binds EnabledDisplay/Enabled with
/// classic {Binding} and the view code-behind mutates rule.Enabled in place
/// expecting the row to refresh. No UI/Brush property existed on the C#
/// model, so nothing was dropped.
/// </summary>
type RuleInfo() =

    let propertyChanged =
        Event<PropertyChangedEventHandler, PropertyChangedEventArgs>()

    let mutable enabled = false

    member val Name: string = null with get, set
    member val DisplayName: string = null with get, set
    member val DisplayGroup: string = null with get, set
    member val Direction: string = null with get, set
    member val Action: string = null with get, set
    member val Profile: string = null with get, set
    member val Program: string = null with get, set
    member val Protocol: string = null with get, set
    member val LocalPort: string = null with get, set
    member val RemotePort: string = null with get, set
    member val RemoteAddress: string = null with get, set

    member this.Enabled
        with get () = enabled
        and set value =
            if enabled <> value then
                enabled <- value
                propertyChanged.Trigger(this, PropertyChangedEventArgs("Enabled"))
                propertyChanged.Trigger(this, PropertyChangedEventArgs("EnabledDisplay"))

    member this.EnabledDisplay = if this.Enabled then "Yes" else "No"

    [<CLIEvent>]
    member this.PropertyChanged = propertyChanged.Publish

    interface INotifyPropertyChanged with
        [<CLIEvent>]
        member this.PropertyChanged = propertyChanged.Publish

/// <summary>
/// Native Windows Firewall management via INetFwPolicy2 COM.
/// Replaces all PowerShell Get-NetFirewallRule / Set-NetFirewallRule calls.
/// F# port: strong-typed COM (Com.fs) instead of C# `dynamic` COM — no COM
/// reference DLL needed either way.
/// F# port: the C# static singleton (FirewallService.Instance) is gone —
/// the service takes the app's FirewallNaming record so the same engine
/// serves any app's block-rule naming; no rule prefix or app name lives in
/// this file.
/// </summary>
type FirewallService(naming: FirewallNaming) =

    // C# cached these as constants (NewIpPrefix "AS-BLOCK-IP " etc.); every
    // prefix now routes through the injected naming record instead.

    static let groupNameCache = Dictionary<string, string>(StringComparer.Ordinal)

    let getPolicy () : INetFwPolicy2 = Com.getPolicy2 ()

    // ── naming-driven helpers ────────────────────────────────────────

    static let startsWith (prefix: string) (s: string) =
        s.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)

    static let startsWithAny (prefixes: string list) (s: string) =
        List.exists (fun p -> startsWith p s) prefixes

    static let isIpName (naming: FirewallNaming) (name: string) =
        startsWith naming.OwnIpPrefix name || startsWithAny naming.LegacyIpPrefixes name

    static let isAppName (naming: FirewallNaming) (name: string) =
        startsWith naming.OwnAppPrefix name || startsWithAny naming.LegacyAppPrefixes name

    // F# port: C# branched on explicit per-family prefixes (NewIpPrefix /
    // ImportedIpPrefix / LegacyIpPrefix[0]). FirewallNaming carries the
    // adopted set as one flat list, so adopted rules branch on content: an
    // app block always sets ApplicationName, an IP block never does. Same
    // outcome for every rule that can actually exist.
    static let isIpRule (naming: FirewallNaming) (name: string) (rule: INetFwRule) =
        if isIpName naming name then true
        elif isAppName naming name then false
        else String.IsNullOrEmpty rule.ApplicationName

    /// <summary>
    /// COM's INetFwRule.Grouping returns indirect resource strings (e.g.
    /// "@FirewallAPI.dll,-32752"), not the localized display names
    /// ("Network Discovery") that the profile presets use.
    /// </summary>
    static member ResolveGroupName(grouping: string) : string =
        if String.IsNullOrEmpty grouping || grouping.[0] <> '@' then
            grouping
        else
            lock
                groupNameCache
                (fun () ->
                    match groupNameCache.TryGetValue grouping with
                    | true, cached -> cached
                    | _ ->
                        let mutable resolved = grouping
                        let sb = StringBuilder(512)

                        if
                            Shlwapi.SHLoadIndirectString(grouping, sb, sb.Capacity, IntPtr.Zero) = 0
                            && sb.Length > 0
                        then
                            resolved <- sb.ToString()

                        groupNameCache.[grouping] <- resolved
                        resolved)

    /// <summary>
    /// Case-insensitive group match against both the raw Grouping string
    /// and its resolved display name.
    /// </summary>
    static member private GroupMatches(ruleGrouping: string, targetName: string) : bool =
        if String.IsNullOrEmpty ruleGrouping || String.IsNullOrEmpty targetName then
            false
        elif String.Equals(ruleGrouping, targetName, StringComparison.OrdinalIgnoreCase) then
            true
        else
            String.Equals(
                FirewallService.ResolveGroupName ruleGrouping,
                targetName,
                StringComparison.OrdinalIgnoreCase
            )

    /// <summary>
    /// Load all firewall rules for a given direction using COM API.
    /// direction: 1 = Inbound, 2 = Outbound
    /// </summary>
    member _.LoadRulesAsync(direction: int) : Task<ResizeArray<RuleInfo>> =
        Task.Run(fun () ->
            let results = ResizeArray<RuleInfo>()

            try
                let fwPolicy = getPolicy ()

                for r in Com.enumRules fwPolicy.Rules do
                    try
                        let ruleDir = int r.Direction

                        if ruleDir = direction then
                            let name =
                                match r.Name with
                                | null -> ""
                                | n -> n

                            let grouping =
                                match FirewallService.ResolveGroupName r.Grouping with
                                | null -> ""
                                | g -> g

                            results.Add(
                                RuleInfo(
                                    Name = name,
                                    DisplayName = name,
                                    DisplayGroup = (if String.IsNullOrEmpty grouping then "(Ungrouped)" else grouping),
                                    Direction = (if direction = 1 then "Inbound" else "Outbound"),
                                    Enabled = r.Enabled,
                                    Action = (if int r.Action = 1 then "Allow" else "Block"),
                                    Profile = FirewallService.DecodeProfile r.Profiles,
                                    Program = (match r.ApplicationName with null -> "" | a -> a),
                                    Protocol = FirewallService.DecodeProtocol r.Protocol,
                                    LocalPort = (match r.LocalPorts with null -> "" | l -> l),
                                    RemotePort = (match r.RemotePorts with null -> "" | p -> p),
                                    RemoteAddress = (match r.RemoteAddresses with null -> "" | a -> a)
                                )
                            )
                    with _ ->
                        () // Skip rules that can't be read
            with ex ->
                Debug.WriteLine($"FirewallService.LoadRules Error: {ex.Message}")

            results)

    /// <summary>
    /// Toggle a single rule's enabled state via COM.
    /// </summary>
    member _.ToggleRuleAsync(ruleName: string, enabled: bool) : Task =
        Task.Run(
            Action(fun () ->
                try
                    let fwPolicy = getPolicy ()

                    for r in Com.enumRules fwPolicy.Rules do
                        try
                            if r.Name = ruleName then r.Enabled <- enabled
                        with _ -> ()
                with ex ->
                    Debug.WriteLine($"FirewallService.ToggleRule Error: {ex.Message}")
            )
        )

    /// <summary>
    /// Toggle all rules in a group. Matches the raw Grouping string and its
    /// resolved display name.
    /// </summary>
    member _.ToggleGroupAsync(groupName: string, enabled: bool) : Task<GroupToggleResult> =
        Task.Run(fun () ->
            let result = GroupToggleResult(GroupName = groupName)

            try
                let fwPolicy = getPolicy ()

                for r in Com.enumRules fwPolicy.Rules do
                    let mutable ruleGroup = Unchecked.defaultof<string>
                    let mutable wasEnabled = false
                    let mutable readable = true

                    try
                        ruleGroup <- (match r.Grouping with null -> "" | g -> g)
                        wasEnabled <- r.Enabled
                    with _ ->
                        readable <- false // Rule unreadable — skip as before

                    if readable then
                        let matches =
                            (String.IsNullOrEmpty ruleGroup && groupName = "(Ungrouped)")
                            || FirewallService.GroupMatches(ruleGroup, groupName)

                        if matches then
                            result.Matched <- result.Matched + 1

                            try
                                r.Enabled <- enabled

                                if wasEnabled <> enabled then
                                    result.Changed <- result.Changed + 1
                            with ex ->
                                result.Failed <- result.Failed + 1

                                if isNull result.FirstError then
                                    result.FirstError <- ex.Message
            with ex ->
                result.FailedCompletely <- true
                result.FirstError <- ex.Message

            result
        )

    /// <summary>
    /// Reset the firewall to the Windows default rule set (the COM
    /// equivalent of `netsh advfirewall reset`), then disable every
    /// remaining rule so both all inbound and all outbound traffic is
    /// blocked. Non-default rules — including the app's own v2 blocks — do
    /// not survive the reset.
    /// </summary>
    member _.ResetToDefaultsAndLockdownAsync(progress: IProgress<string>) : Task<GroupToggleResult> =
        Task.Run(fun () ->
            let result = GroupToggleResult(GroupName = "Lockdown (reset to defaults)")

            try
                let fwPolicy = getPolicy ()

                let mutable beforeCount = 0

                try
                    beforeCount <- fwPolicy.Rules.Count
                with _ -> ()

                if not (isNull progress) then progress.Report("Restoring Windows default firewall rules…")

                fwPolicy.RestoreLocalFirewallDefaults()

                let mutable afterCount = 0

                try
                    afterCount <- fwPolicy.Rules.Count
                with _ -> ()

                let removed = max 0 (beforeCount - afterCount)

                if not (isNull progress) then
                    progress.Report("Defaults restored — disabling every inbound and outbound rule…")

                let mutable disabledCount = 0

                for r in Com.enumRules fwPolicy.Rules do
                    let mutable wasEnabled = false
                    let mutable readable = true

                    try
                        wasEnabled <- r.Enabled
                    with _ ->
                        readable <- false // Rule unreadable — skip as before

                    if readable then
                        result.Matched <- result.Matched + 1

                        try
                            r.Enabled <- false

                            if wasEnabled then
                                result.Changed <- result.Changed + 1
                                disabledCount <- disabledCount + 1
                        with ex ->
                            result.Failed <- result.Failed + 1

                            if isNull result.FirstError then
                                result.FirstError <- ex.Message

                result.Notes <-
                    $"Windows default rule set restored ({removed} non-default rule(s) removed); "
                    + $"{disabledCount} rule(s) disabled — all inbound and outbound traffic is now blocked."
            with ex ->
                result.FailedCompletely <- true
                result.FirstError <- ex.Message

            result
        )

    /// <summary>F# port: overload for the C# optional progress = null.</summary>
    member this.ResetToDefaultsAndLockdownAsync() : Task<GroupToggleResult> =
        this.ResetToDefaultsAndLockdownAsync(Unchecked.defaultof<IProgress<string>>)

    /// <summary>
    /// Get summary counts.
    /// F# port: the C# 4-tuple (TotalInbound, EnabledInbound, TotalOutbound,
    /// EnabledOutbound) returns as ValueTuple — element names are not
    /// carried into C#; deconstruct with `var (a, b, c, d) = await …`.
    /// </summary>
    member _.GetSummaryAsync() : Task<struct (int * int * int * int)> =
        Task.Run(fun () ->
            let mutable totalIn = 0
            let mutable enabledIn = 0
            let mutable totalOut = 0
            let mutable enabledOut = 0

            try
                let fwPolicy = getPolicy ()

                for r in Com.enumRules fwPolicy.Rules do
                    try
                        let dir = int r.Direction
                        let en = r.Enabled

                        if dir = 1 then
                            totalIn <- totalIn + 1
                            if en then enabledIn <- enabledIn + 1
                        else
                            totalOut <- totalOut + 1
                            if en then enabledOut <- enabledOut + 1
                    with _ -> ()
            with _ -> ()

            struct (totalIn, enabledIn, totalOut, enabledOut)
        )

    /// <summary>
    /// Check if specific rules match their expected config state (for drift
    /// detection). Returns list of drifted rule names.
    /// </summary>
    member _.CheckDriftAsync(overrides: Dictionary<string, string>) : Task<ResizeArray<string>> =
        Task.Run(fun () ->
            let drifted = ResizeArray<string>()

            if isNull (box overrides) || overrides.Count = 0 then
                drifted
            else
                try
                    let fwPolicy = getPolicy ()

                    for r in Com.enumRules fwPolicy.Rules do
                        try
                            let name = r.Name
                            let mutable expected = Unchecked.defaultof<string>

                            if overrides.TryGetValue(name, &expected) then
                                let actual = r.Enabled
                                let expectedBool = expected = "True"

                                if actual <> expectedBool then
                                    let actualText = if actual then "True" else "False"

                                    drifted.Add($"{name} (Expected: {expected}, Actual: {actualText})")
                        with _ -> ()
                with _ -> ()

                drifted
        )

    /// <summary>
    /// Adds inbound and outbound block rules for a specific application
    /// path. F# port: the hardcoded rule Description now comes from
    /// naming.UserBlockDescription.
    /// </summary>
    member _.AddBlockRuleForAppAsync(appPath: string, ruleName: string) : Task =
        Task.Run(
            Action(fun () ->
                try
                    // Outbound block
                    let ruleOut = Com.newRule ()
                    ruleOut.Action <- FwAction.Block
                    ruleOut.Description <- naming.UserBlockDescription
                    ruleOut.Direction <- FwRuleDirection.Out
                    ruleOut.Enabled <- true
                    ruleOut.InterfaceTypes <- "All"
                    ruleOut.Name <- $"{ruleName} (Outbound Block)"
                    ruleOut.ApplicationName <- appPath

                    // Inbound block
                    let ruleIn = Com.newRule ()
                    ruleIn.Action <- FwAction.Block
                    ruleIn.Description <- naming.UserBlockDescription
                    ruleIn.Direction <- FwRuleDirection.In
                    ruleIn.Enabled <- true
                    ruleIn.InterfaceTypes <- "All"
                    ruleIn.Name <- $"{ruleName} (Inbound Block)"
                    ruleIn.ApplicationName <- appPath

                    let fwPolicy = getPolicy ()
                    fwPolicy.Rules.Add(ruleOut)
                    fwPolicy.Rules.Add(ruleIn)
                with ex ->
                    raise (Exception($"Failed to add firewall rule: {ex.Message}", ex))
            )
        )

    /// <summary>
    /// Adds TCP and UDP block rules (inbound and outbound) for a specific
    /// remote IP address. Legacy 4-rule scheme — creates rules with the
    /// caller-supplied name. Prefer AddIpBlockAsync for new blocks (2-rule
    /// v2 scheme, own-prefix naming).
    /// F# port: the hardcoded rule Description ("&lt;app&gt; Remote IP
    /// Block") now uses naming.UserBlockDescription — a distinct marker can
    /// be added to FirewallNaming if the split matters.
    /// </summary>
    member _.AddBlockRuleForIpAsync(remoteIp: string, ruleName: string) : Task =
        Task.Run(
            Action(fun () ->
                try
                    let fwPolicy = getPolicy ()
                    let directions = [| (FwRuleDirection.Out, "Outbound"); (FwRuleDirection.In, "Inbound") |]
                    let protocols = [| (int FwProtocol.Tcp, "TCP"); (int FwProtocol.Udp, "UDP") |]

                    for (dir, dirName) in directions do
                        for (proto, protoName) in protocols do
                            let rule = Com.newRule ()
                            rule.Action <- FwAction.Block
                            rule.Description <- naming.UserBlockDescription
                            rule.Direction <- dir
                            rule.Enabled <- true
                            rule.InterfaceTypes <- "All"
                            rule.Name <- $"{ruleName} ({protoName} {dirName} Block)"
                            rule.RemoteAddresses <- remoteIp
                            rule.Protocol <- proto
                            fwPolicy.Rules.Add(rule)
                with ex ->
                    raise (Exception($"Failed to add firewall rule: {ex.Message}", ex))
            )
        )

    /// <summary>
    /// Removes the block rules previously created for a remote IP by
    /// AddBlockRuleForIpAsync (matched on the legacy "IP Block - &lt;ip&gt;"
    /// name prefixes) plus the v2 and adopted families.
    /// Returns how many rules were removed.
    /// </summary>
    member this.RemoveBlockRulesForIpAsync(remoteIp: string) : Task<int> =
        Task.Run(fun () ->
            naming.LegacyIpPrefixes
            @ [ naming.OwnIpPrefix ]
            @ naming.AdoptedPrefixes
            |> List.sumBy (fun prefix -> this.RemoveRulesByNamePrefix($"{prefix}{remoteIp} ("))
        )

    /// <summary>
    /// Removes the inbound/outbound block rules previously created for an
    /// application path (matched on the rule name prefixes used by the
    /// monitor views plus the exact ApplicationName). Returns the removal
    /// count.
    /// </summary>
    member _.RemoveBlockRulesForAppAsync(appPath: string) : Task<int> =
        Task.Run(fun () ->
            let mutable removed = 0

            try
                let fwPolicy = getPolicy ()
                let names = ResizeArray<string>()

                for r in Com.enumRules fwPolicy.Rules do
                    try
                        let name =
                            match r.Name with
                            | null -> ""
                            | n -> n

                        let app =
                            match r.ApplicationName with
                            | null -> ""
                            | a -> a

                        if
                            (startsWithAny naming.LegacyAppPrefixes name
                             || startsWith naming.OwnAppPrefix name
                             || List.exists (fun p -> startsWith p name) naming.AdoptedPrefixes)
                            && String.Equals(app, appPath, StringComparison.OrdinalIgnoreCase)
                        then
                            names.Add(name)
                    with _ -> ()

                for name in names do
                    try
                        fwPolicy.Rules.Remove(name) |> ignore
                        removed <- removed + 1
                    with _ -> ()
            with ex ->
                raise (Exception($"Failed to remove firewall rules: {ex.Message}", ex))

            removed
        )

    member private _.RemoveRulesByNamePrefix(namePrefix: string) : int =
        let mutable removed = 0

        try
            let fwPolicy = getPolicy ()
            // Collect matches first — removing while enumerating the COM collection is unreliable
            let names = ResizeArray<string>()

            for r in Com.enumRules fwPolicy.Rules do
                try
                    let name =
                        match r.Name with
                        | null -> ""
                        | n -> n

                    if name.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase) then
                        names.Add(name)
                with _ -> ()

            for name in names do
                try
                    fwPolicy.Rules.Remove(name) |> ignore
                    removed <- removed + 1
                with _ -> ()
        with ex ->
            raise (Exception($"Failed to remove firewall rules: {ex.Message}", ex))

        removed

    // ── managed block fleet ──────────────────────────────────────────
    //
    // v2 block rules are FEWER and SELF-DESCRIBING:
    //   IP:  2 rules (outbound TCP + UDP) — inbound blocks are redundant on
    //        a client; unsolicited inbound is already dropped by the
    //        firewall's stateful defaults.
    //   APP: 1 outbound rule.
    // Names are deterministic ("<own-ip-prefix><ip> (TCP Out)") which makes
    // creation idempotent and lets wf.msc users sort/filter by the app's
    // block prefix. The Description field carries full provenance (process,
    // PID, host, byte counts, UTC time) — that's the audit trail visible in
    // wf.msc.

    /// <summary>
    /// Shared parser: extracts the IP from a v2, adopted or legacy IP-block
    /// rule name. ("<own-ip-prefix>1.2.3.4 (TCP Out)" /
    /// "&lt;legacy ip prefix&gt;1.2.3.4 (…)")
    /// </summary>
    static member private ParseIpTarget(naming: FirewallNaming, name: string) : string =
        let prefix =
            if startsWith naming.OwnIpPrefix name then
                naming.OwnIpPrefix
            else
                match List.tryFind (fun p -> startsWith p name) naming.AdoptedPrefixes with
                | Some p -> p
                | None ->
                    (match naming.LegacyIpPrefixes with
                     | p :: _ -> p
                     | [] -> "")

        let cut = name.IndexOf('(')

        if cut > 0 then
            name.Substring(prefix.Length, cut - prefix.Length).Trim()
        else
            name.Substring(prefix.Length).Trim()

    /// <summary>
    /// A rule is "risky" when its target is Microsoft/CDN infrastructure or
    /// a Windows component — re-enabling those is what re-breaks internet,
    /// updates or notifications after a panic restore.
    /// </summary>
    static member private IsRiskyRule(naming: FirewallNaming, name: string, rule: INetFwRule) : bool =
        try
            if isIpRule naming name rule then
                IpClassification.isMicrosoftInfra (FirewallService.ParseIpTarget(naming, name))
            else
                let app =
                    match rule.ApplicationName with
                    | null -> ""
                    | a -> a

                app.Length > 0
                && app.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase)
        with _ ->
            false

    static member private FindRule(fwPolicy: INetFwPolicy2, name: string) : INetFwRule =
        let mutable found = null

        for r in Com.enumRules fwPolicy.Rules do
            if isNull found then
                try
                    if r.Name = name then found <- r
                with _ -> ()

        found

    static member private IsOurBlock(naming: FirewallNaming, rule: INetFwRule) : bool * string =
        try
            let name =
                match rule.Name with
                | null -> ""
                | n -> n

            if int rule.Action <> 0 then
                false, name // Block only
            else
                (startsWith naming.OwnIpPrefix name
                 || startsWith naming.OwnAppPrefix name
                 || List.exists (fun p -> startsWith p name) naming.AdoptedPrefixes
                 || startsWithAny naming.LegacyIpPrefixes name
                 || startsWithAny naming.LegacyAppPrefixes name),
                name
        with _ ->
            false, null

    /// <summary>
    /// Add a 2-rule (outbound TCP+UDP) idempotent IP block with full
    /// provenance. F# port: returns ValueTuple — deconstruct, element names
    /// are not carried into C#.
    /// </summary>
    member _.AddIpBlockAsync(ip: string, description: string) : Task<struct (int * int)> =
        Task.Run(fun () ->
            try
                let mutable created = 0
                let mutable updated = 0
                let fwPolicy = getPolicy ()

                for (proto, suffix) in [ (FwProtocol.Tcp, "TCP Out"); (FwProtocol.Udp, "UDP Out") ] do
                    let name = $"{naming.OwnIpPrefix}{ip} ({suffix})"
                    let existing = FirewallService.FindRule(fwPolicy, name)

                    if not (isNull existing) then
                        try
                            existing.Description <- description
                            updated <- updated + 1
                        with _ -> ()
                    else
                        let rule = Com.newRule ()
                        rule.Action <- FwAction.Block
                        rule.Direction <- FwRuleDirection.Out
                        rule.Enabled <- true
                        rule.InterfaceTypes <- "All"
                        rule.Name <- name
                        rule.RemoteAddresses <- ip
                        rule.Protocol <- int proto
                        rule.Description <- description
                        fwPolicy.Rules.Add(rule)
                        created <- created + 1

                struct (created, updated)
            with ex ->
                raise (Exception($"Failed to add IP block: {ex.Message}", ex))
        )

    /// <summary>
    /// Add a 1-rule (outbound) idempotent app block with full provenance.
    /// F# port: returns ValueTuple — deconstruct, element names are not
    /// carried into C#.
    /// </summary>
    member _.AddAppBlockAsync(appPath: string, description: string) : Task<struct (int * int)> =
        Task.Run(fun () ->
            try
                let fwPolicy = getPolicy ()
                let name = $"{naming.OwnAppPrefix}{Path.GetFileName(appPath)} (Out)"
                let existing = FirewallService.FindRule(fwPolicy, name)

                if not (isNull existing) then
                    try
                        existing.Description <- description
                    with _ -> ()

                    struct (0, 1)
                else
                    let rule = Com.newRule ()
                    rule.Action <- FwAction.Block
                    rule.Direction <- FwRuleDirection.Out
                    rule.Enabled <- true
                    rule.InterfaceTypes <- "All"
                    rule.Name <- name
                    rule.ApplicationName <- appPath
                    rule.Description <- description
                    fwPolicy.Rules.Add(rule)
                    struct (1, 0)
            with ex ->
                raise (Exception($"Failed to add app block: {ex.Message}", ex))
        )

    /// <summary>
    /// Emergency internet restore / re-enable. With skipRisky=true, rules
    /// targeting Microsoft/CDN infrastructure or Windows components are
    /// left in their current state — that's the "restore everything except
    /// the problematic ones" path after a panic disable.
    /// F# port: renamed from SetAllAutoScopeBlocksEnabledAsync — the C#
    /// name carried an app name; call sites switch to
    /// SetAllBlocksEnabledAsync.
    /// </summary>
    member _.SetAllBlocksEnabledAsync(enabled: bool, skipRisky: bool) : Task<FleetToggleResult> =
        Task.Run(fun () ->
            let result = FleetToggleResult()

            try
                let fwPolicy = getPolicy ()

                for r in Com.enumRules fwPolicy.Rules do
                    let (ours, name) = FirewallService.IsOurBlock(naming, r)

                    if ours then
                        if skipRisky && enabled && FirewallService.IsRiskyRule(naming, name, r) then
                            result.SkippedRisky <- result.SkippedRisky + 1
                        else
                            result.Matched <- result.Matched + 1

                            try
                                let was = r.Enabled
                                r.Enabled <- enabled

                                if was <> enabled then
                                    result.Changed <- result.Changed + 1
                            with ex ->
                                if isNull result.FirstError then result.FirstError <- ex.Message
            with ex ->
                result.FirstError <- ex.Message

            result
        )

    /// <summary>F# port: overload for the C# default skipRisky = false.</summary>
    member this.SetAllBlocksEnabledAsync(enabled: bool) : Task<FleetToggleResult> =
        this.SetAllBlocksEnabledAsync(enabled, false)

    /// <summary>
    /// Per-target (and per-group, via a list) enable/disable — the toggle
    /// behind the Blocks tab. Matching mirrors removal: IP blocks by rule
    /// name prefix (new v2 + legacy), app blocks by name prefix plus exact
    /// ApplicationName. Returns (rules matched, rules actually flipped) as
    /// ValueTuple.
    /// </summary>
    member _.SetTargetsEnabledAsync
        (targets: IEnumerable<struct (string * string)>, enabled: bool)
        : Task<struct (int * int)> =
        Task.Run(fun () ->
            let mutable matched = 0
            let mutable changed = 0

            try
                // F# port: ValueTuple stream is unwrapped to reference tuples
                // so plain destructuring works below.
                let list =
                    targets
                    |> Seq.map (fun (struct (kind, key)) -> kind, key)
                    |> List.ofSeq

                let ipPrefixes = ResizeArray<string>()

                for kind, key in list do
                    if kind = "ip" then
                        ipPrefixes.Add($"{naming.OwnIpPrefix}{key} (")
                        // flat adopted list: an app-prefixed "<app> <ip> (" entry
                        // matches nothing that exists, same as C#'s per-family check
                        for p in naming.AdoptedPrefixes do
                            ipPrefixes.Add($"{p}{key} (")

                        for p in naming.LegacyIpPrefixes do
                            ipPrefixes.Add($"{p}{key} (")

                let appPaths =
                    HashSet<string>(
                        list
                        |> Seq.filter (fun (kind, _) -> kind <> "ip")
                        |> Seq.map (fun (_, key) -> key),
                        StringComparer.OrdinalIgnoreCase
                    )

                let fwPolicy = getPolicy ()

                for r in Com.enumRules fwPolicy.Rules do
                    try
                        let (ours, name) = FirewallService.IsOurBlock(naming, r)

                        if ours then
                            let hit =
                                if isIpRule naming name r then
                                    ipPrefixes.Exists(fun (p: string) ->
                                        name.StartsWith(p, StringComparison.OrdinalIgnoreCase)
                                    )
                                else
                                    let app =
                                        match r.ApplicationName with
                                        | null -> ""
                                        | a -> a

                                    app.Length > 0 && appPaths.Contains app

                            if hit then
                                matched <- matched + 1
                                let was = r.Enabled
                                r.Enabled <- enabled

                                if was <> enabled then
                                    changed <- changed + 1
                    with _ -> () // per-rule best effort
            with _ -> () // caller surfaces the zero-change result

            struct (matched, changed)
        )

    /// <summary>Inventory of all managed block rules, grouped per target, classified.</summary>
    member _.GetBlockedInventoryAsync() : Task<ResizeArray<BlockedTarget>> =
        Task.Run(fun () ->
            let byKey = Dictionary<string, BlockedTarget>(StringComparer.OrdinalIgnoreCase)

            try
                let fwPolicy = getPolicy ()

                for r in Com.enumRules fwPolicy.Rules do
                    let (ours, name) = FirewallService.IsOurBlock(naming, r)

                    if ours then
                        try
                            let desc =
                                match r.Description with
                                | null -> ""
                                | d -> d

                            let enabled = r.Enabled

                            let app =
                                match r.ApplicationName with
                                | null -> ""
                                | a -> a

                            let mutable t = Unchecked.defaultof<BlockedTarget>

                            if isIpRule naming name r then
                                let ip = FirewallService.ParseIpTarget(naming, name)
                                let key = "ip:" + ip

                                if not (byKey.TryGetValue(key, &t)) then
                                    t <-
                                        BlockedTarget(
                                            Kind = "ip",
                                            Key = key,
                                            Ip = ip,
                                            Target = ip,
                                            Class = IpClassification.classify ip
                                        )

                                    byKey.[key] <- t
                            else
                                let path = if not (String.IsNullOrEmpty app) then app else name
                                let key = "app:" + path.ToLowerInvariant()

                                if not (byKey.TryGetValue(key, &t)) then
                                    t <-
                                        BlockedTarget(
                                            Kind = "app",
                                            Key = key,
                                            AppPath = path,
                                            Target = Path.GetFileName(path),
                                            Class =
                                                (if FirewallService.IsWindowsComponent path then
                                                     "Windows component ⚠"
                                                 else
                                                     "Application")
                                        )

                                    byKey.[key] <- t

                            t.Rules <- t.Rules + 1

                            if enabled then t.EnabledRules <- t.EnabledRules + 1

                            if String.IsNullOrEmpty t.Description then t.Description <- desc

                            if not t.Created.HasValue then t.Created <- FirewallService.ParseBlockedTime desc
                        with _ -> ()
            with _ -> ()

            byKey
                .Values.OrderByDescending(fun (t: BlockedTarget) -> t.Class)
                .ThenBy(fun t -> t.Target)
                .ToList()
        )

    /// <summary>
    /// One-click cleanup of ALL legacy-name blocks: IP sets (4 rules) shrink
    /// to the v2 2-rule scheme, app blocks (2 rules) shrink to the v2 single
    /// outbound rule. Lossless — descriptions carry over with a migration
    /// marker, protection unchanged (inbound was covered by stateful
    /// filtering). Safe to run repeatedly; exits fast when nothing legacy
    /// remains. F# port: ValueTuple return; the migration marker text no
    /// longer carries an app name.
    /// </summary>
    member _.ConsolidateLegacyIpBlocksAsync() : Task<struct (int * int * int)> =
        Task.Run(fun () ->
            let mutable targets = 0
            let mutable removed = 0
            let mutable migrated = 0

            try
                let fwPolicy = getPolicy ()
                let legacy = ResizeArray<string * INetFwRule * string>()

                for r in Com.enumRules fwPolicy.Rules do
                    try
                        let name =
                            match r.Name with
                            | null -> ""
                            | n -> n

                        if int r.Action = 0 && startsWithAny naming.LegacyIpPrefixes name then
                            legacy.Add((name, r, FirewallService.ParseIpTarget(naming, name)))
                    with _ -> ()

                // F# port: group keys lowercased — Seq.groupBy has no
                // comparer overload; C# grouped apps OrdinalIgnoreCase.
                for ipGroup in legacy |> Seq.groupBy (fun (_, _, ip) -> ip) do
                    targets <- targets + 1

                    for (name, rule, ip) in snd ipGroup do
                        if name.Contains("Inbound") then
                            try
                                fwPolicy.Rules.Remove(name) |> ignore
                                removed <- removed + 1
                            with _ -> ()
                        else
                            // rewrite under v2 name: copy-create-remove (COM rename is unreliable)
                            try
                                let proto = if name.Contains("UDP") then "UDP" else "TCP"
                                let newName = $"{naming.OwnIpPrefix}{ip} ({proto} Out)"

                                if isNull (FirewallService.FindRule(fwPolicy, newName)) then
                                    let nr = Com.newRule ()
                                    nr.Action <- FwAction.Block
                                    nr.Direction <- FwRuleDirection.Out
                                    nr.Enabled <- true
                                    nr.InterfaceTypes <- "All"
                                    nr.Name <- newName
                                    nr.RemoteAddresses <- ip
                                    nr.Protocol <- (if name.Contains("UDP") then int FwProtocol.Udp else int FwProtocol.Tcp)

                                    nr.Description <-
                                        (match rule.Description with
                                         | null -> ""
                                         | d -> d)
                                        + " [migrated from legacy rule]"

                                    fwPolicy.Rules.Add(nr)

                                fwPolicy.Rules.Remove(name) |> ignore
                                migrated <- migrated + 1
                            with _ -> ()

                // ── legacy app blocks: 2 rules → 1 outbound v2 rule ──
                let legacyApps = ResizeArray<string * INetFwRule * string>()

                for r in Com.enumRules fwPolicy.Rules do
                    try
                        let name =
                            match r.Name with
                            | null -> ""
                            | n -> n

                        let app =
                            match r.ApplicationName with
                            | null -> ""
                            | a -> a

                        if int r.Action = 0 && app.Length > 0 && startsWithAny naming.LegacyAppPrefixes name then
                            legacyApps.Add((name, r, app))
                    with _ -> ()

                for appGroup in legacyApps |> Seq.groupBy (fun (_, _, app) -> app.ToLowerInvariant()) do
                    targets <- targets + 1

                    for (name, rule, app) in snd appGroup do
                        if name.Contains("Inbound") then
                            try
                                fwPolicy.Rules.Remove(name) |> ignore
                                removed <- removed + 1
                            with _ -> ()
                        else
                            try
                                let newName = $"{naming.OwnAppPrefix}{Path.GetFileName(app)} (Out)"

                                if isNull (FirewallService.FindRule(fwPolicy, newName)) then
                                    let nr = Com.newRule ()
                                    nr.Action <- FwAction.Block
                                    nr.Direction <- FwRuleDirection.Out
                                    nr.Enabled <- true
                                    nr.InterfaceTypes <- "All"
                                    nr.Name <- newName
                                    nr.ApplicationName <- app

                                    nr.Description <-
                                        (match rule.Description with
                                         | null -> ""
                                         | d -> d)
                                        + " [migrated from legacy rule]"

                                    fwPolicy.Rules.Add(nr)

                                fwPolicy.Rules.Remove(name) |> ignore
                                migrated <- migrated + 1
                            with _ -> ()
            with _ -> ()

            struct (targets, removed, migrated)
        )

    /// <summary>Count of legacy-name block rules still in the firewall (0 after migration).</summary>
    member _.CountLegacyBlocksAsync() : Task<int> =
        Task.Run(fun () ->
            let mutable count = 0

            try
                let fwPolicy = getPolicy ()

                for r in Com.enumRules fwPolicy.Rules do
                    try
                        if int r.Action = 0 then
                            let name =
                                match r.Name with
                                | null -> ""
                                | n -> n

                            if startsWithAny naming.LegacyIpPrefixes name
                               || startsWithAny naming.LegacyAppPrefixes name then
                                count <- count + 1
                    with _ -> ()
            with _ -> ()

            count
        )

    /// <summary>
    /// Recent DROP hits from the firewall log, per destination IP with
    /// first/last seen and the process paths the log carries. Empty when
    /// drop-logging is off (the default) — the process-attributed live
    /// source is the block-hit feed.
    /// pfirewall.log format: date time DROP proto src sport DST dport size
    /// … info PATH — the trailing token group starting at a "X:\" marker is
    /// the program.
    /// </summary>
    static member GetRecentLogHits(minutes: int) : Dictionary<string, FirewallLogHit> =
        let hits = Dictionary<string, FirewallLogHit>(StringComparer.OrdinalIgnoreCase)

        try
            let log = Environment.SystemDirectory + @"\LogFiles\Firewall\pfirewall.log"

            if File.Exists log then
                let cutoff = DateTime.Now.AddMinutes(float -minutes)

                for line in File.ReadLines(log) do
                    // 2026-10-10  14:22:31  DROP  TCP  src  port  dst  port ...
                    if line.Contains("DROP") then
                        let parts = line.Split([| ' ' |], StringSplitOptions.RemoveEmptyEntries)

                        if parts.Length >= 8 then
                            let mutable ts = DateTime()

                            let mutable dst = Unchecked.defaultof<IPAddress>

                            if
                                DateTime.TryParse(parts.[0] + " " + parts.[1], &ts)
                                && ts >= cutoff
                                && IPAddress.TryParse(parts.[6], &dst)
                            then
                                let h =
                                    match hits.TryGetValue(parts.[6]) with
                                    | true, existing -> existing
                                    | false, _ ->
                                        let n = FirewallLogHit(FirstSeen = ts, LastSeen = ts)
                                        hits.[parts.[6]] <- n
                                        n

                                h.Count <- h.Count + 1

                                if ts < h.FirstSeen then h.FirstSeen <- ts

                                if ts > h.LastSeen then h.LastSeen <- ts

                                for i = 8 to parts.Length - 1 do
                                    if parts.[i].Length > 3 && parts.[i].[1] = ':' && parts.[i].[2] = '\\' then
                                        h.Processes.Add(String.Join(' ', parts |> Seq.skip i)) |> ignore
        with _ -> ()

        hits

    static member FirewallDropLoggingOn() : bool =
        // INetFwPolicy2's per-profile logging settings are parameterized COM
        // properties; detection reads the registry keys netsh/wf.msc write —
        // the documented, stable route (the C# dynamic binder could not
        // dispatch them either).
        let registryOn =
            try
                let mutable on = false
                let mutable key = Unchecked.defaultof<Microsoft.Win32.RegistryKey>

                for profileName in [| "DomainProfile"; "StandardProfile"; "PublicProfile" |] do
                    if not on then
                        key <-
                            Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\"
                                + profileName
                                + @"\Logging"
                            )

                        if not (isNull key) then
                            match key.GetValue("LogDroppedPackets") with
                            | :? int as v when v = 1 -> on <- true
                            | _ -> ()

                        if not (isNull key) then key.Dispose()
                on
            with _ ->
                false

        if registryOn then
            true
        else
            // A leftover file from a past enabled period is NOT evidence logging is
            // on — treating it as such hides the enable button while no rows accrue.
            try
                let log = Environment.SystemDirectory + @"\LogFiles\Firewall\pfirewall.log"

                File.Exists log
                && File.GetLastWriteTime(log) > DateTime.Now.AddDays(-1.0)
            with _ ->
                false

    /// <summary>
    /// One-shot at startup: turn on "log dropped packets" so the firewall
    /// log feed works out of the box. Runs at most once EVER — a marker file
    /// is written either way, so a user who later disables logging is
    /// respected.
    /// F# port: C# wrote the marker under a per-app folder — app names are
    /// not allowed in the engine, so a neutral "FirewallEngine" folder is
    /// used; a host app wanting its own once-semantics should check/write
    /// its own marker instead.
    /// </summary>
    static member EnsureDropLoggingOnce() : unit =
        try
            let marker =
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "FirewallEngine",
                    "drop-log-autoenabled.marker"
                )

            if not (File.Exists marker) then
                let err = if FirewallService.FirewallDropLoggingOn () then null else FirewallService.SetDropLogging true

                Directory.CreateDirectory(Path.GetDirectoryName(marker)) |> ignore

                let suffix = if isNull err then "" else $" (netsh failed: {err})"
                let stamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm")

                File.WriteAllText(marker, $"{stamp} ensured{suffix}")
        with _ -> ()

    /// <summary>
    /// Enable/disable "log dropped packets" on all profiles via the
    /// documented netsh CLI (needs the app's elevated context). Returns null
    /// on success, otherwise the netsh output/error.
    /// </summary>
    static member SetDropLogging(enable: bool) : string =
        try
            let verb = if enable then "enable" else "disable"

            let psi = ProcessStartInfo("netsh", $"advfirewall set allprofiles logging droppedconnections {verb}")

            psi.CreateNoWindow <- true
            psi.UseShellExecute <- false
            psi.RedirectStandardOutput <- true
            psi.RedirectStandardError <- true

            use p = Process.Start(psi)

            let output = (p.StandardOutput.ReadToEnd() + " " + p.StandardError.ReadToEnd()).Trim()

            p.WaitForExit(10000) |> ignore

            if p.ExitCode = 0 then null else $"netsh exit {p.ExitCode}: {output}"
        with ex ->
            ex.Message

    static member private ParseBlockedTime(desc: string) : Nullable<DateTime> =
        // v2 descriptions embed "[blocked 2026-10-10 14:22 UTC]"
        let i = match desc with null -> -1 | d -> d.IndexOf("[blocked ")

        if i < 0 then
            Nullable<DateTime>()
        else
            let s = desc.Substring(i + 9)
            let j = s.IndexOf(']')

            if j > 0 then
                match
                    DateTime.TryParseExact(
                        s.Substring(0, j).Replace(" UTC", ""),
                        "yyyy-MM-dd HH:mm",
                        null,
                        Globalization.DateTimeStyles.AssumeUniversal
                    )
                with
                | true, t -> Nullable(t.ToLocalTime())
                | _ -> Nullable<DateTime>()
            else
                Nullable<DateTime>()

    static member private IsWindowsComponent(path: string) : bool =
        not (String.IsNullOrEmpty path)
        && path.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase)

    static member private DecodeProfile(profiles: int) : string =
        let parts = ResizeArray<string>()
        if (profiles &&& 1) <> 0 then parts.Add("Domain")
        if (profiles &&& 2) <> 0 then parts.Add("Private")
        if (profiles &&& 4) <> 0 then parts.Add("Public")
        if parts.Count > 0 then String.Join(", ", parts) else "All"

    static member private DecodeProtocol(protocol: int) : string =
        match protocol with
        | 6 -> "TCP"
        | 17 -> "UDP"
        | 1 -> "ICMPv4"
        | 58 -> "ICMPv6"
        | 256 -> "Any"
        | _ -> string protocol
