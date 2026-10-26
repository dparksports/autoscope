// F# port of Core\Models\SvchostMonitorItem.cs (namespace AutoScope.Models)
// plus two tiny things the row needs that are not on the Watch fsproj list:
// the BlockRuleState enum (lived in SvchostMonitorItem.cs) and the
// IResolvableHost interface (Core\Models\IResolvableHost.cs).
// Behavioral faithfulness is the contract: this row is bound by the app's
// DataGrid, so every property name and every PropertyChanged notification
// must be exact.
//
// F# port notes (deviations forced by F#/C# interop, none behavioral):
//   • ProcessGlossary (Core\Services\ProcessGlossary.cs) is referenced by
//     ProcessToolTip but is NOT in the Watch fsproj list — a public module
//     copy lives at the top of this file (C# callers switch the namespace,
//     e.g. ProcessTraceWindow). It is a static table; nothing feeds it.
//   • `nameof(X)` became string literals (identical strings) — the strings
//     are the wire format the grid binds to; F# nameof of an instance
//     property has no clean spelling.
//   • C# `protected OnPropertyChanged` is a private member here: F# cannot
//     declare protected members and nothing subclasses the row (the C#
//     member was protected only because CallerMemberName setters sit in the
//     same class).
//   • C# private-setter properties (HasExited, TaskName, TaskUser) expose
//     public getters plus private mutators — F# has no asymmetric accessor
//     accessibility. Outside code still cannot set them.
//   • The C# public static FIELDS TxThresholdBytes / TxOnlyGraceSeconds are
//     static get/set properties here — F# cannot initialize a
//     `static val mutable`; assignment call sites compile unchanged.

// FS3211 fires on the [<Optional; DefaultParameterValue(null)>] Nullable
// parameter of Reattribute ("default value does not have the same type")
// — the emitted metadata still marks the parameter IsOptional, which is
// what C# needs to call Reattribute(pid, name, image) with the last
// argument omitted (default(Nullable<DateTime>) = null, the C# default).
// Verified by reflection in the scratch self-test.
#nowarn "3211"

namespace AutoScope.Engines.Watch

open System
open System.ComponentModel
open System.IO
open System.Text

/// <summary>Firewall-block state of one blockable target (remote IP or executable).</summary>
type BlockRuleState =
    | None = 0
    /// enabled block rules match — traffic is denied
    | Active = 1
    /// rules exist but are all disabled (fleet pause) — traffic flows
    | Paused = 2

// F# port of Core\Models\IResolvableHost.cs (namespace AutoScope.Models):
// the seam DnsResolutionService pushes resolved hostnames through, so any
// row model (SvchostMonitorItem, TrafficStat) can be resolved without the
// resolver knowing the concrete type.
type IResolvableHost =
    abstract RemoteIp: string with get
    abstract Hostname: string with get, set

/// <summary>
/// One-line plain-English descriptions for the handful of helper binaries
/// whose names confuse people ("git-remote-what?"). The generic mechanism is
/// the spawn chain — "spawned by git.exe" comes from the Sysmon create-record
/// for every process — so this glossary only seeds the top offenders; unknown
/// names get the parent line alone, which is usually enough to read a row.
/// F# port: C# referenced AutoScope.Services.ProcessGlossary, which is not on
/// the Watch fsproj list — the table lives here so the row stays
/// self-contained; same entries, same out-parameter shape.
/// </summary>
module ProcessGlossary =

    /// <summary>
    /// True with a one-line description when <c>nameOrPath</c> names a
    /// known-confusing helper (file name or full path, any case).
    /// </summary>
    let TryDescribe(nameOrPath: string, description: outref<string>) : bool =
        description <- null
        if String.IsNullOrEmpty nameOrPath then
            false
        else
            match Path.GetFileName(nameOrPath).ToLowerInvariant() with
            | "git-remote-https.exe" ->
                description <- "Git's network helper — spawned by git.exe for every fetch/push over HTTPS"
                true
            | "ssh.exe" ->
                description <- "SSH client — Git-over-SSH, remote shells and tunnels all run through it"
                true
            | "conhost.exe" ->
                description <- "Console host — the terminal window behind every command-line app"
                true
            | "msedgewebview2.exe" ->
                description <- "Embedded browser engine — widgets, Teams views and in-app web content"
                true
            | "runtimebroker.exe" ->
                description <- "Windows activation broker — launches Store apps' sessions on demand"
                true
            | "werfault.exe" ->
                description <- "Windows Error Reporting — the crash handler that fires when something dies"
                true
            | _ -> false

/// <summary>
/// The Process Monitor's live row: one remote IP with its counters, process
/// identity, svchost identity, task attribution and firewall-block state.
/// Bound by the app's DataGrid — property names and change notifications are
/// the wire format and must stay exact.
/// F# port: `as this` class self-identifier — the explicit interface
/// implementations below must reach the class's private mutators, and inside
/// an interface member the member's own self-identifier is interface-typed.
/// </summary>
type SvchostMonitorItem() as this =

    let propertyChanged =
        Event<PropertyChangedEventHandler, PropertyChangedEventArgs>()

    let mutable remoteIp: string = null
    let mutable rxPackets = 0L
    let mutable txPackets = 0L
    let mutable rxBytes = 0L
    let mutable txBytes = 0L
    let mutable lastSeen = DateTime()
    let mutable processName: string = null
    let mutable hostname: string = null
    let mutable taskName: string = null
    let mutable taskUser: string = null
    let mutable hasExited = false
    let mutable parentImage: string = null
    let mutable nameRevealedFrom: string = null
    let mutable nameProbeDone = false

    // svchost identity — "which of the 74 instances is this?"
    let mutable hostedServices: string = null // SCM-resident service names, csv ("WpnService")
    let mutable servicesDetail: string = null // names + display names + state, multi-line, for tooltips
    let mutable svchostGroup: string = null // -k netsvcs
    let mutable declaredService: string = null // -s WpnService
    let mutable identitySuspicious = false // -s/SCM mismatch, or visible cmdline without -k
    let mutable cmdLineHidden = false // svchost row whose command line was unreadable
    let mutable identityResolved = false
    let mutable identityPending = false

    // Firewall-block state — two independent dimensions: the remote IP and
    // the process exe.
    let mutable ipBlock = BlockRuleState.None
    let mutable appBlock = BlockRuleState.None
    let mutable ipBlockNote: string = null // rule Description (provenance), for tooltips
    let mutable appBlockNote: string = null

    // Row creation time (UTC) — the clock the TX-only grace period runs on.
    let firstSeenUtc = DateTime.UtcNow

    static let mutable txThresholdBytes = 1024L
    static let mutable txOnlyGraceSeconds = 30

    member val ProcessId: int = 0 with get, set

    // F# port: let-backed property (not member val) so the IResolvableHost
    // explicit implementation can hand out the same storage — inside an F#
    // interface implementation the self-identifier is typed as the
    // interface, so `this.RemoteIp` there would recurse.
    member _.RemoteIp
        with get (): string = remoteIp
        and set (value: string) = remoteIp <- value

    member val Protocol: string = null with get, set

    /// <summary>
    /// Full executable path as logged by Sysmon (null when unknown). It
    /// identifies the row's process even after that process has exited,
    /// which is when the live name lookup would otherwise come up empty.
    /// </summary>
    member val ImagePath: string = null with get, set

    /// <summary>
    /// When the row's process started (UTC), captured once at row creation.
    /// PIDs are recycled aggressively; this timestamp — with the Sysmon image
    /// path — is the row's stable process identity. Later PID inquiries use
    /// it to tell the row's process from any unrelated process that has
    /// since inherited the number.
    /// </summary>
    member val ProcessStartedUtc: Nullable<DateTime> = Nullable<DateTime>() with get, set

    member this.Hostname
        with get (): string = hostname
        and set (value: string) = this.SetHostname value

    // F# port: setter body in a private mutator — inside an F# interface
    // implementation the self-identifier is typed as the interface, so the
    // IResolvableHost.Hostname setter must not re-enter through
    // `this.Hostname <- v` (recursion); both setters funnel here.
    member private this.SetHostname(value: string) : unit =
        if hostname <> value then
            hostname <- value
            this.OnPropertyChanged("Hostname")
            this.OnPropertyChanged("IsResolved")
            this.OnPropertyChanged("HostnameDisplay")

    /// <summary>True when the hostname has been resolved to a real name (not raw IP / empty).</summary>
    member _.IsResolved: bool =
        not (String.IsNullOrEmpty hostname)
        && hostname <> "Unknown"
        && hostname <> "-"
        && not (Net.IPAddress.TryParse hostname |> fst)

    /// <summary>Friendly display — shows italic '(resolving…)' when not yet resolved.</summary>
    member this.HostnameDisplay: string =
        if this.IsResolved then hostname
        elif String.IsNullOrEmpty hostname then "resolving…"
        else hostname

    member this.ProcessName
        with get (): string = processName
        and set (value: string) =
            processName <- value
            this.OnPropertyChanged("ProcessName")
            this.OnPropertyChanged("ProcessDisplay")

    /// <summary>
    /// Last time traffic was seen for this remote IP — seeded from the
    /// Sysmon event time at row creation (the triggering packets usually
    /// crossed the wire before the row existed), then refreshed by the
    /// sniffer on every matched packet, sent or received.
    /// </summary>
    member this.LastSeen
        with get (): DateTime = lastSeen
        and set (value: DateTime) =
            lastSeen <- value
            this.OnPropertyChanged("LastSeen")
            this.OnPropertyChanged("LastSeenDisplay")
            this.OnPropertyChanged("IsStale")

    /// <summary>True when no traffic has been seen for over five minutes (row dims).</summary>
    member _.IsStale: bool =
        lastSeen <> DateTime()
        && DateTime.UtcNow - lastSeen > TimeSpan.FromMinutes 5.

    /// <summary>
    /// Image of the process that spawned this row's process (from the Sysmon
    /// create-record), when known. The "spawned by git.exe" context is what
    /// makes unfamiliar helper names readable — "git-remote-https.exe" alone
    /// tells a user nothing.
    /// </summary>
    member this.ParentImage
        with get (): string = parentImage
        and set (value: string) =
            parentImage <- value
            this.OnPropertyChanged("ProcessToolTip")
            this.OnPropertyChanged("HasToolTip")

    /// <summary>
    /// True for rows whose name never resolved — candidates for the
    /// archive-backed reveal pass (one attempt per row; the day-file scan is
    /// real disk work and the archive does not grow backwards).
    /// </summary>
    member _.NeedsNameReveal: bool =
        String.IsNullOrEmpty processName && not nameProbeDone

    /// <summary>Claims the row for the one-shot reveal pass; false when already attempted.</summary>
    member _.TryBeginNameProbe() : bool =
        if nameProbeDone then false
        else
            nameProbeDone <- true
            true

    /// <summary>
    /// Overwrites the row's identity with what a Sysmon record (trace or
    /// archive) proved the process really is — closing the loop for rows
    /// named by a recycled PID or never named at all. The previous display
    /// name is kept for the tooltip, so a correction is visible instead of
    /// silent.
    /// </summary>
    member this.RevealIdentity(name: string, imagePath: string, parentImageValue: string) : unit =
        if String.IsNullOrEmpty this.ImagePath && not (String.IsNullOrEmpty imagePath) then
            this.ImagePath <- imagePath

        if String.IsNullOrEmpty parentImage && not (String.IsNullOrEmpty parentImageValue) then
            this.ParentImage <- parentImageValue

        if not (String.IsNullOrEmpty name)
           && not (SvchostMonitorItem.SameProcessName(name, this.ProcessName)) then
            nameRevealedFrom <- this.ProcessName
            this.ProcessName <- Path.GetFileName name

        this.OnPropertyChanged("ProcessToolTip")
        this.OnPropertyChanged("HasToolTip")

    /// <summary>
    /// Name equality that tolerates the app's two name shapes (Sysmon
    /// basenames carry ".exe", live ProcessName lookups do not).
    /// </summary>
    static member private SameProcessName(a: string, b: string) : bool =
        // F# port: C# private static method → static private member; same
        // visibility within the class.
        if String.IsNullOrEmpty a || String.IsNullOrEmpty b then
            String.IsNullOrEmpty a && String.IsNullOrEmpty b
        else
            let fa = Path.GetFileName a
            let fb = Path.GetFileName b
            String.Equals(fa, fb, StringComparison.OrdinalIgnoreCase)
            || String.Equals(
                Path.GetFileNameWithoutExtension fa,
                Path.GetFileNameWithoutExtension fb,
                StringComparison.OrdinalIgnoreCase
            )

    /// <summary>
    /// True once the row's process has been observed to have exited. The row
    /// keeps its history (trace/block still work off the Sysmon image path)
    /// but is labeled so a dead connection stops looking live.
    /// </summary>
    member _.HasExited: bool = hasExited

    // F# port: C# had `private set` on HasExited; F# has no asymmetric
    // accessor accessibility, so the setter body lives in this private
    // mutator (public getter, un-settable from outside — same contract).
    member private this.SetHasExited(value: bool) : unit =
        hasExited <- value
        this.OnPropertyChanged("HasExited")

    /// <summary>Labels the row's process as exited (view's refresh timer, PID snapshot).</summary>
    member this.MarkExited() : unit =
        if not this.HasExited then
            this.SetHasExited true
            this.OnPropertyChanged("ProcessDisplay")

    /// <summary>
    /// Hands the row to a new process after its original one exited and a
    /// different PID connected to the same remote IP, so counters keep
    /// accruing to a live process instead of a ghost PID.
    /// </summary>
    member this.Reattribute(
        processId: int,
        processNameValue: string,
        imagePath: string,
        [<Runtime.InteropServices.Optional;
          Runtime.InteropServices.DefaultParameterValue(null)>]
        processStartedUtc: Nullable<DateTime>
    ) : unit =
        this.ProcessId <- processId
        this.ProcessName <- processNameValue
        if not (String.IsNullOrEmpty imagePath) then this.ImagePath <- imagePath
        this.ProcessStartedUtc <- processStartedUtc

        this.SetTaskName null // the old process's task attribution no longer applies
        this.SetTaskUser null

        // The old tenant's reveal state does not describe the new one
        // either — the newcomer gets its own name-probe pass.
        nameRevealedFrom <- null
        nameProbeDone <- false
        parentImage <- null

        // The old tenant's service identity does not describe the new one
        // either — enrichment re-resolves it for the new process.
        identityResolved <- false
        hostedServices <- null
        servicesDetail <- null
        svchostGroup <- null
        declaredService <- null
        identitySuspicious <- false

        this.SetHasExited false
        this.OnPropertyChanged("ProcessDisplay")
        this.OnPropertyChanged("ProcessToolTip")

    // -------------------------------------------------------------------
    // svchost identity — "which of the 74 instances is this?"
    //
    // svchost.exe is one generic binary; an instance's identity is the
    // SCM's PID→service map (ground truth) corroborated by its command
    // line (-k group · -s single tenant). Resolved asynchronously by
    // SvchostIdentityService once per row.
    // -------------------------------------------------------------------

    /// <summary>True when this row's process is a service host image.</summary>
    member _.IsSvchost: bool =
        String.Equals(processName, "svchost.exe", StringComparison.OrdinalIgnoreCase)

    /// <summary>True while the row is a svchost whose identity has not been resolved yet.</summary>
    member this.NeedsSvchostIdentity: bool =
        this.IsSvchost && not identityResolved && not identityPending

    /// <summary>
    /// Claims the row for identity resolution (one async attempt at a time);
    /// false when resolution is already done or in flight.
    /// </summary>
    member this.TryBeginIdentity() : bool =
        if not this.NeedsSvchostIdentity then
            false
        else
            identityPending <- true
            true

    /// <summary>Releases a failed resolve attempt so the next tick can retry.</summary>
    member _.AbandonIdentity() : unit = identityPending <- false

    /// <summary>
    /// Raw SCM-resident service names csv ("WpnService") — the block record's
    /// identity source; empty before resolution.
    /// </summary>
    member _.HostedServicesCsv: string =
        if isNull hostedServices then "" else hostedServices

    /// <summary>-k service group, when the command line was readable.</summary>
    member _.SvchostGroup: string = svchostGroup

    /// <summary>-s self-declared service, when present.</summary>
    member _.DeclaredService: string = declaredService

    /// <summary>Stamps the resolved svchost identity (SCM services + -k/-s tokens).</summary>
    member this.SetSvchostIdentity(
        hostedServicesCsv: string,
        servicesDetailValue: string,
        group: string,
        declaredServiceValue: string,
        commandLineVisible: bool,
        suspicious: bool
    ) : unit =
        hostedServices <- (if isNull hostedServicesCsv then "" else hostedServicesCsv)
        servicesDetail <- servicesDetailValue
        svchostGroup <- group
        declaredService <- declaredServiceValue
        identitySuspicious <- suspicious
        cmdLineHidden <- not commandLineVisible
        identityResolved <- true
        identityPending <- false
        this.OnPropertyChanged("ProcessDisplay")
        this.OnPropertyChanged("ProcessToolTip")
        this.OnPropertyChanged("IdentityLabel")

    /// <summary>Compact service list for the Process cell: "WpnService", "A+B", "A+2 more".</summary>
    member private _.ServicesCompact: string =
        if String.IsNullOrEmpty hostedServices then "no service"
        else
            let names = hostedServices.Split(',')
            if names.Length = 1 then names.[0]
            elif names.Length = 2 then $"{names.[0]}+{names.[1]}"
            else $"{names.[0]}+{names.Length - 1} more"

    /// <summary>
    /// True once the row's hosted services are known (resolved identity with
    /// at least one SCM service).
    /// </summary>
    member _.HasServiceIdentity: bool =
        String.Equals(processName, "svchost.exe", StringComparison.OrdinalIgnoreCase)
        && identityResolved
        && not (String.IsNullOrEmpty hostedServices)

    /// <summary>
    /// Short identity label for dropdowns and report text: the hosted service
    /// for svchost rows, the image name for everything else.
    /// </summary>
    member this.IdentityLabel: string =
        if this.IsSvchost && identityResolved then this.ServicesCompact
        elif isNull this.ProcessName then "?"
        else this.ProcessName

    /// <summary>
    /// True when the resolved identity carries a masquerade signal — the -s
    /// claim contradicts the SCM, or a readable command line has no -k.
    /// </summary>
    member _.IdentitySuspicious: bool = identitySuspicious

    /// <summary>
    /// Friendly display: "PID (name)", "PID (svchost.exe [WpnService])" for
    /// resolved service hosts (the bracket is what tells the 74 svchost
    /// instances apart), "— exited" once the process is gone.
    /// </summary>
    member this.ProcessDisplay: string =
        // F# port: the suspicion marker hoisted out of the interpolation —
        // string literals inside interpolated holes trip FS3373.
        let suspicion = (if identitySuspicious then " ⚠" else "")

        let text =
            if this.IsSvchost && identityResolved then
                $"{this.ProcessId} (svchost.exe [{this.ServicesCompact}]{suspicion})"
            elif String.IsNullOrEmpty this.ProcessName then
                string this.ProcessId
            else
                $"{this.ProcessId} ({this.ProcessName})"

        if hasExited then $"{text} — exited" else text

    /// <summary>Human-readable last-seen time.</summary>
    member _.LastSeenDisplay: string =
        if lastSeen = DateTime() then "—"
        else
            let age = DateTime.UtcNow - lastSeen

            if age.TotalSeconds < 5. then "just now"
            elif age.TotalSeconds < 60. then $"{int age.TotalSeconds}s ago"
            elif age.TotalMinutes < 60. then $"{int age.TotalMinutes}m ago"
            else lastSeen.ToLocalTime().ToString("HH:mm:ss")

    member this.RxPackets
        with get (): int64 = rxPackets
        and set (value: int64) =
            rxPackets <- value
            this.OnPropertyChanged("RxPackets")

    member this.TxPackets
        with get (): int64 = txPackets
        and set (value: int64) =
            txPackets <- value
            this.OnPropertyChanged("TxPackets")

    member this.RxBytes
        with get (): int64 = rxBytes
        and set (value: int64) =
            rxBytes <- value
            this.OnPropertyChanged("RxBytes")
            this.OnPropertyChanged("RxBytesDisplay")
            this.OnPropertyChanged("IsTxOnly")

    member this.TxBytes
        with get (): int64 = txBytes
        and set (value: int64) =
            txBytes <- value
            this.OnPropertyChanged("TxBytes")
            this.OnPropertyChanged("TxBytesDisplay")
            this.OnPropertyChanged("IsHighTransmitter")
            this.OnPropertyChanged("IsTxOnly")

    /// <summary>
    /// Transmit threshold shared by every row: above it a row counts as a
    /// high transmitter (pinned to the top of the grid, tinted). User-
    /// changeable from the monitor toolbar; default 1 KB.
    /// </summary>
    static member TxThresholdBytes
        with get (): int64 = txThresholdBytes
        and set (value: int64) = txThresholdBytes <- value

    /// <summary>True while this row's transmit volume is at or above the high-transmitter threshold.</summary>
    member _.IsHighTransmitter: bool = txBytes >= txThresholdBytes

    /// <summary>
    /// Row creation time (UTC) — the clock the TX-only grace period runs on.
    /// Deliberately not the process start: counters belong to the remote-IP
    /// row, which can outlive and re-attribute processes.
    /// </summary>
    member _.FirstSeenUtc: DateTime = firstSeenUtc

    /// <summary>
    /// Grace period a row must age through before it can count as a one-way
    /// transmitter. Rows are seeded at 0/0 and Rx only arrives when a reply
    /// packet crosses the sniffer, so every new row is briefly "TX, no RX"
    /// mid-handshake; the gate keeps those from flashing in the TX-only view.
    /// </summary>
    static member TxOnlyGraceSeconds
        with get (): int = txOnlyGraceSeconds
        and set (value: int) = txOnlyGraceSeconds <- value

    /// <summary>
    /// True while the row has transmitted but never received anything back —
    /// the one-way-transmitter pattern (firewall-blocked outbound, dead-end
    /// beacons). Time-gated by the grace period, so it must be re-raised
    /// periodically (RefreshLastSeenDisplay), not only when a counter moves.
    /// </summary>
    member _.IsTxOnly: bool =
        txBytes > 0L
        && rxBytes = 0L
        && (DateTime.UtcNow - firstSeenUtc).TotalSeconds >= float txOnlyGraceSeconds

    member _.RxBytesDisplay: string = SvchostMonitorItem.FormatBytes rxBytes
    member _.TxBytesDisplay: string = SvchostMonitorItem.FormatBytes txBytes

    // -------------------------------------------------------------------
    // Firewall-block state — stamped by the view from the firewall's live
    // inventory (the rules are the source of truth, so agent- and
    // wf.msc-created blocks mark rows just like monitor-created ones).
    // Two independent dimensions: the remote IP and the process exe.
    // -------------------------------------------------------------------

    member _.IpBlockState: BlockRuleState = ipBlock
    member _.ProcessBlockState: BlockRuleState = appBlock

    /// <summary>IP cell marker: red + strikethrough when an enabled block rule matches.</summary>
    member _.IsIpBlocked: bool = ipBlock = BlockRuleState.Active

    /// <summary>Process cell marker: red + strikethrough when an enabled app rule matches.</summary>
    member _.IsProcessBlocked: bool = appBlock = BlockRuleState.Active

    /// <summary>True when either dimension blocks this row's traffic.</summary>
    member _.IsTrafficBlocked: bool =
        ipBlock = BlockRuleState.Active || appBlock = BlockRuleState.Active

    /// <summary>True when block rules exist but are all disabled (fleet pause) — traffic flows.</summary>
    member _.HasPausedBlock: bool =
        not (ipBlock = BlockRuleState.Active || appBlock = BlockRuleState.Active)
        && (ipBlock = BlockRuleState.Paused || appBlock = BlockRuleState.Paused)

    /// <summary>Status-column glyph: ⛔ blocked · ⏸ paused · empty = allowed.</summary>
    member this.StatusGlyph: string =
        if this.IsTrafficBlocked then "⛔"
        elif this.HasPausedBlock then "⏸"
        else ""

    /// <summary>Provenance of the IP block rule (null when the IP is not blocked).</summary>
    member _.IpBlockToolTip: string =
        // F# port: the C# ternary chain + string concatenation written as
        // one if/elif; same three shapes, same trailing lines.
        if ipBlock = BlockRuleState.None then
            null
        else
            let head =
                if ipBlock = BlockRuleState.Active then
                    "⛔ Remote IP is blocked — outbound TCP/UDP rules active"
                else
                    "⏸ Block rules for this IP exist but are disabled (traffic flows) — re-enable from 'Blocked' → Manage all"

            head
            + (if String.IsNullOrEmpty ipBlockNote then "" else $"\n{ipBlockNote}")
            + "\nUndo: right-click the row → Unblock, or 'Blocked' → Manage all."

    /// <summary>Provenance of the app block rule (null when the process is not blocked).</summary>
    member _.ProcessBlockToolTip: string =
        if appBlock = BlockRuleState.None then
            null
        else
            let head =
                if appBlock = BlockRuleState.Active then
                    "⛔ This executable is blocked — outbound rule active"
                else
                    "⏸ A block rule for this executable exists but is disabled (traffic flows) — re-enable from 'Blocked' → Manage all"

            head
            + (if String.IsNullOrEmpty appBlockNote then "" else $"\n{appBlockNote}")
            + "\nUndo: right-click the row → Unblock, or 'Blocked' → Manage all."

    /// <summary>Status-column tooltip: whichever dimension is blocked, with provenance.</summary>
    member this.StatusToolTip: string =
        if not this.IsTrafficBlocked && not this.HasPausedBlock then
            null
        else
            let sb = StringBuilder()

            if ipBlock <> BlockRuleState.None then
                let ip = this.IpBlockToolTip
                if not (isNull ip) then sb.AppendLine(ip.TrimEnd()) |> ignore

            if appBlock <> BlockRuleState.None then
                let app = this.ProcessBlockToolTip
                if not (isNull app) then sb.AppendLine(app.TrimEnd()) |> ignore

            if sb.Length = 0 then null else sb.ToString()

    /// <summary>Stamped by the view's blocked-state sync (see RefreshBlockStateFromFirewallAsync).</summary>
    member this.SetBlockState(ip: BlockRuleState, ipNote: string, app: BlockRuleState, appNote: string) : unit =
        ipBlock <- ip
        appBlock <- app
        ipBlockNote <- ipNote
        appBlockNote <- appNote
        this.OnPropertyChanged("IpBlockState")
        this.OnPropertyChanged("ProcessBlockState")
        this.OnPropertyChanged("IsIpBlocked")
        this.OnPropertyChanged("IsProcessBlocked")
        this.OnPropertyChanged("IsTrafficBlocked")
        this.OnPropertyChanged("HasPausedBlock")
        this.OnPropertyChanged("StatusGlyph")
        this.OnPropertyChanged("IpBlockToolTip")
        this.OnPropertyChanged("ProcessBlockToolTip")
        this.OnPropertyChanged("StatusToolTip")

    // F# port: TaskName/TaskUser had `private set` in C#; F# has no
    // asymmetric accessor accessibility — public getters plus private
    // mutators that carry the original setter bodies (the INPC raises).
    /// <summary>
    /// Scheduled task that launched this taskhostw instance (attribution from
    /// TaskSchedulerService), or null when the row is not a task host.
    /// </summary>
    member _.TaskName: string = taskName

    member private this.SetTaskName(value: string) : unit =
        taskName <- value
        this.OnPropertyChanged("TaskName")
        this.OnPropertyChanged("ProcessToolTip")

    /// <summary>Account the scheduled task ran as, when known.</summary>
    member _.TaskUser: string = taskUser

    member private this.SetTaskUser(value: string) : unit =
        taskUser <- value
        this.OnPropertyChanged("TaskUser")
        this.OnPropertyChanged("ProcessToolTip")

    /// <summary>Called by the view when TaskSchedulerService resolves the task behind a taskhostw row.</summary>
    member this.SetTaskInfo(taskNameValue: string, taskUserValue: string) : unit =
        // F# port: `if (TaskName != null) return;` → early guard; the C#
        // private setters now route through the mutators above.
        if isNull this.TaskName then
            this.SetTaskName taskNameValue
            this.SetTaskUser taskUserValue

    /// <summary>True when the Process tooltip has any content to show.</summary>
    member this.HasToolTip: bool =
        not (String.IsNullOrEmpty this.ImagePath)
        || not (isNull this.TaskName)
        || (this.IsSvchost && identityResolved)
        || not (String.IsNullOrEmpty parentImage)
        || not (isNull nameRevealedFrom)

    /// <summary>
    /// Tooltip for the Process column: image path, spawn parent and
    /// plain-English gloss (the "it was Git all along" context),
    /// scheduled-task attribution, and — for resolved svchost rows — the
    /// full service identity (SCM ground truth, -k group, -s claim,
    /// corroboration).
    /// </summary>
    member this.ProcessToolTip: string =
        let sb = StringBuilder()

        if not (String.IsNullOrEmpty this.ImagePath) then
            sb.AppendLine this.ImagePath |> ignore

        if not (String.IsNullOrEmpty parentImage)
           && not (SvchostMonitorItem.SameProcessName(parentImage, this.ProcessName)) then
            sb.AppendLine("spawned by " + Path.GetFileName parentImage) |> ignore

        let mutable gloss: string = null

        if
            ProcessGlossary.TryDescribe(
                (if not (String.IsNullOrEmpty this.ImagePath) then this.ImagePath else this.ProcessName),
                &gloss
            )
        then
            sb.AppendLine("ℹ " + gloss) |> ignore

        if not (isNull nameRevealedFrom) then
            sb.AppendLine $"🏷 real name revealed from the Sysmon record (row previously showed '{nameRevealedFrom}')"
            |> ignore

        if not (isNull this.TaskName) then
            sb.Append("Task: ").Append this.TaskName |> ignore

            if not (String.IsNullOrEmpty this.TaskUser) then
                sb.Append("   (as ").Append this.TaskUser |> ignore
                sb.Append ')' |> ignore

            sb.AppendLine() |> ignore

        if this.IsSvchost && identityResolved then
            sb.AppendLine "svchost identity:" |> ignore

            if not (String.IsNullOrEmpty servicesDetail) then
                sb.AppendLine servicesDetail |> ignore

            sb.Append("group (-k): ")
              .Append(if String.IsNullOrEmpty svchostGroup then "—" else svchostGroup)
              .Append(" · self-declared (-s): ")
              .Append(if String.IsNullOrEmpty declaredService then "—" else declaredService)
            |> ignore

            if identitySuspicious then sb.AppendLine "   ⚠ identity signal — see below" |> ignore
            else sb.AppendLine() |> ignore

            if String.IsNullOrEmpty hostedServices then
                sb.Append "⚠ no service resolves to this PID — the strongest single masquerade red flag"
                |> ignore
            elif identitySuspicious then
                sb.Append "⚠ command line contradicts the SCM-resident services — masquerade signal (audit-svchost.ps1)"
                |> ignore
            elif cmdLineHidden then
                sb.Append "command line hidden (standard user cannot read SYSTEM svchost lines) — rerun elevated to corroborate -k/-s"
                |> ignore
            else
                sb.Append "command line corroborates the SCM ✓" |> ignore

        let text = sb.ToString()
        if text.Length = 0 then null else text

    [<CLIEvent>]
    member this.PropertyChanged = propertyChanged.Publish

    /// <summary>
    /// Called by the UI refresh timer to re-evaluate the relative "Xs ago"
    /// text, the staleness flag, and the time-gated TX-only flag without
    /// needing to mutate LastSeen itself.
    /// </summary>
    member this.RefreshLastSeenDisplay() : unit =
        this.OnPropertyChanged("LastSeenDisplay")
        this.OnPropertyChanged("IsStale")
        this.OnPropertyChanged("IsTxOnly")

    // F# port: C# `protected OnPropertyChanged([CallerMemberName] string name = null)`
    // — private raise helper with an explicit name (F# cannot declare
    // protected members and does not flow CallerMemberName the way C#
    // setters here are written).
    member private this.OnPropertyChanged(name: string) : unit =
        propertyChanged.Trigger(this, PropertyChangedEventArgs name)

    static member private FormatBytes(bytes: int64) : string =
        if bytes < 1024L then $"%d{bytes} B"
        elif bytes < 1048576L then $"{float bytes / 1024.0:F1} KB"
        else $"{float bytes / 1048576.0:F1} MB"

    interface IResolvableHost with
        member _.RemoteIp = remoteIp

        member _.Hostname
            with get () = this.Hostname
            and set (value) = this.SetHostname value

    interface INotifyPropertyChanged with
        [<CLIEvent>]
        member this.PropertyChanged = propertyChanged.Publish

/// <summary>
/// One python/task process creation, as recorded by Sysmon EID 1 (with full
/// parentage) and closed out by EID 5 (Exited). Pairs of spawns coming from
/// a venv launcher collapse into a single row. Ported from the C# app model;
/// the two Visibility props (UI types) were dropped — no engine consumer.
/// </summary>
[<AllowNullLiteral>]
type SpawnItem() as this =
    let propChanged = Event<System.ComponentModel.PropertyChangedEventHandler, System.ComponentModel.PropertyChangedEventArgs>()

    let mutable exited_ = false
    let mutable flowCount_ = 0
    let mutable hasTrace_ = false
    let mutable outcome_ = null
    let mutable verdict_ = null
    let mutable venvLauncher_ = null
    let mutable isAbsorbedLauncher_ = false
    let mutable hasPythonParent_ = false
    let mutable detailBadge_ = null

    member val TimeUtc = System.DateTime() with get, set
    member val Pid = 0 with get, set
    /// <summary>Sysmon's ProcessGuid (braces stripped) — kernel-assigned and
    /// unique for the whole boot; safer than the PID for attribution.</summary>
    member val ProcessGuid: string = null with get, set
    member val Image: string = null with get, set
    member val CommandLine: string = null with get, set
    member val ParentPid = 0 with get, set
    member val ParentImage: string = null with get, set
    member val ParentCommandLine: string = null with get, set
    member val User: string = null with get, set
    member val IntegrityLevel: string = null with get, set
    member val Hashes: string = null with get, set
    member val Source: string = null with get, set

    /// <summary>The venv launcher row this spawn was paired with; null when
    /// the spawn has no launcher in front of it.</summary>
    member this.VenvLauncher = venvLauncher_
    member this.IsAbsorbedLauncher = isAbsorbedLauncher_
    member this.HasPythonParent = hasPythonParent_

    member this.MarkAbsorbedLauncher() =
        isAbsorbedLauncher_ <- true
        this.OnPropertyChanged("Badge")

    member this.SetVenvLauncher(launcher: SpawnItem) =
        venvLauncher_ <- launcher
        this.OnPropertyChanged("Badge")

    member this.SetPythonParent() =
        hasPythonParent_ <- true
        this.OnPropertyChanged("Badge")

    /// <summary>View-set badge; python badges take precedence when present.</summary>
    member this.SetDetailBadge(badge: string) =
        detailBadge_ <- badge
        this.OnPropertyChanged("Badge")

    /// <summary>Grid badge: "venv" for a paired interpreter, "py→py" for python-spawned-python.</summary>
    member this.Badge =
        if not (isNull venvLauncher_) then "venv"
        elif hasPythonParent_ then "py→py"
        else if isNull detailBadge_ then "" else detailBadge_

    member this.SetOutcome(outcome: string) =
        outcome_ <- outcome
        this.OnPropertyChanged("OutcomeDisplay")

    /// <summary>View-set verdict from TaskLaunchInfo — Inbox / Third-party / Orphaned.</summary>
    member this.SetVerdict(verdict: string) =
        verdict_ <- verdict
        this.OnPropertyChanged("Verdict")
        this.OnPropertyChanged("VerdictBackground")
        this.OnPropertyChanged("VerdictForeground")

    member this.Exited
        with get() = exited_
        and set v = exited_ <- v; this.OnPropertyChanged("Exited"); this.OnPropertyChanged("LifeDisplay")

    member this.FlowCount
        with get() = flowCount_
        and set v = flowCount_ <- v; this.OnPropertyChanged("FlowCount")

    member this.HasTrace
        with get() = hasTrace_
        and set v = hasTrace_ <- v; this.OnPropertyChanged("HasTrace")

    member this.TimeDisplay = if this.TimeUtc = System.DateTime() then "—" else this.TimeUtc.ToLocalTime().ToString("HH:mm:ss")
    member this.ImageDisplay = if System.String.IsNullOrEmpty(this.Image) then "—" else System.IO.Path.GetFileName(this.Image)
    member this.LifeDisplay = if exited_ then "exited" else "running"
    member this.OutcomeDisplay = if isNull outcome_ then (if exited_ then "exited" else "running") else outcome_
    member this.Verdict = verdict_

    /// <summary>Chip background per verdict (color string; the view converts).</summary>
    member this.VerdictBackground =
        match verdict_ with
        | "Inbox" -> "#2E5E3E"
        | "Third-party" -> "#6B4E1A"
        | "Orphaned" -> "#6E2A2A"
        | _ -> "#2A2A33"

    /// <summary>Chip text per verdict, matched to its background.</summary>
    member this.VerdictForeground =
        match verdict_ with
        | "Inbox" -> "#7ED8A0"
        | "Orphaned" -> "#F2A0B4"
        | _ -> "#E5C77B"

    /// <summary>"PID (name)" for the parent column; "—" when no parent image.</summary>
    member this.ParentDisplay =
        if System.String.IsNullOrEmpty(this.ParentImage) then
            (if this.ParentPid > 0 then string this.ParentPid else "—")
        else $"{this.ParentPid} ({System.IO.Path.GetFileName(this.ParentImage)})"

    /// <summary>Full parent image + command line for the column tooltip.</summary>
    member this.ParentToolTip =
        if System.String.IsNullOrEmpty(this.ParentImage) && System.String.IsNullOrEmpty(this.ParentCommandLine) then null
        else
            let img = (if isNull this.ParentImage then "?" else this.ParentImage)
            let cmd = (if isNull this.ParentCommandLine then System.String.Empty else this.ParentCommandLine)
            img + System.Environment.NewLine + cmd

    /// <summary>Chip background for the badge column (venv pairs get the accent blue).</summary>
    member this.BadgeBackground = if not (isNull venvLauncher_) then "#1A4A8A" else "#2A2A33"

    member private this.OnPropertyChanged(name: string) =
        propChanged.Trigger(this, PropertyChangedEventArgs(name))

    interface System.ComponentModel.INotifyPropertyChanged with
        [<CLIEvent>]
        member this.PropertyChanged = propChanged.Publish
