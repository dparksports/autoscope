// F# port of Core\Services\SiteVerdictService.cs (AutoScope.Services →
// AutoScope.Engines.Diagnosis). Faithful by contract: same VerdictKind
// members and values, same rule order, same thresholds, and byte-identical
// headline / next-step / evidence strings (the self-test asserts them).
// C# SiteVerdictService.Decide → SiteVerdict.Decide; the nested C# types
// VerdictKind and Verdict are flattened into this namespace.
namespace AutoScope.Engines.Diagnosis

open System
open System.Runtime.InteropServices

type VerdictKind =
    | Blocked = 0               // nothing reaches the site from this PC
    | DependencyBlocked = 1     // the site answers fine — a host the page depends on is on OUR block list
    | LocalTlsBroken = 2        // every handshake fails, controls included — the PC's stack
    | HandshakeDropping = 3     // servers accept TCP but drop some TLS hellos
    | Steering = 4              // short-TTL DNS roulette across uneven servers
    | FarAway = 5               // handshakes complete but the path is slow
    | Healthy = 6               // no network problem found from here
    | Insufficient = 7          // not enough evidence to say anything

// F# port: a class, not a record — the C# view mutates NextStep and assigns
// indexes into the Evidence list, so Evidence is the same mutable
// System.Collections.Generic.List<string> the C# property exposed, populated
// at construction (Decide builds the evidence before choosing the rule
// outcome); Kind and Headline stay read-only.
type Verdict (kind: VerdictKind, headline: string, nextStep: string,
              evidence: System.Collections.Generic.List<string>) =
    let mutable nextStep = nextStep

    member _.Kind = kind
    /// <summary>One sentence, plain English, the answer first.</summary>
    member _.Headline = headline
    /// <summary>The math, one line per measured fact.</summary>
    member _.Evidence = evidence
    /// <summary>One reversible suggestion; never applied by this engine.</summary>
    member _.NextStep
        with get () = nextStep
        and set (value) = nextStep <- value

    /// <summary>F# port: convenience overload standing in for the C#
    /// `Evidence { get; set; } = new()` initializer — evidence starts
    /// empty.</summary>
    new (kind, headline, nextStep) =
        Verdict (kind, headline, nextStep, System.Collections.Generic.List<string>())

/// <summary>
/// Weighs the passive fingerprint and the active probe report into one
/// plain-English verdict, in the app's voice: a headline the user can
/// act on, the math behind it, one reversible next step — and never a
/// conclusion the evidence doesn't support. Rule order matters: a block
/// outranks everything; a handshake drop outranks steering; "far away"
/// outranks "healthy"; and when nothing fired, the verdict says so
/// honestly instead of inventing one.
///
/// Every rule below maps to a failure observed in the wild, most while
/// diagnosing a real "this site refreshes slowly" report.
/// </summary>
[<AbstractClass; Sealed>]
type SiteVerdict private () =

    // F# port: C# SiteFingerprintService.EdgeDispersionFloor (const 4),
    // inlined so this file does not depend on where the fingerprint
    // engine's F# port exposes the constant. Re-point at the shared
    // constant at integration if it kept the name.
    static let EdgeDispersionFloor = 4

    /// <summary>
    /// Decide from whatever evidence exists. Any input may be null
    /// (passive-only or probe-only runs degrade, never guess).
    /// </summary>
    static member Decide (fingerprint: SiteFingerprint,
                          report: SiteProbeReport,
                          [<Optional; DefaultParameterValue(null)>] dependency: Report) : Verdict =
        // F# port: the C# entry point accepted null for every input; the
        // box-based checks below hold whatever the parallel DTO ports use
        // (F# class or record — both are reference types at runtime).
        let hasFingerprint = not (isNull (box fingerprint))
        let hasReport = not (isNull (box report))
        let hasDependency = not (isNull (box dependency))

        let evidence = ResizeArray<string>()

        // Fingerprint lines are evidence no matter which rule fires.
        if hasFingerprint && fingerprint.LooksStruggling then
            evidence.AddRange(fingerprint.Signals)

        if hasReport then
            evidence.AddRange(SiteVerdict.ExtractProbeEvidence(report))

        if hasDependency then
            evidence.AddRange(SiteVerdict.DependencyEvidence(dependency))

        // F# port: rules return their (kind, headline, next-step) core as
        // an internal tuple so the single Verdict is constructed at the
        // end with its evidence already in hand.
        let outcome : (VerdictKind * string * string) option =
            if hasReport then
                // F# port: the C# `verdict ??= RuleX(...)` cascade in the
                // same priority order, short-circuiting the same way.
                SiteVerdict.RuleBlocked(report)
                |> Option.orElseWith (fun () -> SiteVerdict.RuleLocalTlsBroken(report))
                |> Option.orElseWith (fun () -> SiteVerdict.RuleDependencyBlocked(dependency, report))
                |> Option.orElseWith (fun () -> SiteVerdict.RuleHandshakeDropping(report))
                |> Option.orElseWith (fun () -> SiteVerdict.RuleSteering(report, fingerprint))
                |> Option.orElseWith (fun () -> SiteVerdict.RuleFarAway(report))
                |> Option.orElseWith (fun () -> SiteVerdict.RuleHealthy(report, fingerprint))
            elif hasDependency && dependency.Any then
                // No probe (or it failed to run) — the block-hit join stands
                // on its own recorded evidence.
                SiteVerdict.RuleDependencyBlocked(dependency, Unchecked.defaultof<SiteProbeReport>)
            else
                None

        let kind, headline, nextStep =
            match outcome with
            | Some core -> core
            | None ->
                // Probe-only said nothing conclusive; see what the archive says.
                if hasFingerprint && fingerprint.LooksStruggling then
                    (VerdictKind.Steering,
                     "Recorded traffic shows this site behaving unevenly — bursts and address-hopping — " +
                     "but only the live 60-second check can say why. Run it while the site is being slow.",
                     "Run the check while the page is misbehaving; the verdict is only as good as the moment it measures.")
                else
                    (VerdictKind.Insufficient,
                     "Not enough evidence yet — no recorded conversations for this site and no probe run. " +
                     "Browse the site once, then run the check.",
                     "Visit the site in the browser first so there's traffic to reason about.")

        // F# port: Evidence is populated at construction, so the C#'s
        // last-step fallback list is folded into the list handed to the
        // constructor here.
        let evidence =
            if evidence.Count > 0 then evidence
            else ResizeArray<string>([ "No measurements recorded." ])
        Verdict(kind, headline, nextStep, evidence)

    // ── rules, in priority order ─────────────────────────────────────

    static member private RuleDependencyBlocked (dep: Report, r: SiteProbeReport) : (VerdictKind * string * string) option =
        // The login-failure shape observed in the wild: the site's own
        // servers answer fine, but during the page load the browser's
        // connects to an address the page NEEDS (captcha, assets, APIs)
        // were silently dropped by this machine's own block rules. A
        // local, fixable cause outranks the remote-cause rules below —
        // and it fires only on hits INSIDE a recorded visit window, so
        // it never blames an unrelated block.
        if isNull (box dep) || not dep.Any then
            None
        else
            let hasR = not (isNull (box r))
            // F# port: dep.Host ?? r?.Host ?? "this site" spelled out.
            let host =
                if not (isNull dep.Host) then dep.Host
                elif hasR && not (isNull r.Host) then r.Host
                else "this site"
            let top = Seq.head dep.InWindow
            // F# port: Seq.sumBy is checked arithmetic; the C# Sum is
            // unchecked — they differ only past 2^31 attempts.
            let attempts = dep.InWindow |> Seq.sumBy (fun h -> h.Attempts)
            let attemptWord = if attempts = 1 then "connection attempt" else "connection attempts"
            let addresses = dep.InWindow.Count
            let addrDetail =
                if addresses = 1 then
                    $"{top.Ip} — an address this page depends on"
                else
                    let firstIpsText =
                        String.Join(", ", dep.InWindow |> Seq.map (fun h -> h.Ip) |> Seq.truncate 3 |> Array.ofSeq)
                    $"{addresses} addresses this page depends on ({firstIpsText})"
            // F# port: `when` is an F# keyword; the C# local lives on
            // under the name whenText.
            let whenText =
                if dep.VisitTimesUtc.Count > 0 then
                    (Seq.max dep.VisitTimesUtc).ToLocalTime().ToString("HH:mm")
                else
                    "your visit"
            let served =
                if top.ServedHosts.Count > 0 then
                    let firstServedText = String.Join(", ", top.ServedHosts |> Seq.truncate 2 |> Array.ofSeq)
                    $" — recorded traffic shows it also serving {firstServedText}"
                else
                    ""
            let siteFine =
                if hasR && r.Edges.Count > 0 then
                    $"{host}'s own servers answer fine — but "
                else
                    ""
            Some (VerdictKind.DependencyBlocked,
                  $"{siteFine}at {whenText}, {top.Process} made {attempts} blocked {attemptWord} toward " +
                  $"{addrDetail}{served}. AutoScope's own firewall rules dropped them silently — " +
                  "when a page's dependency is blocked, the page fails oddly (sign-ins show generic errors) " +
                  "while the site itself keeps working.",
                  "Unblock with the button below, then retry what failed — only AutoScope's own rules are " +
                  "removed, fully reversible from the Blocks tab. If a rule was there for a reason, re-block " +
                  "it there and the diagnosis stands as the explanation.")

    /// <summary>Evidence lines from the dependency pass — shown under
    /// "the math" no matter which rule fires.</summary>
    static member private DependencyEvidence (dep: Report) : ResizeArray<string> =
        let lines = ResizeArray<string>()
        for h in dep.InWindow do
            let served =
                if h.ServedHosts.Count > 0 then
                    let firstServedText = String.Join(", ", h.ServedHosts |> Seq.truncate 2 |> Array.ofSeq)
                    $" · served here: {firstServedText}"
                else
                    ""
            let since =
                if h.BlockedSince.HasValue then
                    let sinceText = h.BlockedSince.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                    $" · blocked since {sinceText}"
                else
                    ""
            let firstTime = h.FirstUtc.ToLocalTime().ToString("HH:mm:ss")
            let lastTime = h.LastUtc.ToLocalTime().ToString("HH:mm:ss")
            lines.Add(
                $"{firstTime}–{lastTime}  " +
                $"{h.Process} → {h.Ip}  {h.Attempts} attempt(s) blocked{served}{since}")
        for f in dep.Rotations do
            lines.Add(
                $"{f.Host} currently resolves to {f.TotalAddresses} addresses; " +
                $"{f.BlockedAddresses} of them are blocked here — that rotation is why it comes and goes.")
        if dep.InWindow.Count = 0 && dep.Nearby.Count > 0 then
            let nearbyAttempts = dep.Nearby |> Seq.sumBy (fun h -> h.Attempts)
            lines.Add(
                $"{nearbyAttempts} blocked connect(s) from this site's browsers " +
                "today, none inside a recorded page load — context, not cause.")
        lines

    static member private RuleBlocked (r: SiteProbeReport) : (VerdictKind * string * string) option =
        // DNS answered but every TCP connect failed: packets leave the
        // browser and nothing comes back — the block / sinkhole shape.
        let tcpFailed = ResizeArray(r.Edges |> Seq.filter (fun e -> not e.TcpConnectMs.HasValue))
        if r.Edges.Count > 0 && tcpFailed.Count = r.Edges.Count then
            Some (VerdictKind.Blocked,
                  "Nothing can reach this site from your PC — the server addresses answer DNS but refuse " +
                  "every connection. A block rule may be why.",
                  "Open the Blocks tab and look for these addresses (or press 🚑 Restore Internet — one click, fully reversible).")
        else
            // DNS itself never answered: sinkhole or dead name.
            if (not r.Dns.AnySuccess) && (r.Edges.Count = 0) then
                Some (VerdictKind.Blocked,
                      "This site's name never resolves from your PC — either the name is dead or something local " +
                      "is answering DNS for it (a sinkhole or hosts entry).",
                      "Check the Black Hole tab and the Windows hosts file; both are one-glance checks, and anything you find there is reversible.")
            else
                None

    static member private RuleLocalTlsBroken (r: SiteProbeReport) : (VerdictKind * string * string) option =
        // TCP reaches the site, every handshake fails — and the CONTROL
        // sites fail the same way. Same machine, same stack, same
        // failure everywhere means the local TLS stack, not the site.
        // (Observed in the wild: OS hardening that leaves schannel
        // unable to create ephemeral keys — some apps' TLS still works,
        // which makes it look exactly like "this one site is broken".)
        if r.Controls.Count = 0 || (r.Controls |> Seq.exists (fun c -> c.TlsMs.HasValue)) then
            None
        else
            let tcpOk = ResizeArray(r.Edges |> Seq.filter (fun e -> e.TcpConnectMs.HasValue))
            if tcpOk.Count = 0 ||
               not (tcpOk |> Seq.forall (fun e -> SiteVerdict.Failed(e.TlsDefaultMs) && SiteVerdict.Failed(e.TlsPlainMs))) then
                None
            else
                Some (VerdictKind.LocalTlsBroken,
                      "Every secure handshake fails — including to your control sites, whose servers are known-good. " +
                      "The connection layer on THIS PC is the problem (TLS settings or hardening), not the site.",
                      "Recent OS 'TLS hardening' changes are the usual suspect — if you ran any, undo them and retest. " +
                      "Sites may still load in some browsers (they carry their own TLS), which makes this look like a one-site fault.")

    static member private RuleHandshakeDropping (r: SiteProbeReport) : (VerdictKind * string * string) option =
        // The smoking gun: TCP completes, one hello shape is silently
        // dropped, the other succeeds — on the same address, same minute.
        let splitEdges =
            ResizeArray(r.Edges |> Seq.filter (fun e ->
                e.TcpConnectMs.HasValue &&
                (SiteVerdict.Failed(e.TlsDefaultMs) <> SiteVerdict.Failed(e.TlsPlainMs))))

        if splitEdges.Count > 0 then
            let defaultDropped =
                splitEdges |> Seq.exists (fun e ->
                    SiteVerdict.Failed(e.TlsDefaultMs) && not (SiteVerdict.Failed(e.TlsPlainMs)))
            let shape = if defaultDropped then "the Windows-default handshake" else "the plain handshake"
            Some (VerdictKind.HandshakeDropping,
                  $"This site's servers accept the connection, then silently drop {shape} while accepting the other — " +
                  "a server-side quirk, not your PC. A browser that speaks the dropped flavor stalls for seconds " +
                  "before retrying somewhere else, which is exactly what a slow refresh feels like.",
                  "Report it to the site (their CDN is mishandling some modern TLS hellos). To test from your side: " +
                  "in Chrome, visit chrome://flags/#enable-post-quantum-kyber, set it to Disabled, relaunch — " +
                  "if refreshes snap to fast, the dropped hello was the post-quantum keyshare; the flag is one click to restore.")
        else
            // Weaker form: edges that dropped BOTH shapes after a good TCP.
            // Conclusive on its own from 2+ edges; a single edge needs a
            // healthy control to rule out the local machine.
            let tcpOk = ResizeArray(r.Edges |> Seq.filter (fun e -> e.TcpConnectMs.HasValue))
            let controlHealthy = r.Controls |> Seq.exists (fun c -> c.TlsMs.HasValue)
            if tcpOk.Count >= 1 &&
               (tcpOk |> Seq.forall (fun e -> SiteVerdict.Failed(e.TlsDefaultMs) && SiteVerdict.Failed(e.TlsPlainMs))) &&
               (tcpOk.Count >= 2 || controlHealthy) then
                Some (VerdictKind.HandshakeDropping,
                      "This site's servers accept connections but never answer any secure handshake this app can " +
                      "send — while your control sites answer instantly. The servers are the problem.",
                      "Nothing to fix on your PC. If the site loads in some apps and not others, that difference " +
                      "itself is the report to send the site: their servers are dropping handshakes selectively.")
            else
                None

    static member private RuleSteering (r: SiteProbeReport, fp: SiteFingerprint) : (VerdictKind * string * string) option =
        let rotating = r.Dns.Samples.Count >= 2 && r.Dns.AnswerRotated
        let dispersion =
            (not (isNull (box fp))) && fp.LooksStruggling &&
            fp.Edges.Count >= EdgeDispersionFloor
        if not rotating && not dispersion then
            None
        else
            let dice =
                if rotating then
                    $"DNS handed back a different server set between samples ({r.Dns.DistinctIps.Count} addresses seen across {r.Dns.Samples.Count} looks)"
                else
                    "recorded traffic shows the site hopping across many server addresses"
            Some (VerdictKind.Steering,
                  $"This site rotates its servers constantly — {dice}. Every visit rolls the dice on which server " +
                  "answers, and today some of them are bad ones. Your line is fine (the controls say so).",
                  "Retry usually lands on a healthy server within a few refreshes. It's the site's steering that " +
                  "needs fixing, not your PC — worth reporting to them.")

    static member private RuleFarAway (r: SiteProbeReport) : (VerdictKind * string * string) option =
        let controlMs = SiteVerdict.ControlBaselineMs(r)
        let ok =
            ResizeArray(r.Edges |> Seq.filter (fun e -> e.TlsDefaultMs.HasValue || e.TlsPlainMs.HasValue))
        if ok.Count = 0 then
            None
        else
            // e.TlsDefaultMs ?? e.TlsPlainMs ?? 0 — the ok filter above
            // guarantees at least one of them has a value.
            let worst =
                ok
                |> Seq.map (fun e -> if e.TlsDefaultMs.HasValue then e.TlsDefaultMs.Value
                                     elif e.TlsPlainMs.HasValue then e.TlsPlainMs.Value
                                     else 0.0)
                |> Seq.max
            match controlMs with
            | Some c when worst > 4.0 * c && worst > 150.0 ->
                let worstText = worst.ToString("0")
                let controlText = c.ToString("0")
                Some (VerdictKind.FarAway,
                      $"Handshakes complete but slowly — up to {worstText} ms to this site versus {controlText} ms for " +
                      "your control sites. Parts of this site are served from far away; every request pays the distance.",
                      "Nothing local to fix — distance is physics. A VPN endpoint nearer the site's servers is the " +
                      "only lever that moves this number.")
            | None when worst > 400.0 ->
                let worstText = worst.ToString("0")
                Some (VerdictKind.FarAway,
                      $"Handshakes take up to {worstText} ms — slow even without a control to compare against. " +
                      "The site's servers are answering from far away or under load.",
                      "Nothing local to fix; the distance or the load is the site's, not yours.")
            | _ ->
                None

    static member private RuleHealthy (r: SiteProbeReport, fp: SiteFingerprint) : (VerdictKind * string * string) option =
        let controlMs = SiteVerdict.ControlBaselineMs(r)
        // F# port: Math.Max(controlMs ?? 60, 60) * 2.5.
        let bar = (max (defaultArg controlMs 60.0) 60.0) * 2.5
        let allFast =
            r.Edges.Count > 0 &&
            (r.Edges
             |> Seq.filter (fun e -> e.TcpConnectMs.HasValue)
             |> Seq.forall (fun e ->
                 // e.TlsDefaultMs ?? e.TlsPlainMs ?? int.MaxValue <= bar
                 let tls = if e.TlsDefaultMs.HasValue then e.TlsDefaultMs.Value
                           elif e.TlsPlainMs.HasValue then e.TlsPlainMs.Value
                           else double Int32.MaxValue
                 tls <= bar))
        let struggling = (not (isNull (box fp))) && fp.LooksStruggling
        let calmHistory = not struggling

        if not allFast then
            None
        elif calmHistory then
            Some (VerdictKind.Healthy,
                  "No network problem found from here — connections and handshakes to this site are as fast as " +
                  "your control sites, and its recorded traffic looks calm. The slowness you're seeing is inside " +
                  "the browser or the site's own application.",
                  "Try the page in a private window with extensions off; if it's still slow while this tab says " +
                  "the network is fine, the site's own app is the suspect.")
        else
            Some (VerdictKind.Healthy,
                  "Connections are fast right now, but the recorded traffic shows earlier bursts and address-hopping — " +
                  "the problem comes and goes with which server the dice roll lands on.",
                  "Run the check again the next time it's slow — an intermittent fault has to be caught in the act.")

    // ── helpers ───────────────────────────────────────────────────────

    static member private Failed (ms: Nullable<double>) = not ms.HasValue

    static member private ControlBaselineMs (r: SiteProbeReport) : float option =
        let good = ResizeArray(r.Controls |> Seq.filter (fun c -> c.TlsMs.HasValue))
        if good.Count > 0 then
            Some(good |> Seq.map (fun c -> c.TlsMs.Value) |> Seq.min)
        else
            None

    // F# port: the C# interpolated a null double? as "" (String.Format on
    // a boxed null); spelled out so the control line matches byte-for-byte.
    static member private FormatMs (n: Nullable<double>) =
        if n.HasValue then n.Value.ToString("0") else ""

    static member private ExtractProbeEvidence (r: SiteProbeReport) : ResizeArray<string> =
        let lines = ResizeArray<string>()
        for e in r.Edges do
            let tcp =
                if e.TcpConnectMs.HasValue then
                    let msText = e.TcpConnectMs.Value.ToString("0")
                    $"TCP {msText} ms"
                else
                    $"TCP FAILED ({e.TcpError})"
            let tls = SiteVerdict.Describe(e.TlsDefaultMs, e.TlsDefaultVersion, e.TlsDefaultError, "default")
            let plain = SiteVerdict.Describe(e.TlsPlainMs, e.TlsPlainVersion, e.TlsPlainError, "plain")
            lines.Add($"{e.Ip}: {tcp} · {tls} · {plain}")
        for c in r.Controls do
            if c.TlsMs.HasValue then
                let tcpText = SiteVerdict.FormatMs(c.TcpConnectMs)
                let tlsText = c.TlsMs.Value.ToString("0")
                lines.Add($"control {c.Host}: TCP {tcpText} ms, TLS {tlsText} ms")
            else
                lines.Add($"control {c.Host}: FAILED ({c.Error})")
        lines

    static member private Describe (ms: Nullable<double>, version: string, error: string, shape: string) =
        if ms.HasValue then
            let msText = ms.Value.ToString("0")
            $"{shape} hello → {version} in {msText} ms"
        else
            $"{shape} hello → NO ANSWER ({SiteVerdict.FirstWords(error, 48)})"

    static member private FirstWords (s: string, max: int) =
        if String.IsNullOrEmpty(s) then "timeout"
        elif s.Length <= max then s
        else s.Substring(0, max) + "…"
