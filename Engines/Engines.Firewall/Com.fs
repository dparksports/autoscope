namespace AutoScope.Engines.Firewall

open System
open System.Collections
open System.Runtime.InteropServices
open System.Text

/// <summary>
/// Strong-typed COM interop for the Windows Firewall (INetFwPolicy2 family),
/// replacing the C# `dynamic` COM calls — F# has no dynamic, so the members
/// the C# touched are declared as ComImport interfaces with the exact vtable
/// order of netfw.idl.
/// </summary>
///
/// IID NOTE (verified live 2026-10-25 on this machine, Win11 build 26300):
/// the firewall COM objects answer QueryInterface with the IIDs published in
/// the Windows SDK netfw.idl / netfw.h —
///   INetFwPolicy2 {98325047-C671-4174-8D81-DEFCD3F03186}
///   INetFwRule    {AF230D27-BABA-4E42-ACED-F524F22CFCE2}
///   INetFwRules   {9C4C6277-5027-441E-AFAE-CA1F542DA009}
/// (all three registered under HKCR\Interface with typelib
/// {58FBCF7C-E7A9-467C-80B3-FC65E8FCCA08}). The IIDs that circulate in older
/// hand-rolled C# interop snippets (...-DACD38CE1C54 / AF230D26-... /
/// ...-0623-4F28-85B2-...) are NOT registered here and QI returns
/// E_NOINTERFACE for them. To be safe on older builds as well, both GUID
/// sets are declared: the Native set is tried first, the Legacy set is the
/// fallback, and a small shim presents one face to the service either way.

/// COM NET_FW_ACTION (netfw.idl).
type FwAction =
    | Block = 0
    | Allow = 1

/// COM NET_FW_RULE_DIRECTION (netfw.idl).
type FwRuleDirection =
    | In = 1
    | Out = 2

/// COM NET_FW_IP_PROTOCOL values the engine writes (netfw.idl).
type FwProtocol =
    | Tcp = 6
    | Udp = 17

/// COM NET_FW_PROFILE_TYPE2 — used to index the parameterized profile
/// properties on INetFwPolicy2. (The Profiles bitmask on a rule is a
/// different thing: Domain=1, Private=2, Public=4 — handled as raw int.)
type FwProfile =
    | Domain = 0
    | Private = 1
    | Public = 2
    | All = 0x7FF

// ── Internal ComImport declarations ─────────────────────────────────────
//
// Member order is vtable order (verified against the Windows SDK netfw.idl
// and the win32metadata bindings); ComImport slot mapping follows
// declaration order, so placeholders must stay even for members the engine
// never calls. Each property's getter/setter pair sits adjacent, exactly as
// in the IDL. "X" types carry the live-verified IIDs, "Legacy" types the
// older GUID set as a QI fallback.

[<ComImport; Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2")>]
[<AllowNullLiteral>]
type internal NetFwRuleX =
    abstract Name: string with get, set
    abstract Description: string with get, set
    abstract ApplicationName: string with get, set
    abstract ServiceName: string with get, set
    abstract Protocol: int with get, set
    abstract LocalPorts: string with get, set
    abstract RemotePorts: string with get, set
    abstract LocalAddresses: string with get, set
    abstract RemoteAddresses: string with get, set
    abstract IcmpTypesAndCodes: string with get, set
    abstract Direction: FwRuleDirection with get, set
    abstract Interfaces: obj with get, set // SAFEARRAY(VARIANT); slot filler, never called
    abstract InterfaceTypes: string with get, set
    abstract Enabled: bool with get, set
    abstract Grouping: string with get, set
    abstract Profiles: int with get, set
    abstract EdgeTraversal: bool with get, set
    abstract Action: FwAction with get, set

[<ComImport; Guid("AF230D26-BABA-4E42-ACED-F524F22CFCE2")>]
[<AllowNullLiteral>]
type internal NetFwRuleLegacy =
    abstract Name: string with get, set
    abstract Description: string with get, set
    abstract ApplicationName: string with get, set
    abstract ServiceName: string with get, set
    abstract Protocol: int with get, set
    abstract LocalPorts: string with get, set
    abstract RemotePorts: string with get, set
    abstract LocalAddresses: string with get, set
    abstract RemoteAddresses: string with get, set
    abstract IcmpTypesAndCodes: string with get, set
    abstract Direction: FwRuleDirection with get, set
    abstract Interfaces: obj with get, set // SAFEARRAY(VARIANT); slot filler, never called
    abstract InterfaceTypes: string with get, set
    abstract Enabled: bool with get, set
    abstract Grouping: string with get, set
    abstract Profiles: int with get, set
    abstract EdgeTraversal: bool with get, set
    abstract Action: FwAction with get, set

// INetFwRules vtable order: get_Count, Add, Remove, Item, _NewEnum — the
// enumerator is LAST. Inheriting IEnumerable and re-declaring GetEnumerator
// in that position mirrors the classic NetFwTypeLib interop, which is what
// makes `for r in rules` walk the collection via IEnumVARIANT marshaling.
[<ComImport; Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")>]
[<AllowNullLiteral>]
type internal NetFwRulesX =
    inherit IEnumerable
    abstract Count: int
    abstract Add: rule: NetFwRuleX -> unit
    abstract Remove: name: string -> unit
    abstract Item: name: string -> NetFwRuleX with get
    abstract GetEnumerator: unit -> IEnumerator

[<ComImport; Guid("9C4C6277-0623-4F28-85B2-0EFAF20ACBCE")>]
[<AllowNullLiteral>]
type internal NetFwRulesLegacy =
    inherit IEnumerable
    abstract Count: int
    abstract Add: rule: NetFwRuleLegacy -> unit
    abstract Remove: name: string -> unit
    abstract Item: name: string -> NetFwRuleLegacy with get
    abstract GetEnumerator: unit -> IEnumerator

// INetFwPolicy2 vtable order per netfw.idl: CurrentProfileTypes, then the
// parameterized per-profile properties (get+put adjacent), then Rules,
// ServiceRestriction, EnableRuleGroup, IsRuleGroupEnabled,
// RestoreLocalFirewallDefaults. Unused members are declared as plain
// get_/put_ methods — same slots, no marshaling risk since nothing calls
// them; they exist purely to keep Rules/RestoreLocalFirewallDefaults on the
// right slots.
[<ComImport; Guid("98325047-C671-4174-8D81-DEFCD3F03186")>]
[<AllowNullLiteral>]
type internal NetFwPolicy2X =
    abstract CurrentProfileTypes: int
    abstract get_FirewallEnabled: profileType: int -> bool
    abstract put_FirewallEnabled: profileType: int * value: bool -> unit
    abstract get_ExcludedInterfaces: profileType: int -> obj // slot filler, never called
    abstract put_ExcludedInterfaces: profileType: int * value: obj -> unit // slot filler, never called
    abstract get_BlockAllInboundTraffic: profileType: int -> bool
    abstract put_BlockAllInboundTraffic: profileType: int * value: bool -> unit
    abstract get_NotificationsDisabled: profileType: int -> bool
    abstract put_NotificationsDisabled: profileType: int * value: bool -> unit
    abstract get_UnicastResponsesToMulticastBroadcastDisabled: profileType: int -> bool
    abstract put_UnicastResponsesToMulticastBroadcastDisabled: profileType: int * value: bool -> unit
    abstract Rules: NetFwRulesX
    abstract get_ServiceRestriction: unit -> obj // slot filler, never called
    abstract EnableRuleGroup: profileTypesBitmask: int * group: string * enable: bool -> unit
    abstract IsRuleGroupEnabled: profileTypesBitmask: int * group: string -> bool
    abstract RestoreLocalFirewallDefaults: unit -> unit

[<ComImport; Guid("98325047-C671-4174-8D81-DACD38CE1C54")>]
[<AllowNullLiteral>]
type internal NetFwPolicy2Legacy =
    abstract CurrentProfileTypes: int
    abstract get_FirewallEnabled: profileType: int -> bool
    abstract put_FirewallEnabled: profileType: int * value: bool -> unit
    abstract get_ExcludedInterfaces: profileType: int -> obj // slot filler, never called
    abstract put_ExcludedInterfaces: profileType: int * value: obj -> unit // slot filler, never called
    abstract get_BlockAllInboundTraffic: profileType: int -> bool
    abstract put_BlockAllInboundTraffic: profileType: int * value: bool -> unit
    abstract get_NotificationsDisabled: profileType: int -> bool
    abstract put_NotificationsDisabled: profileType: int * value: bool -> unit
    abstract get_UnicastResponsesToMulticastBroadcastDisabled: profileType: int -> bool
    abstract put_UnicastResponsesToMulticastBroadcastDisabled: profileType: int * value: bool -> unit
    abstract Rules: NetFwRulesLegacy
    abstract get_ServiceRestriction: unit -> obj // slot filler, never called
    abstract EnableRuleGroup: profileTypesBitmask: int * group: string * enable: bool -> unit
    abstract IsRuleGroupEnabled: profileTypesBitmask: int * group: string -> bool
    abstract RestoreLocalFirewallDefaults: unit -> unit

// ── Public face (plain F# interfaces; COM detail stays behind Com) ──────

/// <summary>The members of COM INetFwRule the engine reads and writes.</summary>
[<AllowNullLiteral>]
type INetFwRule =
    abstract Name: string with get, set
    abstract Description: string with get, set
    abstract ApplicationName: string with get, set
    abstract Protocol: int with get, set
    abstract LocalPorts: string with get, set
    abstract RemotePorts: string with get, set
    abstract RemoteAddresses: string with get, set
    abstract InterfaceTypes: string with get, set
    abstract Enabled: bool with get, set
    abstract Grouping: string with get, set
    abstract Profiles: int with get, set
    abstract Direction: FwRuleDirection with get, set
    abstract Action: FwAction with get, set

/// <summary>The members of COM INetFwRules the engine touches; enumerable
/// so `for r in rules` walks the collection like the old PIA.</summary>
[<AllowNullLiteral>]
type INetFwRules =
    inherit IEnumerable
    abstract Count: int
    abstract Add: rule: INetFwRule -> unit
    abstract Remove: name: string -> unit
    abstract Item: name: string -> INetFwRule with get

/// <summary>The members of COM INetFwPolicy2 the engine touches.</summary>
[<AllowNullLiteral>]
type INetFwPolicy2 =
    abstract CurrentProfileTypes: int
    abstract Rules: INetFwRules
    abstract RestoreLocalFirewallDefaults: unit -> unit

// ── Shims: one face over whichever IID set QI-succeeded ────────────────

module internal ComImpl =

    let tryCast<'T> (o: obj) : 'T option =
        try
            match o with
            | :? 'T as t -> Some t
            | _ -> None
        with _ -> None

/// <summary>Adapts a COM rule object (either IID flavor) to INetFwRule.</summary>
type internal RuleShim(x: NetFwRuleX, legacy: NetFwRuleLegacy) =
    member _.X = x
    member _.Legacy = legacy
    interface INetFwRule with
        member s.Name
            with get () = (if not (isNull x) then x.Name else legacy.Name)
            and set v = (if not (isNull x) then x.Name <- v else legacy.Name <- v)
        member s.Description
            with get () = (if not (isNull x) then x.Description else legacy.Description)
            and set v = (if not (isNull x) then x.Description <- v else legacy.Description <- v)
        member s.ApplicationName
            with get () = (if not (isNull x) then x.ApplicationName else legacy.ApplicationName)
            and set v = (if not (isNull x) then x.ApplicationName <- v else legacy.ApplicationName <- v)
        member s.Protocol
            with get () = (if not (isNull x) then x.Protocol else legacy.Protocol)
            and set v = (if not (isNull x) then x.Protocol <- v else legacy.Protocol <- v)
        member s.LocalPorts
            with get () = (if not (isNull x) then x.LocalPorts else legacy.LocalPorts)
            and set v = (if not (isNull x) then x.LocalPorts <- v else legacy.LocalPorts <- v)
        member s.RemotePorts
            with get () = (if not (isNull x) then x.RemotePorts else legacy.RemotePorts)
            and set v = (if not (isNull x) then x.RemotePorts <- v else legacy.RemotePorts <- v)
        member s.RemoteAddresses
            with get () = (if not (isNull x) then x.RemoteAddresses else legacy.RemoteAddresses)
            and set v = (if not (isNull x) then x.RemoteAddresses <- v else legacy.RemoteAddresses <- v)
        member s.InterfaceTypes
            with get () = (if not (isNull x) then x.InterfaceTypes else legacy.InterfaceTypes)
            and set v = (if not (isNull x) then x.InterfaceTypes <- v else legacy.InterfaceTypes <- v)
        member s.Enabled
            with get () = (if not (isNull x) then x.Enabled else legacy.Enabled)
            and set v = (if not (isNull x) then x.Enabled <- v else legacy.Enabled <- v)
        member s.Grouping
            with get () = (if not (isNull x) then x.Grouping else legacy.Grouping)
            and set v = (if not (isNull x) then x.Grouping <- v else legacy.Grouping <- v)
        member s.Profiles
            with get () = (if not (isNull x) then x.Profiles else legacy.Profiles)
            and set v = (if not (isNull x) then x.Profiles <- v else legacy.Profiles <- v)
        member s.Direction
            with get () = (if not (isNull x) then x.Direction else legacy.Direction)
            and set v = (if not (isNull x) then x.Direction <- v else legacy.Direction <- v)
        member s.Action
            with get () = (if not (isNull x) then x.Action else legacy.Action)
            and set v = (if not (isNull x) then x.Action <- v else legacy.Action <- v)

/// <summary>Adaptation of raw COM objects to the shim face — defined after
/// RuleShim so both the RulesShim and the Com module can use it.</summary>
module internal ComAdapt =

    let adaptRule (o: obj) : INetFwRule =
        match ComImpl.tryCast<NetFwRuleX> o with
        | Some x -> RuleShim(x, null) :> INetFwRule
        | _ ->
            match ComImpl.tryCast<NetFwRuleLegacy> o with
            | Some l -> RuleShim(null, l) :> INetFwRule
            | _ -> null

    /// Enumerates a raw COM rules collection (either IID flavor), adapting
    /// each element. IEnumVARIANT marshaling comes from the IEnumerable
    /// inheritance on the ComImport definitions — the classic PIA route.
    let adaptedSeq (raw: IEnumerable) : seq<INetFwRule> =
        seq {
            for r in raw do
                yield adaptRule r
        }

/// <summary>Adapts the rules collection (either IID flavor) to INetFwRules;
/// enumerating yields RuleShim-wrapped elements.</summary>
type internal RulesShim(x: NetFwRulesX, legacy: NetFwRulesLegacy) =
    let underlying () : IEnumerable =
        (if not (isNull x) then x :> IEnumerable else legacy :> IEnumerable)
    interface INetFwRules with
        member _.Count = (if not (isNull x) then x.Count else legacy.Count)
        member _.Add(rule: INetFwRule) =
            match rule with
            | :? RuleShim as s ->
                if not (isNull s.X) then x.Add(s.X)
                else legacy.Add(s.Legacy)
            | _ -> invalidOp "rule must originate from Com.newRule()"
        member _.Remove(name) =
            (if not (isNull x) then x.Remove(name) else legacy.Remove(name))
        member _.Item
            with get name =
                (if not (isNull x) then
                    let r = x.Item(name)
                    if isNull (box r) then null else RuleShim(r, null) :> INetFwRule
                 else
                    let r = legacy.Item(name)
                    if isNull (box r) then null else RuleShim(null, r) :> INetFwRule)
        member _.GetEnumerator() : IEnumerator =
            (ComAdapt.adaptedSeq (underlying ())).GetEnumerator()

/// <summary>Adapts the policy object (either IID flavor) to INetFwPolicy2.</summary>
type internal Policy2Shim(x: NetFwPolicy2X, legacy: NetFwPolicy2Legacy) =
    interface INetFwPolicy2 with
        member _.CurrentProfileTypes =
            (if not (isNull x) then x.CurrentProfileTypes else legacy.CurrentProfileTypes)
        member _.Rules =
            (if not (isNull x) then RulesShim(x.Rules, null) :> INetFwRules
             else RulesShim(null, legacy.Rules) :> INetFwRules)
        member _.RestoreLocalFirewallDefaults() =
            (if not (isNull x) then x.RestoreLocalFirewallDefaults() else legacy.RestoreLocalFirewallDefaults())

/// <summary>
/// COM access points for the firewall engine: policy/rule factories and
/// collection enumeration. All COM late-binding detail stops here.
/// </summary>
module Com =

    /// <summary>
    /// Enumerates a rules collection as adapted INetFwRule values.
    /// </summary>
    let enumRules (rules: INetFwRules) : seq<INetFwRule> =
        Seq.cast<INetFwRule> rules

    /// <summary>
    /// Policy object via the HNetCfg.FwPolicy2 ProgID. Throws
    /// InvalidOperationException("Windows Firewall COM component not
    /// available.") when the COM class is missing or answers to neither
    /// known IID.
    /// </summary>
    let getPolicy2 () : INetFwPolicy2 =
        let fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
        if isNull fwPolicyType then
            invalidOp "Windows Firewall COM component not available."
        let o = Activator.CreateInstance(fwPolicyType)
        match ComImpl.tryCast<NetFwPolicy2X> o with
        | Some x -> Policy2Shim(x, null) :> INetFwPolicy2
        | None ->
            match ComImpl.tryCast<NetFwPolicy2Legacy> o with
            | Some l -> Policy2Shim(null, l) :> INetFwPolicy2
            | None -> invalidOp "Windows Firewall COM component not available."

    /// <summary>New mutable rule object via the HNetCfg.FWRule ProgID.</summary>
    let newRule () : INetFwRule =
        let ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule")
        if isNull ruleType then
            invalidOp "Windows Firewall COM component not available."
        ComAdapt.adaptRule (Activator.CreateInstance(ruleType))

/// <summary>SHLoadIndirectString — resolves indirect resource strings
/// ("@FirewallAPI.dll,-32752") that INetFwRule.Grouping returns.</summary>
module internal Shlwapi =

    [<DllImport("shlwapi.dll", CharSet = CharSet.Unicode)>]
    extern int SHLoadIndirectString(string pszSource, StringBuilder pszOutBuf, int cchOutBuf, IntPtr ppvReserved)
