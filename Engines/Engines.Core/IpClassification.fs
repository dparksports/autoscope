namespace AutoScope.Engines.Core

open System.Net
open System.Net.Sockets

/// <summary>
/// IP ownership classification against session-verified ranges.
/// Used by the block-rule guardrails and the Blocked Rules manager so the
/// UI can warn BEFORE a user blocks infrastructure Windows depends on.
/// Note: SvchostTraceView keeps its own copy of this table for trace
/// analysis; if the ranges change, update both (extract-to-library is the
/// eventual fix — this file is that extraction).
/// F# port of Core/Services/IpClassifier.cs — pure, no state, no IO. Both
/// the C# names (Classify/IsMicrosoftInfra/WarningText) and F#-style
/// lowercase names are exposed; C# callers switch with a one-line rename
/// (IpClassifier → IpClassification).
/// </summary>
module IpClassification =

    // (Name, Cidrs) range table — order matters, first match wins
    // (mirrors the C# IpClassifier.Ranges exactly).
    let private ranges: (string * string[])[] =
        [| ("Microsoft/Azure",
            [| "20.0.0.0/8"; "40.0.0.0/8"; "13.64.0.0/11"; "13.104.0.0/14"
               "52.96.0.0/12"; "52.112.0.0/14"; "65.52.0.0/14"; "72.145.32.0/19"; "172.176.0.0/12" |])
           ("Akamai (MS CDN)",
            [| "23.32.0.0/11"; "23.192.0.0/11"; "2.16.0.0/13"; "95.100.0.0/15"; "184.24.0.0/13"; "104.64.0.0/10" |])
           ("Gcore (MS CDN)", [| "92.223.0.0/16" |]) |]

    let private toUint (a: IPAddress) : uint32 =
        let b = a.GetAddressBytes()
        // C# computes b[0]<<24 | b[1]<<16 | b[2]<<8 | b[3] in int, then casts
        // to uint — mirror that. Parens are load-bearing: F# `<<<` binds
        // LOWER than `|||` (the opposite of C#), so the shifts must be
        // parenthesized or the shift counts get OR-ed together.
        uint32 ((int b.[0] <<< 24) ||| (int b.[1] <<< 16) ||| (int b.[2] <<< 8) ||| (int b.[3]))

    let private inCidr (v: uint32) (cidr: string) : bool =
        let parts = cidr.Split('/')
        let net = toUint (IPAddress.Parse parts.[0])
        let mask = System.UInt32.MaxValue <<< (32 - int parts.[1])
        (v &&& mask) = (net &&& mask)

    let classify (ip: string) : string =
        match IPAddress.TryParse ip with
        | true, addr when addr.AddressFamily = AddressFamily.InterNetwork ->
            let v = toUint addr
            ranges
            |> Array.tryPick (fun (name, cidrs) -> if Array.exists (inCidr v) cidrs then Some name else None)
            |> Option.defaultValue "Unclassified"
        | _ -> "IPv6/other"

    /// <summary>True when a block on this IP risks breaking Windows features.</summary>
    let isMicrosoftInfra (ip: string) : bool =
        let c = classify ip
        c <> "Unclassified" && c <> "IPv6/other"

    /// <summary>Impact warning for the confirm dialog; empty when unclassified.</summary>
    let warningText (ip: string) : string =
        match classify ip with
        | "Microsoft/Azure" ->
            $"⚠ {ip} belongs to Microsoft (Azure/M365 core).\n"
            + "Endpoints in these ranges carry Windows Update, Defender signatures,\n"
            + "push notifications (WNS) and Microsoft-account sign-in.\n"
            + "Blocking it can break updates, notifications or login — usually NOT what you want."
        | "Akamai (MS CDN)" ->
            $"⚠ {ip} is an Akamai edge — a Microsoft CDN partner that delivers\n"
            + "Windows Update and Store content. Blocking it can break updates."
        | "Gcore (MS CDN)" ->
            $"⚠ {ip} is a Gcore edge — a Microsoft CDN partner for update delivery.\n"
            + "Blocking it can break updates."
        | _ -> ""

    // C#-callable aliases with the exact original IpClassifier method names —
    // existing callers switch with a one-line rename (IpClassifier → IpClassification).
    let Classify(ip: string) : string = classify ip

    let IsMicrosoftInfra(ip: string) : bool = isMicrosoftInfra ip

    let WarningText(ip: string) : string = warningText ip
