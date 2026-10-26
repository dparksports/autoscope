namespace AutoScope.Engines.Firewall

/// <summary>
/// Every rule-name prefix and description string the firewall engine knows,
/// injected by the host app — the engine itself is app-agnostic and never
/// embeds an app name. "Own" prefixes are what this app CREATES; "Adopted"
/// are other installs' rules it manages in place without renaming;
/// "Legacy" are this app's own historical naming schemes (consolidation
/// targets, still honored for matching).
/// </summary>
type FirewallNaming =
    { OwnIpPrefix: string
      OwnAppPrefix: string
      AdoptedPrefixes: string list
      LegacyIpPrefixes: string list
      LegacyAppPrefixes: string list
      /// rule Description marker for user-created blocks (provenance is
      /// appended after it)
      UserBlockDescription: string }

module Naming =
    /// AutoScope's policy: creates AS-BLOCK, adopts AutoCommand's AC-BLOCK
    /// and AutoTrack's AT-BLOCK in place (mutual adoption — any of the three
    /// apps' panic buttons restores everything), still honors its own
    /// pre-v3 legacy names.
    let autoscope () =
        { OwnIpPrefix = "AS-BLOCK-IP "
          OwnAppPrefix = "AS-BLOCK-APP "
          AdoptedPrefixes = [ "AC-BLOCK-IP "; "AC-BLOCK-APP "; "AT-BLOCK-IP "; "AT-BLOCK-APP " ]
          LegacyIpPrefixes = [ "AutoScope IP Block - " ]
          LegacyAppPrefixes = [ "AutoScope Process Block - " ]
          UserBlockDescription = "AutoScope User Block" }
