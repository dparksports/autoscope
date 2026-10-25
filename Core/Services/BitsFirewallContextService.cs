using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace AutoScope.Services
{
    /// <summary>
    /// Answers "does BITS traffic bypass the firewall rules here?" with
    /// three honest layers instead of a yes/no guess:
    ///   1. The active profiles' DEFAULT OUTBOUND action — when Windows
    ///      Firewall defaults outbound to Allow (the OS default), no rule
    ///      is evaluated at all for any BITS job: bypass by default.
    ///   2. Explicit allow rules scoped to the BITS service or to
    ///      svchost.exe — under a default-deny outbound policy these are
    ///      the exemptions that let BITS through.
    ///   3. The structural fact (always true): BITS transfers execute
    ///      inside the trusted svchost hosting the BITS service, so
    ///      firewall rules targeting the CREATING process or its image
    ///      never match this traffic — the documented ATT&CK T1197
    ///      evasion. Blocking BITS itself would break Windows Update.
    /// The COM reads (INetFwPolicy2 via HNetCfg.FwPolicy2) are read-only
    /// and were validated on-box; the summary builder is pure so the
    /// self-test pins every branch.
    /// </summary>
    public sealed class BitsFirewallContextService
    {
        public sealed class Facts
        {
            public bool OutboundDefaultAllow;
            public string ProfilesChecked;
            public int AllowRuleCount;
            public List<string> AllowRuleNames = new();
            public DateTime FetchedUtc;
            public string Error;
        }

        public sealed class Verdict
        {
            public bool Bypassed;
            public string Headline;
            public string Detail;
        }

        /// <summary>Always-true structural note, shown for every job regardless of rules.</summary>
        public const string StructuralNote =
            "Structural (always true): the transfer runs inside the trusted svchost.exe hosting the BITS service — " +
            "any rule blocking the creating process or its image never matches this traffic (ATT&CK T1197 evasion). " +
            "Blocking BITS outright breaks Windows Update delivery.";

        private Facts _cached;
        private DateTime _fetchedUtc = DateTime.MinValue;
        private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);
        private readonly object _sync = new();

        /// <summary>Snapshot from cache, or null if nothing fetched yet.</summary>
        public Facts Cached()
        {
            lock (_sync) return _cached;
        }

        /// <summary>Reads the firewall state (COM, read-only), caching for 5 minutes.</summary>
        public Facts Get(bool force = false)
        {
            lock (_sync)
            {
                if (!force && _cached != null && DateTime.UtcNow - _fetchedUtc < CacheTtl) return _cached;
            }

            var f = new Facts { FetchedUtc = DateTime.UtcNow };
            try
            {
                var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                object pol = Activator.CreateInstance(type);
                var pt = pol.GetType();

                int currentProfiles = (int)pt.InvokeMember("CurrentProfileTypes", BindingFlags.GetProperty, null, pol, null);

                bool anyAllow = false;
                var names = new List<string>();
                foreach (int profileBit in new[] { 1, 2, 4 })   // domain, private, public
                {
                    if ((currentProfiles & profileBit) == 0) continue;
                    int action = (int)pt.InvokeMember("DefaultOutboundAction", BindingFlags.GetProperty, null, pol, new object[] { profileBit });
                    if (action == 1) anyAllow = true;
                }
                f.ProfilesChecked = currentProfiles switch
                {
                    1 => "domain", 2 => "private", 4 => "public", 3 => "domain+private",
                    5 => "domain+public", 6 => "private+public", _ => $"bitmask {currentProfiles}"
                };
                // If any active profile defaults outbound to Allow, traffic on that profile leaves unchecked.
                f.OutboundDefaultAllow = anyAllow;

                object rules = pt.InvokeMember("Rules", BindingFlags.GetProperty, null, pol, null);
                foreach (object r in (System.Collections.IEnumerable)rules)
                {
                    try
                    {
                        var rt = r.GetType();
                        bool enabled = (bool)rt.InvokeMember("Enabled", BindingFlags.GetProperty, null, r, null);
                        if (!enabled) continue;
                        int dir = (int)rt.InvokeMember("Direction", BindingFlags.GetProperty, null, r, null);
                        if (dir != 2) continue;                        // outbound only
                        int act = (int)rt.InvokeMember("Action", BindingFlags.GetProperty, null, r, null);
                        if (act != 1) continue;                        // allow only
                        string app = (string)rt.InvokeMember("Application", BindingFlags.GetProperty, null, r, null);
                        string svc = (string)rt.InvokeMember("Service", BindingFlags.GetProperty, null, r, null);
                        bool svcBits = string.Equals(svc, "BITS", StringComparison.OrdinalIgnoreCase);
                        bool appSvchost = app != null && app.EndsWith("svchost.exe", StringComparison.OrdinalIgnoreCase);
                        if (svcBits || appSvchost)
                        {
                            f.AllowRuleCount++;
                            if (f.AllowRuleNames.Count < 8)
                                f.AllowRuleNames.Add((string)rt.InvokeMember("Name", BindingFlags.GetProperty, null, r, null)
                                    + (svcBits ? " (service: BITS)" : " (svchost)"));
                        }
                    }
                    catch { /* per-rule property gaps are expected */ }
                }
            }
            catch (Exception ex)
            {
                f.Error = ex.Message;
            }

            lock (_sync) { _cached = f; _fetchedUtc = DateTime.UtcNow; }
            return f;
        }

        /// <summary>Pure verdict builder — every branch testable offline.</summary>
        public static Verdict BuildSummary(Facts f)
        {
            if (f == null) return new Verdict { Bypassed = false, Headline = "Firewall state not checked yet.", Detail = "" };
            if (f.Error != null)
                return new Verdict { Bypassed = false, Headline = $"Firewall state unavailable: {f.Error}", Detail = "" };

            if (f.OutboundDefaultAllow)
            {
                return new Verdict
                {
                    Bypassed = true,
                    Headline = "YES — bypasses the rules: the active firewall profile(s) default outbound to Allow.",
                    Detail = $"Profiles active: {f.ProfilesChecked}. With a default-allow outbound policy Windows Firewall " +
                             "evaluates no rule for these connections — every BITS job leaves unchecked, like all outbound " +
                             "traffic on this machine. A hard deny (outbound = Block) is required before any BITS rule can bite."
                };
            }

            if (f.AllowRuleCount > 0)
            {
                var names = string.Join("; ", f.AllowRuleNames);
                return new Verdict
                {
                    Bypassed = true,
                    Headline = $"YES — bypasses the default deny: {f.AllowRuleCount} explicit allow rule(s) cover the BITS service / svchost.",
                    Detail = $"Outbound defaults to Block on {f.ProfilesChecked}, but these allow rules exempt BITS-hosted transfers: {names}."
                };
            }

            return new Verdict
            {
                Bypassed = false,
                Headline = "No — outbound defaults to Block and no BITS-specific allow rule was found.",
                Detail = $"Profiles active: {f.ProfilesChecked}. BITS traffic is subject to the same default-deny policy as everything else. " +
                         "Note that per-destination outcomes also depend on any matching custom allow rules for the target IPs."
            };
        }
    }
}
