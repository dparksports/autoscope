using System.Collections.Generic;
using System.Linq;

namespace AutoScope.Services
{
    /// <summary>
    /// "A network feature stopped working — which of my blocks is doing it,
    /// and what do I pause to restore it?" Maps user-visible symptoms to the
    /// service groups whose ACTIVE blocks can cause them, so the Blocks tab's
    /// Restore guide can show exactly which rules to lift — the inverse of
    /// the block list: symptom → serviceKeys → matching block records,
    /// ranked by how freshly the blocked target is still being attempted
    /// (the block that is actively swallowing traffic is the likely culprit).
    /// </summary>
    public sealed class ServiceSymptom
    {
        public string Id;
        public string Title;        // "Windows Update & Store downloads"
        public string Notice;       // what the user would notice
        /// <summary>Blocks whose service group is one of these keys match.</summary>
        public string[] ServiceKeys;
        /// <summary>Optional: also match IP blocks classified into these
        /// categories (update symptoms implicate CDN-edge blocks even when
        /// their service attribution is still unresolved).</summary>
        public string[] AlsoClasses = System.Array.Empty<string>();
    }

    public static class ServiceOutageMap
    {
        public static readonly ServiceSymptom[] Symptoms =
        {
            new ServiceSymptom
            {
                Id = "connectivity",
                Title = "Internet / network connectivity",
                Notice = "No internet, 'no network' status, pages won't load, nothing resolves.",
                ServiceKeys = new[] { "dnscache", "nlasvc", "netprofm", "ncsi", "dhcp", "winhttpautoproxysvc" },
            },
            new ServiceSymptom
            {
                Id = "updates",
                Title = "Windows Update & Store downloads",
                Notice = "Updates stuck at 0%, Store downloads hang, update scans never finish.",
                ServiceKeys = new[] { "wuauserv", "dosvc", "usosvc", "mousocoreworker", "bits", "installservice" },
                AlsoClasses = new[] { "Akamai (MS CDN)", "Gcore (MS CDN)" }, // update content CDNs
            },
            new ServiceSymptom
            {
                Id = "defender",
                Title = "Microsoft Defender protection",
                Notice = "Signature updates fail, protection shows out of date, scans error.",
                ServiceKeys = new[] { "msmpeng", "mpcmdrun", "mpdefendercoreservice", "nisdrv" },
            },
            new ServiceSymptom
            {
                Id = "signin",
                Title = "Microsoft-account / workplace sign-in",
                Notice = "Can't sign in to Microsoft account, mail, Teams or workplace apps.",
                ServiceKeys = new[] { "lsass", "wlidsvc", "tokenbroker", "licensing", "appinfo" },
            },
            new ServiceSymptom
            {
                Id = "startmenu",
                Title = "Start menu, search & widgets",
                Notice = "Start menu web results empty, search suggests nothing, widgets blank.",
                ServiceKeys = new[] { "searchhost", "startmenuexperiencehost", "widgets", "msedgewebview2", "cdpsvc" },
            },
            new ServiceSymptom
            {
                Id = "notifications",
                Title = "Toast & tile notifications",
                Notice = "Notifications never arrive, live tiles stay cold.",
                ServiceKeys = new[] { "wpnservice", "backgroundtaskhost" },
            },
            new ServiceSymptom
            {
                Id = "browser",
                Title = "Microsoft Edge & embedded web content",
                Notice = "Edge won't load pages, apps with embedded web views show errors.",
                ServiceKeys = new[] { "msedge", "msedgewebview2", "microsoftedgeupdate" },
            },
            new ServiceSymptom
            {
                Id = "certificates",
                Title = "Certificate / HTTPS errors in system apps",
                Notice = "System components report certificate trust errors, updates fail validation.",
                ServiceKeys = new[] { "cryptsvc" },
            },
            new ServiceSymptom
            {
                Id = "telemetry",
                Title = "Diagnostics & feedback upload (telemetry)",
                Notice = "Only telemetry/fedback upload is affected — often blocked on purpose.",
                ServiceKeys = new[] { "diagtrack", "werfault" },
            },
            new ServiceSymptom
            {
                Id = "time",
                Title = "System clock sync",
                Notice = "Clock drifts, Kerberos/HTTPS complain about time skew.",
                ServiceKeys = new[] { "w32time" },
            },
        };

        /// <summary>Whether one record belongs to this symptom's blast
        /// radius: a matching service group, or (for infrastructure symptoms
        /// like updates) any block classified into the implicated CDN
        /// classes — attribution state irrelevant, an unresolved Akamai edge
        /// block still stops update delivery.</summary>
        public static bool Matches(ServiceSymptom s, BlockRecord r)
        {
            var keys = new HashSet<string>(s.ServiceKeys, System.StringComparer.OrdinalIgnoreCase);
            var classes = new HashSet<string>(s.AlsoClasses, System.StringComparer.OrdinalIgnoreCase);
            return MatchesCore(keys, classes, r);
        }

        internal static bool MatchesCore(HashSet<string> keys, HashSet<string> classes, BlockRecord r)
        {
            if (keys.Contains(BlocksStore.ServiceGroupKey(r))) return true;
            return classes.Count > 0 && classes.Contains(r.ClassAtBlock ?? "");
        }

        /// <summary>
        /// The blocks whose pause would restore the symptom (record status
        /// filter: only ACTIVE blocks — a paused block breaks nothing).
        /// </summary>
        public static List<BlockRecord> MatchingBlocks(ServiceSymptom s, IEnumerable<BlockRecord> records)
        {
            var keys = new HashSet<string>(s.ServiceKeys, System.StringComparer.OrdinalIgnoreCase);
            var classes = new HashSet<string>(s.AlsoClasses, System.StringComparer.OrdinalIgnoreCase);
            return records.Where(r => r.Status != "off" && MatchesCore(keys, classes, r)).ToList();
        }
    }
}
