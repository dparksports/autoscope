using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using AutoScope.Models;

namespace AutoScope.Services
{
    /// <summary>
    /// The "why they connect" half of the BITS tab: a small curated
    /// knowledge base that maps (job name, creating process, destination
    /// host) patterns to a human explanation and an expected verdict.
    /// Seeded from the 2026-10-15 on-box triage (svchost -k netsvcs -p -s
    /// BITS uploading packets to 34.104.35.123 → Chrome Component Updater
    /// pulling from Google's gvt1.com CDN via BITS). Matching is
    /// specificity-ordered: the rule with the most matched conditions
    /// wins, so a broad host rule never shadows a precise creator+host
    /// rule. Upload jobs always end at Review regardless of rule.
    /// </summary>
    public static class BitsReasonCatalog
    {
        public sealed class ReasonRule
        {
            public string JobNamePattern;
            public string CreatorPattern;
            public string HostPattern;
            public string Title;
            public string Explanation;
        }

        public sealed class Explanation
        {
            public string Title;
            public string Text;
            public string Verdict;   // "Normal" | "Review"
        }

        private static readonly (Regex name, Regex creator, Regex host)[] Compiled;
        private static readonly ReasonRule[] Rules = BuildRules();

        private static ReasonRule[] BuildRules() => new[]
        {
            new ReasonRule
            {
                JobNamePattern = @"Chrome Component Updater",
                CreatorPattern = @"\\chrome\.exe$",
                HostPattern = @"(^|\.)gvt1\.com$|(^|\.)google\.com$|(^|\.)googleusercontent\.com$",
                Title = "Google Chrome component updates",
                Explanation = "Chrome keeps browser components (codec packs, sub-components like the Puffin diff generator) current by handing BITS download jobs against Google's own gvt1.com download CDN. The transfer executes inside the trusted svchost hosting BITS — that is why the socket shows as svchost, not chrome. Download-only; observed on this machine as three jobs within a minute, each completing with status 0x0."
            },
            new ReasonRule
            {
                JobNamePattern = @"Font Download",
                CreatorPattern = @"svchost\.exe$",
                HostPattern = @"fs\.microsoft\.com$|\.akamaiedge\.net$",
                Title = "Windows cloud font catalog",
                Explanation = "Windows fetches its cloud-font availability list (fs.microsoft.com/fs/windows/config.json, fronted by Akamai) as a BITS download owned by LOCAL SERVICE, so per-user fonts can be streamed on demand. A config.json fetch is metadata, not font payloads."
            },
            new ReasonRule
            {
                JobNamePattern = @"Defender|Antimalware|Signature",
                HostPattern = @"\.microsoft\.com$|\.windowsupdate\.com$|\.mp\.microsoft\.com$",
                Title = "Defender definition updates",
                Explanation = "Microsoft Defender pulls engine and signature updates (mpam-*.exe, nis_*.exe) through BITS from Microsoft update endpoints. Runs as SYSTEM; schedule follows the signature-refresh cadence (multiple times a day)."
            },
            new ReasonRule
            {
                CreatorPattern = @"wuaueng|svchost\.exe$",
                HostPattern = @"windowsupdate\.com$|\.mp\.microsoft\.com$|delivery\.mp\.microsoft\.com$|do\.dsp\.cdn\.windowsupdate\.com$",
                Title = "Windows Update / Delivery Optimization metadata",
                Explanation = "The update stack uses BITS for manifest and metadata fetches (payload chunks usually go via Delivery Optimization instead). Destination ranges rotate weekly; blocking them produces 0x80d0xxxx update errors."
            },
            new ReasonRule
            {
                JobNamePattern = @"OneSetup|Office",
                HostPattern = @"officecdn\.microsoft\.com$|\.microsoft\.com$",
                Title = "Office click-to-run servicing",
                Explanation = "Microsoft 365's click-to-run installer and its OneSetup bootstrap fetch update manifests and packages over BITS from the Office CDN."
            },
            new ReasonRule
            {
                CreatorPattern = @"\\Google\\|\\GoogleUpdater|\\GoogleUpdate",
                HostPattern = @"(^|\.)gvt1\.com$|(^|\.)google\.com$|(^|\.)googleapis\.com$|(^|\.)googleusercontent\.com$",
                Title = "Google software updater",
                Explanation = "Google updaters (and enterprise MSI installs of Chrome) use BITS to pull packages from Google's gvt1.com download CDN. gvt1.com is Google-owned; e.g. edgedl.me.gvt1.com resolves into 34.104.32.0/20 (Google LLC)."
            },
            new ReasonRule
            {
                HostPattern = @"(^|\.)microsoft\.com$|(^|\.)windowsupdate\.com$|(^|\.)msedge\.net$|(^|\.)akam(services|amai)?(edge|ai)?\.net$|\.akamai(edgenet|networks)?\.net$|(^|\.)gcore\.com$|(^|\.)gvt1\.com$",
                Title = "Known Microsoft/CDN endpoint",
                Explanation = "The destination belongs to Microsoft or a major download CDN (Akamai/Gcore/Google) — the usual infrastructure for OS and application updates delivered over BITS."
            },
        };

        static BitsReasonCatalog()
        {
            Compiled = Rules
                .Select(r => (
                    name: r.JobNamePattern != null ? new Regex(r.JobNamePattern, RegexOptions.IgnoreCase | RegexOptions.Compiled) : null,
                    creator: r.CreatorPattern != null ? new Regex(r.CreatorPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled) : null,
                    host: r.HostPattern != null ? new Regex(r.HostPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled) : null))
                .ToArray();
        }

        /// <summary>
        /// Explains one job. Every field is optional — the catalog degrades
        /// gracefully to "Unattributed — review" with investigation
        /// pointers instead of guessing. Upload direction always wins the
        /// verdict: BITS upload jobs are the documented T1197 exfiltration
        /// vector and deserve eyes even when the host looks legitimate.
        /// </summary>
        public static Explanation Explain(BitsJobItem job)
        {
            if (job == null) return null;

            bool upload = job.IsUpload;

            int best = -1, bestScore = -1;
            for (int i = 0; i < Rules.Length; i++)
            {
                var (name, creator, host) = Compiled[i];
                int score = 0;
                if (name != null && name.IsMatch(job.Name ?? "")) score++;
                if (creator != null && creator.IsMatch(job.CreatorImage ?? "")) score++;
                if (host != null && host.IsMatch(job.Host ?? "")) score++;
                if (score > bestScore) { bestScore = score; best = i; }
            }

            if (best >= 0 && bestScore >= 1)
            {
                var rule = Rules[best];
                string text = rule.Explanation;
                if (upload)
                    text += "  NOTE: this job is an UPLOAD — data is being sent TO the remote endpoint. " +
                            "Update delivery is download-only, so an upload here needs manual review even if the host is known.";
                return new Explanation
                {
                    Title = rule.Title,
                    Text = text,
                    Verdict = upload ? "Review" : "Normal"
                };
            }

            string pointers =
                $"Created by {job.CreatorDisplay} (owner {job.OwnerAccount ?? "?"}) targeting " +
                $"{job.HostDisplay ?? "an unknown host"}" +
                (string.IsNullOrEmpty(job.Org) ? "" : $" ({job.Org})") + ". " +
                "No known update pattern matches this combination. Check: does the creator process signature verify " +
                "(field above)? Is the destination owner plausible for this software? Is the direction really a download? " +
                "BITS jobs created by script hosts, office apps, or anything running from Temp are the classic " +
                "living-off-the-land shape (ATT&CK T1197).";
            return new Explanation
            {
                Title = "Unattributed — review",
                Text = pointers,
                Verdict = "Review"
            };
        }
    }
}
