using System;
using System.Collections.Generic;

namespace AutoScope.Models
{
    public sealed class VendorEntry
    {
        public string Name { get; init; }
        public string Role { get; init; }
        public string SourceUrl { get; init; }
        public string SourceLabel { get; init; }
        public DateTime VerifiedUtc { get; init; }
    }

    public sealed class VendorCategory
    {
        public string Title { get; init; }
        public string Explanation { get; init; }
        public IReadOnlyList<VendorEntry> Entries { get; init; }
    }

    /// <summary>
    /// Curated catalog of who can receive Defender/Windows security data —
    /// what the Data &amp; Privacy tab shows as "who receives your data".
    /// Hand-curated from Microsoft's published documents on the Verified
    /// dates; the point of the "source ↗" links is that users re-verify
    /// themselves (the tab makes no background calls to check freshness).
    ///
    /// Honest limits this catalog states up front rather than inventing
    /// names: for consumer Windows, Microsoft publishes the *category*
    /// "vendors or agents working on our behalf" but not a per-user (or
    /// public consumer) vendor list. The closest public named list is the
    /// Online Services subprocessor list (enterprise services).
    /// </summary>
    public static class VendorCatalog
    {
        private static readonly DateTime Verified = new(2026, 10, 12, 0, 0, 0, DateTimeKind.Utc);

        public static readonly IReadOnlyList<VendorCategory> Categories = new[]
        {
            new VendorCategory
            {
                Title = "Microsoft (first party)",
                Explanation = "Data goes to Microsoft's cloud and is stored in Microsoft datacenters (your region and/or the US, plus other jurisdictions where Microsoft or its service providers operate). Microsoft corporate entities and affiliates act as one group — there is no separate hand-off to \"HQ\".",
                Entries = new[]
                {
                    new VendorEntry
                    {
                        Name = "Microsoft Corporation & affiliates",
                        Role = "Cloud-delivered protection analysis (file hash/certificate reputation, sample analysis), detection reporting, diagnostic telemetry storage.",
                        SourceUrl = "https://privacy.microsoft.com/en-us/privacystatement",
                        SourceLabel = "Microsoft Privacy Statement — \"Reasons we share personal data\"",
                        VerifiedUtc = Verified
                    }
                }
            },
            new VendorCategory
            {
                Title = "Contracted vendors (processors)",
                Explanation = "Companies Microsoft contracts to help process data, bound by Microsoft's privacy/security requirements, prohibited from using the data for any other purpose. Microsoft does not sell Defender data.",
                Entries = new[]
                {
                    new VendorEntry
                    {
                        Name = "Microsoft Online Services subprocessors (named list)",
                        Role = "Published subprocessor list for Microsoft's online services — the closest thing to a named vendor list that exists publicly (enterprise scope; the consumer-Windows list is not published by name).",
                        SourceUrl = "https://www.microsoft.com/en-us/trust-center/privacy",
                        SourceLabel = "Microsoft Trust Center — privacy (links the subprocessor list)",
                        VerifiedUtc = Verified
                    },
                    new VendorEntry
                    {
                        Name = "Consumer-Windows vendors (unnamed by Microsoft)",
                        Role = "The Privacy Statement confirms the category — \"vendors or agents working on our behalf\" — but does not name them for consumer Windows. Use the request-builder on this tab to ask Microsoft directly; that is the only authoritative source.",
                        SourceUrl = "https://privacy.microsoft.com/en-us/privacystatement",
                        SourceLabel = "Privacy Statement — sharing section",
                        VerifiedUtc = Verified
                    }
                }
            },
            new VendorCategory
            {
                Title = "Security-intelligence sharing",
                Explanation = "Threat intelligence (malware signatures, IoCs — not your personal files) is shared with the security industry.",
                Entries = new[]
                {
                    new VendorEntry
                    {
                        Name = "Virus Information Alliance (VIA) members",
                        Role = "Microsoft's threat-intel sharing program; the member list is published. Telemetry-derived intel flows here; it is threat data, not personal files.",
                        SourceUrl = "https://learn.microsoft.com/en-us/defender-endpoint/virus-information-alliance",
                        SourceLabel = "Microsoft Learn — Virus Information Alliance",
                        VerifiedUtc = Verified
                    }
                }
            },
            new VendorCategory
            {
                Title = "Legal / government recipients",
                Explanation = "Disclosure only when Microsoft believes it must comply with valid legal process, or to protect customers/safety. Microsoft publishes aggregate counts — agencies are not named per request.",
                Entries = new[]
                {
                    new VendorEntry
                    {
                        Name = "Law-enforcement & government agencies (aggregate reporting)",
                        Role = "Aggregate counts of requests and accounts affected are published twice yearly. Individual disclosures are not itemized.",
                        SourceUrl = "https://www.microsoft.com/en-us/corporate-responsibility/digital-safety",
                        SourceLabel = "Microsoft — Digital Safety / Law Enforcement Requests Report",
                        VerifiedUtc = Verified
                    }
                }
            },
            new VendorCategory
            {
                Title = "Where you can see what's held",
                Explanation = "Self-service views of the data Microsoft associates with your account.",
                Entries = new[]
                {
                    new VendorEntry
                    {
                        Name = "Microsoft privacy dashboard",
                        Role = "Activity data, ad settings, and export/delete requests for your Microsoft account.",
                        SourceUrl = "https://account.microsoft.com/privacy",
                        SourceLabel = "account.microsoft.com/privacy",
                        VerifiedUtc = Verified
                    },
                    new VendorEntry
                    {
                        Name = "Diagnostic Data Viewer",
                        Role = "Microsoft's own tool that shows the exact diagnostic events Windows sends — the raw evidence behind the telemetry level on this tab.",
                        SourceUrl = "https://learn.microsoft.com/en-us/windows/privacy/diagnostic-data-viewer-overview",
                        SourceLabel = "Microsoft Learn — Diagnostic Data Viewer",
                        VerifiedUtc = Verified
                    }
                }
            }
        };
    }
}
