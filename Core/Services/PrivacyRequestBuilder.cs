using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AutoScope.Services
{
    /// <summary>
    /// Draft-letter generator + local tracker for the Data &amp; Privacy tab.
    ///
    /// Two deliberately separate flows, because they are legally different:
    ///   • Corporate privacy request — CCPA/CPRA and the growing family of
    ///     state privacy statutes. Requests about data a vendor processes for
    ///     Microsoft go THROUGH Microsoft (the business), not to vendors
    ///     directly — vendors process on the business's behalf and would just
    ///     redirect. The letter says exactly which Defender data categories
    ///     are in scope.
    ///   • FOIA + Privacy Act request — to FEDERAL AGENCIES only. FOIA
    ///     (5 U.S.C. § 552) never applies to private companies, so this
    ///     flow is for records an agency holds (e.g. legal process served
    ///     on Microsoft concerning your data), not for Microsoft itself.
    ///
    /// Everything this class produces is a DRAFT for the user to review,
    /// edit, and send themselves — AutoScope never sends anything. The
    /// letters are informational, not legal advice; the UI states this too.
    /// </summary>
    public sealed class PrivacyRequestBuilder
    {
        // ── State statutes ──────────────────────────────────────────────────

        public sealed class StatePrivacyLaw
        {
            public string State { get; init; }
            public string StatuteName { get; init; }
            public string Citation { get; init; }
            public int ResponseDays { get; init; }
            public int ExtensionDays { get; init; }

            public override string ToString() => State;
        }

        /// <summary>Major US comprehensive privacy statutes as of the
        /// verified date. Residents of states not listed can still send a
        /// general request, but no statutory response deadline applies —
        /// the letter says so honestly.</summary>
        public static readonly IReadOnlyList<StatePrivacyLaw> StateLaws = new[]
        {
            new StatePrivacyLaw { State = "California",  StatuteName = "California Consumer Privacy Act (as amended by the CPRA)", Citation = "Cal. Civ. Code § 1798.100 et seq.",            ResponseDays = 45, ExtensionDays = 45 },
            new StatePrivacyLaw { State = "Virginia",    StatuteName = "Virginia Consumer Data Protection Act",                   Citation = "Va. Code § 59.1-575 et seq.",                    ResponseDays = 45, ExtensionDays = 60 },
            new StatePrivacyLaw { State = "Colorado",    StatuteName = "Colorado Privacy Act",                                   Citation = "C.R.S. § 6-1-1301 et seq.",                      ResponseDays = 45, ExtensionDays = 45 },
            new StatePrivacyLaw { State = "Connecticut", StatuteName = "Connecticut Data Privacy Act",                           Citation = "Conn. Gen. Stat. § 42-515 et seq.",              ResponseDays = 45, ExtensionDays = 45 },
            new StatePrivacyLaw { State = "Utah",        StatuteName = "Utah Consumer Privacy Act",                              Citation = "Utah Code § 13-61-101 et seq.",                  ResponseDays = 45, ExtensionDays = 45 },
            new StatePrivacyLaw { State = "Texas",       StatuteName = "Texas Data Privacy and Security Act",                    Citation = "Tex. Bus. & Com. Code § 541.001 et seq.",        ResponseDays = 45, ExtensionDays = 45 },
            new StatePrivacyLaw { State = "Oregon",      StatuteName = "Oregon Consumer Privacy Act",                            Citation = "ORS § 646A.400 et seq.",                         ResponseDays = 45, ExtensionDays = 45 },
            new StatePrivacyLaw { State = "Montana",     StatuteName = "Montana Consumer Data Privacy Act",                      Citation = "Mont. Code § 30-14-1701 et seq.",                ResponseDays = 45, ExtensionDays = 45 },
            new StatePrivacyLaw { State = "Other US state (no statute selected)", StatuteName = null, Citation = null, ResponseDays = 0, ExtensionDays = 0 }
        };

        // ── FOIA agencies ───────────────────────────────────────────────────

        public sealed class FoiaAgency
        {
            public string Name { get; init; }
            public string PortalUrl { get; init; }
            public override string ToString() => Name;
        }

        public static readonly IReadOnlyList<FoiaAgency> FoiaAgencies = new[]
        {
            new FoiaAgency { Name = "Federal Bureau of Investigation (FBI)",        PortalUrl = "https://www.fbi.gov/foia" },
            new FoiaAgency { Name = "Dept. of Homeland Security (DHS)",             PortalUrl = "https://www.dhs.gov/foia" },
            new FoiaAgency { Name = "Cybersecurity & Infrastructure Security Agency (CISA)", PortalUrl = "https://www.cisa.gov/foia-requests" },
            new FoiaAgency { Name = "National Security Agency (NSA)",               PortalUrl = "https://www.nsa.gov/about/foia/" },
            new FoiaAgency { Name = "Other agency — find via foia.gov",             PortalUrl = "https://www.foia.gov/" }
        };

        // ── Letter inputs ───────────────────────────────────────────────────

        public sealed class CorporateInput
        {
            public StatePrivacyLaw Law { get; set; }
            public string FullName { get; set; }
            public string Email { get; set; }
            public string Devices { get; set; }
            public DateTime? FromDate { get; set; }
            public DateTime? ToDate { get; set; }
            public bool RightToKnowCategories { get; set; }
            public bool RightToKnowSpecific { get; set; }
            public bool RightToDelete { get; set; }
            public bool RightToCorrect { get; set; }
            public bool RightToOptOut { get; set; }
            public bool IncludeSettingsSnapshot { get; set; }
            public DefenderPrivacyService.PrivacyState Snapshot { get; set; }
        }

        public sealed class FoiaInput
        {
            public FoiaAgency Agency { get; set; }
            public string FullName { get; set; }
            public string Email { get; set; }
            public string Description { get; set; }
            public bool FeeWaiver { get; set; }
            public bool Expedited { get; set; }
        }

        // ── Corporate letter ────────────────────────────────────────────────

        public static string BuildCorporateLetter(CorporateInput input)
        {
            var law = input.Law;
            var sb = new StringBuilder();
            sb.AppendLine(DateTime.Today.ToString("MMMM d, yyyy"));
            sb.AppendLine();
            sb.AppendLine(input.FullName);
            sb.AppendLine(input.Email);
            sb.AppendLine();
            sb.AppendLine("Privacy Response Center");
            sb.AppendLine("Microsoft Corporation");
            sb.AppendLine("One Microsoft Way");
            sb.AppendLine("Redmond, WA 98052");
            sb.AppendLine();
            string rightsPhrase = law.StatuteName == null
                ? "a consumer privacy request"
                : $"a request under the {law.StatuteName}, {law.Citation}";
            sb.AppendLine($"Re: {rightsPhrase} — data collected through Microsoft Defender Antivirus and Windows security features");
            sb.AppendLine();
            sb.AppendLine("To the Microsoft Privacy Response Center:");
            sb.AppendLine();
            sb.Append("I am a resident of ").Append(law.State).AppendLine(" and am submitting")
              .Append("this request in my individual capacity as a consumer whose personal data Microsoft")
              .AppendLine(" processes through the Windows security features described below.");

            var rights = new List<string>();
            if (input.RightToKnowCategories) rights.Add("the CATEGORIES of personal data collected (request to know)");
            if (input.RightToKnowSpecific) rights.Add("the SPECIFIC pieces of personal data collected (request to know)");
            if (input.RightToDelete) rights.Add("DELETION of my personal data (request to delete)");
            if (input.RightToCorrect) rights.Add("CORRECTION of inaccurate personal data (request to correct)");
            if (input.RightToOptOut) rights.Add("to OPT OUT of any sale or sharing of my personal data");

            if (rights.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("I am exercising the following rights:");
                for (int i = 0; i < rights.Count; i++)
                    sb.AppendLine($"  {i + 1}. {rights[i]}");
            }

            sb.AppendLine();
            sb.Append("Scope of this request: personal data associated with me and my account, and with the")
              .AppendLine(" following device(s), generated by Microsoft Defender Antivirus and related Windows")
              .AppendLine(" security features, for the period ")
              .Append(input.FromDate?.ToString("yyyy-MM-dd") ?? "the beginning of collection")
              .Append(" through ")
              .Append(input.ToDate?.ToString("yyyy-MM-dd") ?? "the date of this letter")
              .AppendLine(":")
              .AppendLine("  1. File samples: copies of files uploaded from my device(s) for analysis, and the dates/times of those uploads;")
              .AppendLine("  2. File metadata submitted for cloud reputation lookups (file hashes, file names, digital certificate information);")
              .AppendLine("  3. Detection reports produced when threats were identified on my device(s);")
              .AppendLine("  4. Associated diagnostic telemetry linked to those features.")
              .AppendLine();
            sb.Append("Device(s): ").AppendLine(string.IsNullOrWhiteSpace(input.Devices) ? "[describe your device(s), e.g. laptop model + Windows device name]" : input.Devices);
            sb.AppendLine();
            sb.Append("I additionally request disclosure of the categories of recipients — including service")
              .AppendLine(" providers, contractors, and processors — with which the above data has been shared,")
              .AppendLine(" consistent with the rights above.");
            sb.AppendLine();

            if (input.IncludeSettingsSnapshot && input.Snapshot is { Available: true })
            {
                var s = input.Snapshot;
                sb.Append("For reference, my device's current relevant settings as read on ")
                  .AppendLine(s.ReadAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm"))
                  .AppendLine($"  - Sample submission consent level: {s.SubmitSamplesConsent} (0=prompt, 1=safe samples auto, 2=never, 3=all)")
                  .AppendLine($"  - Cloud-delivered protection (MAPS) reporting level: {s.MapsReporting} (0=off, 1=basic, 2=advanced)")
                  .AppendLine($"  - Windows diagnostic data level: {(s.AllowTelemetry?.ToString() ?? "Settings-controlled (no policy value)")}")
                  .AppendLine();
            }

            sb.Append("I understand you may need to verify my identity; I have provided my contact details")
              .AppendLine(" above and will supply reasonable additional verification on request. I am not acting")
              .AppendLine(" through an authorized agent.");
            sb.AppendLine();
            if (law.ResponseDays > 0)
            {
                sb.Append("Please respond within ").Append(law.ResponseDays)
                  .Append(" days as required by ").Append(law.Citation)
                  .AppendLine(". I reserve all rights under the statute, including its");
                sb.AppendLine("non-discrimination protections.");
            }
            else
            {
                sb.Append("Although my state may not impose a statutory response deadline for this request,")
                  .AppendLine(" I ask that you respond within 45 days as a matter of good practice.");
            }
            sb.AppendLine();
            sb.AppendLine("Sincerely,");
            sb.AppendLine();
            sb.Append(input.FullName);
            return sb.ToString();
        }

        // ── FOIA / Privacy Act letter ───────────────────────────────────────

        public static string BuildFoiaLetter(FoiaInput input)
        {
            var sb = new StringBuilder();
            sb.AppendLine(DateTime.Today.ToString("MMMM d, yyyy"));
            sb.AppendLine();
            sb.AppendLine("FOIA / Privacy Act Officer");
            sb.AppendLine(input.Agency?.Name ?? "[agency name]");
            sb.AppendLine();
            sb.Append(input.FullName).AppendLine();
            sb.AppendLine(input.Email);
            sb.AppendLine();
            sb.AppendLine("Re: Freedom of Information Act / Privacy Act Request");
            sb.AppendLine();
            sb.AppendLine("Dear FOIA Officer:");
            sb.AppendLine();
            sb.Append("Under the Freedom of Information Act, 5 U.S.C. § 552, and the Privacy Act of")
              .AppendLine(" 1974, 5 U.S.C. § 552a, I request copies of all records about ME held by your")
              .AppendLine(" agency concerning:")
              .AppendLine();
            sb.Append("  ").AppendLine(string.IsNullOrWhiteSpace(input.Description)
                ? "[describe the records you seek — e.g. any legal process, national security letters, or formal information requests served on Microsoft Corporation concerning my accounts, identifiers, or devices]"
                : input.Description);
            sb.AppendLine();
            sb.Append("I request a search of all reasonably locatable records, including electronic records")
              .AppendLine(" and cross-indexed files, for the period from the earliest date such records exist")
              .AppendLine(" through the date this request is processed.");
            sb.AppendLine();
            sb.Append("Fee category: I am an individual requester seeking these records for personal,")
              .AppendLine(" non-commercial use. Please notify me before incurring fees above $25.");
            if (input.FeeWaiver)
            {
                sb.Append("I additionally request a fee waiver: disclosure is in the public interest because it")
                  .AppendLine(" is likely to contribute significantly to public understanding of government")
                  .AppendLine(" surveillance and oversight activities (5 U.S.C. § 552(a)(4)(A)(iii)).");
            }
            sb.AppendLine();
            if (input.Expedited)
            {
                sb.Append("I request expedited processing under 5 U.S.C. § 552(a)(6)(E): [state your")
                  .AppendLine(" compelling need — e.g. imminent threat to life or physical safety, or urgency")
                  .AppendLine(" in informing the public about actual or alleged federal government activity].");
                sb.AppendLine();
            }
            sb.Append("As this request is made under both FOIA and the Privacy Act, please process it")
              .AppendLine(" under both statutes. If you deem any portion exempt from disclosure, please")
              .AppendLine(" release all reasonably segregable non-exempt portions and itemize the exemptions")
              .AppendLine(" claimed for withheld material, as required by 5 U.S.C. § 552(b).");
            sb.AppendLine();
            sb.Append("Please respond within the twenty-business-day statutory time limit")
              .AppendLine(" (5 U.S.C. § 552(a)(6)(A)(i)).");
            sb.AppendLine();
            sb.AppendLine("Sincerely,");
            sb.AppendLine();
            sb.Append(input.FullName);
            return sb.ToString();
        }

        // ── Local request tracker ───────────────────────────────────────────

        public sealed class RequestRecord
        {
            public Guid Id { get; set; } = Guid.NewGuid();
            public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
            /// <summary>"Corporate" or "FOIA".</summary>
            public string Kind { get; set; }
            public string Recipient { get; set; }
            public string Statute { get; set; }
            public int ResponseDays { get; set; }
            /// <summary>"Draft", "Sent", "Answered".</summary>
            public string Status { get; set; } = "Draft";
            public DateTime? SentUtc { get; set; }
            public DateTime? DueUtc { get; set; }
            public string LetterFile { get; set; }

            public string DueDisplay => Status == "Sent" && DueUtc is { } due
                ? due.ToLocalTime().ToString("yyyy-MM-dd")
                : "—";

            public string CreatedLocal => CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd");
        }

        private static string StorePath =>
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AutoScope", "privacy-requests.json");

        public static async Task<List<RequestRecord>> LoadRequestsAsync()
        {
            try
            {
                if (!File.Exists(StorePath)) return new List<RequestRecord>();
                await using var stream = File.OpenRead(StorePath);
                return await JsonSerializer.DeserializeAsync<List<RequestRecord>>(stream) ?? new List<RequestRecord>();
            }
            catch
            {
                return new List<RequestRecord>();
            }
        }

        public static async Task SaveRequestsAsync(IEnumerable<RequestRecord> records)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(StorePath));
            await using var stream = File.Create(StorePath);
            await JsonSerializer.SerializeAsync(stream, records.ToList(), new JsonSerializerOptions { WriteIndented = true });
        }
    }
}
