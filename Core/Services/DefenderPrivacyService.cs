using System;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AutoScope.Services
{
    /// <summary>
    /// Reads the Windows settings that decide what data Defender and Windows
    /// share with Microsoft — backing the Data &amp; Privacy tab. Read-only by
    /// design: changes go through Windows Security / Settings deep links (the
    /// supported place), because several of these values are Tamper- or
    /// policy-protected and Set-MpPreference is the wrong tool on builds
    /// where Tamper Protection blocks it.
    ///
    /// Surfaced state:
    ///   • SubmitSamplesConsent — when Defender uploads copies of suspicious
    ///     files (0 prompt, 1 safe samples auto [default], 2 never, 3 all)
    ///   • MAPSReporting — cloud-delivered protection membership
    ///     (0 off, 1 basic, 2 advanced)
    ///   • CloudBlockLevel — how aggressive cloud verdicts are
    ///   • AllowTelemetry — Windows diagnostic data level (0 security … 3 full)
    ///   • SmartScreen policy + Smart App Control state
    ///   • Management state (domain/MDM/Defender policy keys) — an org-managed
    ///     machine can own these settings over the user's head
    ///
    /// Same PowerShell plumbing as DefenderPreferencesService: one
    /// -EncodedCommand round trip, UTF-8 both ways, JSON back.
    /// </summary>
    public sealed class DefenderPrivacyService
    {
        public sealed class PrivacyState
        {
            public bool Available { get; set; }
            public string UnavailableReason { get; set; }

            public int SubmitSamplesConsent { get; set; } = 1;
            public int? PolicySubmitSamples { get; set; }
            public int MapsReporting { get; set; }
            public int? PolicyMapsReporting { get; set; }
            public int CloudBlockLevel { get; set; }

            public int? AllowTelemetry { get; set; }
            public int? PolicySmartScreen { get; set; }

            /// <summary>Smart App Control: -1 unknown, 0 off, 1 enforcement,
            /// 2 evaluation.</summary>
            public int SmartAppControl { get; set; } = -1;

            public bool DomainJoined { get; set; }
            public bool MdmEnrolled { get; set; }
            public bool DefenderPolicyManaged { get; set; }
            public bool OrgManaged => DomainJoined || MdmEnrolled || DefenderPolicyManaged;

            public DateTime ReadAtUtc { get; set; }
        }

        private const int TimeoutMs = 60_000;

        private const string Script = @"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function Reg($path, $name) {
    try { (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name } catch { $null }
}
try {
    $pref = Get-MpPreference
    $mdm = $false
    try {
        $mdm = [bool](Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
            Where-Object { $_.EnrollmentType -in 6,13 -and $_.ProviderID })
    } catch { }
    $telemetry = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry'
    if ($null -eq $telemetry) { $telemetry = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' 'AllowTelemetry' }
    [pscustomobject]@{
        ok          = ($null -ne $pref)
        samples     = $pref.SubmitSamplesConsent
        polSamples  = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SubmitSamplesConsent'
        maps        = $pref.MAPSReporting
        polMaps     = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SpyNetReporting'
        cloudBlock  = $pref.CloudBlockLevel
        telemetry   = $telemetry
        smartscreen = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
        sac         = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
        domain      = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain
        mdm         = $mdm
        polManaged  = [bool](Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender')
    } | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{ ok = $false; err = ('read failed: ' + $_.Exception.Message) } | ConvertTo-Json -Compress
}";

        public async Task<PrivacyState> GetStateAsync()
        {
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(Script));
            var psi = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };

            using var process = Process.Start(psi);
            string output = await process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(TimeoutMs))
            {
                try { process.Kill(); } catch { }
                return new PrivacyState
                {
                    Available = false,
                    UnavailableReason = "Reading the privacy settings timed out."
                };
            }

            try
            {
                using var doc = JsonDocument.Parse(output.Trim());
                return ParseState(doc.RootElement);
            }
            catch (JsonException)
            {
                return new PrivacyState
                {
                    Available = false,
                    UnavailableReason = "The privacy settings could not be read (another antivirus may be managing this machine)."
                };
            }
        }

        private static PrivacyState ParseState(JsonElement root)
        {
            var state = new PrivacyState { ReadAtUtc = DateTime.UtcNow };
            if (root is not { ValueKind: JsonValueKind.Object } ||
                !root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True)
            {
                state.UnavailableReason = GetString(root, "err")
                    ?? "Windows Defender privacy settings could not be read.";
                return state;
            }

            state.Available = true;
            state.SubmitSamplesConsent = GetInt(root, "samples", 1);
            state.PolicySubmitSamples = GetIntOrNull(root, "polSamples");
            state.MapsReporting = GetInt(root, "maps", 0);
            state.PolicyMapsReporting = GetIntOrNull(root, "polMaps");
            state.CloudBlockLevel = GetInt(root, "cloudBlock", 0);
            state.AllowTelemetry = GetIntOrNull(root, "telemetry");
            state.PolicySmartScreen = GetIntOrNull(root, "smartscreen");
            state.SmartAppControl = GetInt(root, "sac", -1);
            state.DomainJoined = GetBool(root, "domain");
            state.MdmEnrolled = GetBool(root, "mdm");
            state.DefenderPolicyManaged = GetBool(root, "polManaged");
            return state;
        }

        private static string GetString(JsonElement root, string property)
        {
            return root.ValueKind == JsonValueKind.Object &&
                   root.TryGetProperty(property, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString()
                : null;
        }

        private static int GetInt(JsonElement root, string property, int fallback)
        {
            if (root.ValueKind == JsonValueKind.Object &&
                root.TryGetProperty(property, out var v) && v.ValueKind == JsonValueKind.Number)
                return v.GetInt32();
            // PS booleans cross as true/false; absent stays at the fallback
            return fallback;
        }

        private static int? GetIntOrNull(JsonElement root, string property)
        {
            if (root.ValueKind == JsonValueKind.Object &&
                root.TryGetProperty(property, out var v) && v.ValueKind == JsonValueKind.Number)
                return v.GetInt32();
            if (root.ValueKind == JsonValueKind.Object &&
                root.TryGetProperty(property, out v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False)
                return v.ValueKind == JsonValueKind.True ? 1 : 0;
            return null;
        }

        private static bool GetBool(JsonElement root, string property)
        {
            return root.ValueKind == JsonValueKind.Object &&
                   root.TryGetProperty(property, out var v) && v.ValueKind == JsonValueKind.True;
        }
    }
}
