using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AutoScope.Services
{
    /// <summary>
    /// Reads — and where safe adjusts — Windows Defender scan preferences via
    /// the supported MpCmdlet surface (Get/Set-MpPreference, Get-MpComputerStatus),
    /// for the Settings tab's Defender card:
    ///   • ScanAvgCPULoadFactor — average-CPU cap for scans (5–100, default 50)
    ///   • ScanOnlyIfIdleEnabled — scheduled scans wait for an idle machine
    ///
    /// Exclusions are READ-ONLY here by design: adding antivirus exclusions is
    /// a classic malware technique, so AutoScope surfaces them for visibility
    /// but never writes them — Windows Security is the supported place to add.
    /// All state lives in Defender itself; nothing is persisted locally.
    ///
    /// Scripts run through powershell.exe -EncodedCommand (base64 UTF-16LE)
    /// so quoting never breaks, with [Console]::OutputEncoding set to UTF-8 on
    /// the script side and matching decoding here so non-ASCII exclusion paths
    /// survive the round trip.
    /// </summary>
    public sealed class DefenderPreferencesService
    {
        public sealed class DefenderState
        {
            public bool Available { get; set; }
            public string UnavailableReason { get; set; }
            public int ScanCpuLoadFactor { get; set; }
            public bool ScanOnlyIfIdle { get; set; }
            public bool? RealTimeProtection { get; set; }
            public bool? TamperProtected { get; set; }
            public string RunningMode { get; set; }
            public string ProductVersion { get; set; }
            public string EngineVersion { get; set; }
            public string SignatureVersion { get; set; }
            public DateTime? SignatureLastUpdatedUtc { get; set; }
            public DateTime? QuickScanStartUtc { get; set; }
            public DateTime? QuickScanEndUtc { get; set; }
            public DateTime? FullScanStartUtc { get; set; }
            public DateTime? FullScanEndUtc { get; set; }

            /// <summary>The AvgCpuLoadFactor Group Policy value when one is set —
            /// the cap is policy-owned in that case (tamper-blocked builds route
            /// through it). Null when no policy exists.</summary>
            public int? PolicyCpuLoadFactor { get; set; }

            /// <summary>The ScanOnlyIfIdle Group Policy value when one is set.</summary>
            public bool? PolicyScanOnlyIfIdle { get; set; }
            public List<string> ExclusionPaths { get; } = new();
            public List<string> ExclusionProcesses { get; } = new();
            public List<string> ExclusionExtensions { get; } = new();

            /// <summary>True when Defender returned its "N/A: Must be an administrator
            /// to view exclusions" sentinel instead of the lists.</summary>
            public bool ExclusionsRequireElevation { get; set; }
        }

        public sealed class SetResult
        {
            public bool Ok { get; set; }
            public string Error { get; set; }
            public DefenderState Fresh { get; set; }   // state re-read after the set

            /// <summary>True when the change landed through the Group Policy
            /// registry fallback rather than Set-MpPreference (Tamper Protection
            /// blocks direct preference writes on some Windows builds).</summary>
            public bool ViaPolicy { get; set; }
        }

        private const int TimeoutMs = 60_000; // first Get-MpComputerStatus can be slow; tamper-blocked sets are skipped, not waited out

        // PS 5.1's ConvertTo-Json collapses 0/1-element arrays to scalars, so
        // lists cross the boundary as unit-separator (\u001f) joined strings.
        // ProgressPreference suppresses the CLIXML progress records the cmdlets
        // emit while warming up (they would pollute the redirected streams).
        private const string Prologue = @"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$setErr = $null
$viaPolicy = $false
";

        private const string ReadTail = @"try {
    $pref = Get-MpPreference
    $stat = Get-MpComputerStatus
    $sep  = [string][char]31
    function Fmt($d) { if ($d) { $d.ToUniversalTime().ToString('u') } else { $null } }
    $policyCpu = $null
    try { $policyCpu = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -Name AvgCpuLoadFactor -ErrorAction SilentlyContinue).AvgCpuLoadFactor } catch { }
    $policyIdle = $null
    try { $policyIdle = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -Name ScanOnlyIfIdle -ErrorAction SilentlyContinue).ScanOnlyIfIdle } catch { }
    [pscustomobject]@{
        ok        = ($null -ne $pref -and $null -ne $stat)
        setErr    = $setErr
        viaPolicy = $viaPolicy
        cpu       = $pref.ScanAvgCPULoadFactor
        policyCpu = $policyCpu
        idle      = [bool]$pref.ScanOnlyIfIdleEnabled
        policyIdle= $policyIdle
        rtp       = $stat.RealTimeProtectionEnabled
        tamper    = $stat.IsTamperProtected
        mode      = $stat.AMRunningMode
        product   = $stat.AMProductVersion
        engine    = $stat.AMEngineVersion
        sig       = $stat.AntivirusSignatureVersion
        sigTime   = Fmt $stat.AntivirusSignatureLastUpdated
        qStart    = Fmt $stat.QuickScanStartTime
        qEnd      = Fmt $stat.QuickScanEndTime
        fStart    = Fmt $stat.FullScanStartTime
        fEnd      = Fmt $stat.FullScanEndTime
        paths     = (@($pref.ExclusionPath     | Where-Object { $_ }) -join $sep)
        procs     = (@($pref.ExclusionProcess  | Where-Object { $_ }) -join $sep)
        exts      = (@($pref.ExclusionExtension| Where-Object { $_ }) -join $sep)
    } | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{ ok = $false; setErr = ('read failed: ' + $_.Exception.Message) } | ConvertTo-Json -Compress
}";

        public Task<DefenderState> GetStateAsync() =>
            RunScriptAsync(Prologue + ReadTail, root => ParseState(root, setErr: null));

        /// <summary>
        /// Sets the scan CPU cap. When Tamper Protection is on we go straight
        /// to the Group Policy value ("Specify the maximum percentage of CPU
        /// utilization during a scan": HKLM\SOFTWARE\Policies\Microsoft\Windows
        /// Defender\Scan\AvgCpuLoadFactor) — Set-MpPreference is blocked there
        /// and its refusal is SLOW (it hangs past any sane timeout before
        /// erroring), so calling it first just burns half a minute. Tamper off:
        /// direct write first, policy registry as the automatic fallback.
        /// Defender picks policy changes up on its next config refresh.
        /// </summary>
        public Task<SetResult> SetScanCpuLoadFactorAsync(int percent, bool preferPolicy = false)
        {
            int clamped = Math.Clamp(percent, 5, 100);
            string direct = $"try {{ Set-MpPreference -ScanAvgCPULoadFactor {clamped} }} catch {{ $setErr = $_.Exception.Message }}`n";
            string policy = PolicyWriteBlock("AvgCpuLoadFactor", clamped.ToString(CultureInfo.InvariantCulture));
            return RunSetAsync(preferPolicy ? policy : direct + "if ($setErr) {`n" + policy + "`n}`n");
        }

        /// <summary>
        /// Sets idle-only scanning. Same routing as the CPU cap: policy-first
        /// under Tamper Protection (ADMX value ScanOnlyIfIdle), direct
        /// Set-MpPreference with policy fallback otherwise.
        /// </summary>
        public Task<SetResult> SetScanOnlyIfIdleAsync(bool enabled, bool preferPolicy = false)
        {
            string direct = $"try {{ Set-MpPreference -ScanOnlyIfIdleEnabled ${enabled} }} catch {{ $setErr = $_.Exception.Message }}`n";
            string policy = PolicyWriteBlock("ScanOnlyIfIdle", enabled ? "1" : "0");
            return RunSetAsync(preferPolicy ? policy : direct + "if ($setErr) {`n" + policy + "`n}`n");
        }

        /// <summary>Writes one DWORD under the Defender Scan policy key, creating the key.</summary>
        private static string PolicyWriteBlock(string name, string value) =>
            "try {`n" +
            "    $key = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan'`n" +
            "    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }`n" +
           $"    New-ItemProperty -Path $key -Name '{name}' -Value {value} -PropertyType DWord -Force | Out-Null`n" +
            "    $setErr = $null`n" +
            "    $viaPolicy = $true`n" +
            "} catch { $setErr = ('policy write failed: ' + $_.Exception.Message) }`n";

        /// <summary>
        /// Launches a scan in a detached PowerShell child so this call returns
        /// immediately — Start-MpScan blocks until the scan completes (a quick
        /// scan can run 30s+, a full scan hours) which would blow the read
        /// round-trip timeout. Progress arrives as Defender events (EID 1000
        /// started / 1001 finished / 1002 stopped), surfaced by the monitoring
        /// service.
        /// </summary>
        public Task<SetResult> TriggerScanAsync(string scanType) =>
            scanType is not ("QuickScan" or "FullScan")
                ? Task.FromResult(new SetResult { Ok = false, Error = $"'{scanType}' is not a supported scan type" })
                : RunSetAsync($"try {{ Start-Process powershell.exe -ArgumentList '-NoProfile','-Command','Start-MpScan -ScanType {scanType}' -WindowStyle Hidden }} catch {{ $setErr = $_.Exception.Message }}`n");

        public Task<SetResult> UpdateSignaturesAsync() =>
            RunSetAsync("try { Start-Process powershell.exe -ArgumentList '-NoProfile','-Command','Update-MpSignature' -WindowStyle Hidden } catch { $setErr = $_.Exception.Message }`n");

        private static async Task<SetResult> RunSetAsync(string setLine)
        {
            string setErr = null;
            bool viaPolicy = false;
            DefenderState fresh = await RunScriptAsync(Prologue + setLine + ReadTail, root =>
            {
                string reported = GetString(root, "setErr");
                setErr = string.IsNullOrEmpty(reported) ? null : reported;
                viaPolicy = root is { ValueKind: JsonValueKind.Object } &&
                            root.Value.TryGetProperty("viaPolicy", out var v) &&
                            v.ValueKind == JsonValueKind.True;
                return ParseState(root, setErr);
            });
            return new SetResult
            {
                Ok = fresh.Available && setErr == null,
                Error = setErr,
                Fresh = fresh,
                ViaPolicy = viaPolicy && setErr == null
            };
        }

        // -----------------------------------------------------------------------
        // PowerShell plumbing
        // -----------------------------------------------------------------------

        private static async Task<T> RunScriptAsync<T>(string script, Func<JsonElement?, T> parse)
        {
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
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
                return parse(null);
            }

            try
            {
                using var doc = JsonDocument.Parse(output.Trim());
                return parse(doc.RootElement);
            }
            catch (JsonException)
            {
                return parse(null);
            }
        }

        // -----------------------------------------------------------------------
        // JSON → state
        // -----------------------------------------------------------------------

        private static string GetString(JsonElement? root, string property)
        {
            if (root is not { ValueKind: JsonValueKind.Object }) return null;
            return root.Value.TryGetProperty(property, out var value) &&
                   value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
        }

        /// <summary>Parses a PS 'u'-format UTC timestamp ("yyyy-MM-dd HH:mm:ssZ").</summary>
        private static DateTime? GetUtcDate(JsonElement root, string property)
        {
            string raw = GetString(root, property);
            return DateTime.TryParse(raw, System.Globalization.CultureInfo.InvariantCulture,
                       System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                       out DateTime parsed)
                ? parsed
                : null;
        }

        private static DefenderState ParseState(JsonElement? root, string setErr)
        {
            var state = new DefenderState();
            if (root is not { ValueKind: JsonValueKind.Object } ||
                !root.Value.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
            {
                state.Available = false;
                string err = GetString(root, "setErr");
                if (string.IsNullOrEmpty(err)) err = setErr;
                state.UnavailableReason = string.IsNullOrWhiteSpace(err)
                    ? "Windows Defender preferences could not be read (another antivirus may be managing this machine, or the Defender module is absent)."
                    : err;
                return state;
            }

            var o = root.Value;
            state.Available = true;
            if (o.TryGetProperty("cpu", out var cpu) && cpu.ValueKind == JsonValueKind.Number)
                state.ScanCpuLoadFactor = cpu.GetInt32();  // raw: 0 means "no cap" on some builds
            if (o.TryGetProperty("idle", out var idle) && idle.ValueKind == JsonValueKind.True)
                state.ScanOnlyIfIdle = true;
            if (o.TryGetProperty("rtp", out var rtp) && rtp.ValueKind is JsonValueKind.True or JsonValueKind.False)
                state.RealTimeProtection = rtp.GetBoolean();
            if (o.TryGetProperty("tamper", out var tamper) && tamper.ValueKind is JsonValueKind.True or JsonValueKind.False)
                state.TamperProtected = tamper.GetBoolean();

            state.RunningMode = GetString(o, "mode");
            state.ProductVersion = GetString(o, "product");
            state.EngineVersion = GetString(o, "engine");
            state.SignatureVersion = GetString(o, "sig");
            state.SignatureLastUpdatedUtc = GetUtcDate(o, "sigTime");
            state.QuickScanStartUtc = GetUtcDate(o, "qStart");
            state.QuickScanEndUtc = GetUtcDate(o, "qEnd");
            state.FullScanStartUtc = GetUtcDate(o, "fStart");
            state.FullScanEndUtc = GetUtcDate(o, "fEnd");
            if (o.TryGetProperty("policyCpu", out var policyCpu) && policyCpu.ValueKind == JsonValueKind.Number)
                state.PolicyCpuLoadFactor = policyCpu.GetInt32();
            if (o.TryGetProperty("policyIdle", out var policyIdle) &&
                policyIdle.ValueKind is JsonValueKind.True or JsonValueKind.False or JsonValueKind.Number)
                state.PolicyScanOnlyIfIdle = policyIdle.ValueKind == JsonValueKind.True ||
                                             (policyIdle.ValueKind == JsonValueKind.Number && policyIdle.GetInt32() != 0);

            FillList(o, "paths", state.ExclusionPaths);
            FillList(o, "procs", state.ExclusionProcesses);
            FillList(o, "exts", state.ExclusionExtensions);
            if (HasElevationSentinel(state))
            {
                state.ExclusionsRequireElevation = true;
                state.ExclusionPaths.Clear();
                state.ExclusionProcesses.Clear();
                state.ExclusionExtensions.Clear();
            }
            return state;
        }

        private static void FillList(JsonElement root, string property, List<string> target)
        {
            if (!root.TryGetProperty(property, out var value)) return;
            string joined = value.ValueKind == JsonValueKind.String ? value.GetString() : null;
            if (string.IsNullOrEmpty(joined)) return;
            target.AddRange(joined.Split('\u001f')
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase));
        }

        /// <summary>True when Defender answered with its elevation sentinel
        /// ("N/A: Must be an administrator to view exclusions") — the app runs
        /// elevated so this is rare, but the card degrades honestly if seen.</summary>
        private static bool HasElevationSentinel(DefenderState state) =>
            state.ExclusionPaths.Concat(state.ExclusionProcesses)
                .Concat(state.ExclusionExtensions)
                .Any(s => s.StartsWith("N/A:", StringComparison.OrdinalIgnoreCase));
    }
}
