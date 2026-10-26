// F# port of Core\Services\SysmonInstallerService.cs (namespace AutoScope.Services)
// for the Engines library. The external-command contract is the contract:
// same sc.exe / wevtutil / reg.exe / Sysmon64.exe argument shapes, same
// exit-code and output-text decisions, same config XML.
//
// F# port notes (deviations forced by F#/C# interop, none behavioral):
//   • The C# helpers lived in AutoScope.Helpers.ProcessRunner, which is a
//     Core-assembly utility this engine does not reference; the two
//     members it used (RunWithDetails / RunWithDetailsAsync) are ported
//     verbatim as private members here (redirected stdout+stderr, no
//     shell, no window, null-char strip — the Sysinternals mojibake fix).
//   • C# `static readonly` TempDir/PendingRepairMarker became lazily
//     cached private members: the C# fields hardcoded
//     %TEMP%\AutoScope_Sysmon at type init; engines are app-agnostic, so
//     the folder name now derives from WatchConfig.Identity.Name, and
//     nothing identity-dependent runs at type-initialization time.
//   • Tuples are ValueTuple, matching the C# tuple returns; async members
//     are task { } with the same Task<(...)> shapes.

namespace AutoScope.Engines.Watch

open System
open System.Diagnostics
open System.Diagnostics.Eventing.Reader
open System.IO
open System.Linq
open System.Net.Http
open System.Threading.Tasks

/// <summary>
/// F# port of the C# SysmonInstallState enum — same names, same values.
/// </summary>
type SysmonInstallState =
    | Installed = 0
    | NotInstalled = 1
    | Inconsistent = 2

/// <summary>
/// Installs, repairs and configures Sysmon64 with the app's recommended
/// forensic config (process + network + DNS events), growing the
/// Operational channel so the archive's backfill has history to read.
/// F# port: member names, Task shapes and behavior as the C# original.
/// </summary>
type SysmonInstallerService() =

    static let SysmonDownloadUrl = "https://live.sysinternals.com/Sysmon64.exe"
    static let SysmonExeName = "Sysmon64.exe"
    static let ConfigFileName = "sysmon_config.xml"
    static let EventChannelName = "Microsoft-Windows-Sysmon/Operational"
    static let ProviderName = "Microsoft-Windows-Sysmon"

    // Sysmon's ETW provider GUID, used for its event-manifest registration
    static let SysmonProviderGuid = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"

    [<Literal>]
    static let ChannelMaxSizeBytesValue = 192L * 1024L * 1024L

    // F# port: C# hardcoded "AutoScope_Sysmon" under %TEMP% in two static
    // readonly fields. Same location and shape, but named after the
    // hosting app's identity — and resolved lazily so this type can be
    // touched before WatchConfig.Configure without a type-init failure.
    static let mutable tempDirCache: string = null

    static let tempDir () =
        if isNull tempDirCache then
            tempDirCache <- Path.Combine(Path.GetTempPath(), WatchConfig.Identity.Name + "_Sysmon")
        tempDirCache

    static let pendingRepairMarker () = Path.Combine(tempDir (), "repair_pending.flag")

    // ── ProcessRunner.RunWithDetails, verbatim (see header) ───────────

    static let stripNullChars (value: string) =
        // F# port: '\0' is not a valid F# escape — '\u0000' is the NUL char.
        if String.IsNullOrEmpty value || value.IndexOf('\u0000') < 0 then
            value
        else
            value.Replace("\u0000", "")

    static let runWithDetails (fileName: string) (arguments: string) : struct (string * string * int) =
        let proc_ =
            new Process(
                StartInfo = ProcessStartInfo(
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                )
            )

        proc_.Start() |> ignore
        let output = proc_.StandardOutput.ReadToEnd()
        let error = proc_.StandardError.ReadToEnd()
        proc_.WaitForExit()
        struct (stripNullChars output, stripNullChars error, proc_.ExitCode)

    static let runWithDetailsAsync (fileName: string) (arguments: string) : Task<ValueTuple<string, string, int>> =
        Task.Run(fun () -> runWithDetails fileName arguments)

    /// <summary>
    /// The Operational channel defaults to 64 MB. On a busy dev box the
    /// app has measured ~15,000 events/hour — the default wraps in ~4
    /// hours, silently breaking "every spawn retroactively traceable"
    /// for anything older than a lunch break (an overnight incident is
    /// already gone by morning triage). 3× = 192 MB buys roughly half a
    /// day of history at that rate; growing a live channel keeps every
    /// event already in it.
    /// F# port: the C# `public const long` is a static property backed by
    /// a private [<Literal>] — F# classes cannot emit const fields; the
    /// value (192 MB) is unchanged.
    /// </summary>
    static member ChannelMaxSizeBytes = ChannelMaxSizeBytesValue

    member _.IsSysmonInstalled() : bool =
        // Sysmon registers a "Sysmon64" service on install; the exe on disk
        // alone is not proof (a failed install leaves it behind)
        let struct (_, _, exitCode) = runWithDetails "sc.exe" "query Sysmon64"
        exitCode = 0

    /// <summary>
    /// Distinguishes a clean "never installed" machine from one stuck with
    /// leftovers of a failed install, which makes every "-i" attempt abort
    /// with "wevtutil.exe returned failure / Event manifest installation failed".
    /// </summary>
    member this.DetectInstallState() : SysmonInstallState =
        if this.IsSysmonInstalled() then
            // Service present but its event channel unreadable = broken manifest
            if SysmonInstallerService.isEventChannelHealthy () then
                SysmonInstallState.Installed
            else
                SysmonInstallState.Inconsistent
        else
            let installedExe =
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), SysmonExeName)

            if File.Exists installedExe then SysmonInstallState.Inconsistent
            elif SysmonInstallerService.isProviderRegistered () then SysmonInstallState.Inconsistent
            else SysmonInstallState.NotInstalled

    /// <summary>
    /// Repairs an inconsistent install: removes leftovers, reinstalls and
    /// verifies. When the stale event-manifest registration can only be
    /// cleared by restarting Windows, RebootRequired is true and a pending
    /// marker is written so the next startup finishes and verifies the repair.
    /// </summary>
    member _.RepairAsync() : Task<ValueTuple<bool, string, bool>> =
        task {
            try
                let! exePath = SysmonInstallerService.ensureSysmonDownloaded ()
                let! configPath = SysmonInstallerService.writeConfig ()

                SysmonInstallerService.cleanupStaleInstall exePath

                let! struct (output, error, exitCode) =
                    runWithDetailsAsync exePath $"-i \"{configPath}\" -accepteula"

                if exitCode = 0 then
                    SysmonInstallerService.deletePendingRepairMarker ()
                    SysmonInstallerService.EnsureChannelSize () |> ignore
                    return struct (true, String.Empty, false)
                else
                    let details = $"Exit code: {exitCode}. Output: {output}. Error: {error}"

                    if (output + " " + error).IndexOf("Event manifest installation failed", StringComparison.OrdinalIgnoreCase) >= 0 then
                        // The stale manifest registration is held by the event log
                        // service and only a restart flushes it; the install is then
                        // retried and verified automatically on startup
                        SysmonInstallerService.writePendingRepairMarker details
                        return struct (false, details, true)
                    else
                        return struct (false, details, false)
            with ex ->
                Debug.WriteLine($"SysmonInstallerService Error: {ex.Message}")
                return struct (false, ex.Message, false)
        }

    /// <summary>
    /// Called on app startup after a repair restart: reinstalls Sysmon and
    /// verifies the service and its event channel. Message is null when no
    /// repair was pending.
    /// </summary>
    member this.CompletePendingRepairIfAnyAsync() : Task<ValueTuple<bool, string>> =
        task {
            if not (File.Exists(pendingRepairMarker ())) then
                return struct (false, null)
            else
                SysmonInstallerService.deletePendingRepairMarker ()

                try
                    let! exePath = SysmonInstallerService.ensureSysmonDownloaded ()
                    let! configPath = SysmonInstallerService.writeConfig ()

                    let! struct (output, error, exitCode) =
                        runWithDetailsAsync exePath $"-i \"{configPath}\" -accepteula"

                    if exitCode <> 0 then
                        return struct (false, $"Exit code: {exitCode}. Output: {output}. Error: {error}")
                    elif not (this.IsSysmonInstalled()) then
                        return struct (false, "Sysmon setup reported success but the Sysmon64 service is not present.")
                    elif not (SysmonInstallerService.isEventChannelHealthy ()) then
                        return struct (false, "The Sysmon64 service is installed but its event channel did not register correctly.")
                    else
                        SysmonInstallerService.EnsureChannelSize () |> ignore
                        return struct (true, $"Sysmon64 service installed and event channel '{EventChannelName}' is healthy.")
                with ex ->
                    return struct (false, ex.Message)
        }

    member _.InstallAndConfigureAsync() : Task<ValueTuple<bool, string>> =
        task {
            try
                let! exePath = SysmonInstallerService.ensureSysmonDownloaded ()
                let! configPath = SysmonInstallerService.writeConfig ()

                // Clear any leftovers of previous failed installs
                SysmonInstallerService.cleanupStaleInstall exePath

                // -i: Install, -accepteula: self-explanatory, -c: use config
                let! struct (output, error, exitCode) =
                    runWithDetailsAsync exePath $"-i \"{configPath}\" -accepteula"

                if exitCode = 0 then
                    SysmonInstallerService.EnsureChannelSize () |> ignore
                    return struct (true, String.Empty)
                else
                    return struct (false, $"Exit code: {exitCode}. Output: {output}. Error: {error}")
            with ex ->
                Debug.WriteLine($"SysmonInstallerService Error: {ex.Message}")
                return struct (false, ex.Message)
        }

    static member private ensureSysmonDownloaded () : Task<string> =
        task {
            if not (Directory.Exists(tempDir ())) then Directory.CreateDirectory(tempDir ()) |> ignore

            let exePath = Path.Combine(tempDir (), SysmonExeName)

            if not (File.Exists exePath) then
                use client = new HttpClient()
                let! data = client.GetByteArrayAsync(SysmonDownloadUrl)
                do! File.WriteAllBytesAsync(exePath, data)

            return exePath
        }

    static member private writeConfig () : Task<string> =
        // Recommended config for post-hoc process/network forensics:
        //   ProcessCreate   (ID 1)  every launch with full command line + parent image
        //   NetworkConnect  (ID 3)  every outbound connection with image + PID
        //   DnsQuery       (ID 22)  hostname lookups, ties IPs to names after the fact
        // An empty onmatch="exclude" rule is the Sysmon idiom for "capture
        // everything"; noise filtering happens app-side (ignore lists,
        // cloud-IP filter) so the raw log stays complete.
        let configXml = @"
<Sysmon schemaversion=""4.82"">
  <EventFiltering>
    <RuleGroup name="""" groupRelation=""or"">
      <ProcessCreate onmatch=""exclude""/>
      <NetworkConnect onmatch=""exclude""/>
      <DnsQuery onmatch=""exclude""/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>"

        task {
            let configPath = Path.Combine(tempDir (), ConfigFileName)
            do! File.WriteAllTextAsync(configPath, configXml)
            return configPath
        }

    /// <summary>
    /// Applies the recommended config to an already-installed Sysmon
    /// without reinstalling (Sysmon64 -c). Needed when an install made
    /// with an older config (e.g. network-only) should start capturing
    /// process creations and DNS queries too. Call only when Sysmon is
    /// actually installed — otherwise the call just fails.
    /// </summary>
    member _.UpdateConfigAsync() : Task<ValueTuple<bool, string>> =
        task {
            try
                // Prefer the installed exe; fall back to the downloaded copy
                let installedExe =
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), SysmonExeName)

                let! exePath =
                    if File.Exists installedExe then
                        Task.FromResult installedExe
                    else
                        SysmonInstallerService.ensureSysmonDownloaded ()

                let! configPath = SysmonInstallerService.writeConfig ()
                let! struct (output, error, exitCode) =
                    runWithDetailsAsync exePath $"-c \"{configPath}\" -accepteula"

                if exitCode = 0 then
                    return struct (true, String.Empty)
                else
                    return struct (false, $"Exit code: {exitCode}. Output: {output}. Error: {error}")
            with ex ->
                return struct (false, ex.Message)
        }

    static member private isProviderRegistered () : bool =
        let struct (output, _, _) = runWithDetails "wevtutil.exe" "ep"
        output.Split('\n') |> Array.exists (fun line -> line.Trim() = ProviderName)

    static member private isEventChannelHealthy () : bool =
        let struct (_, _, exitCode) = runWithDetails "wevtutil.exe" $"gl \"{EventChannelName}\""
        exitCode = 0

    /// <summary>
    /// Raises the Sysmon Operational channel's max size to
    /// ChannelMaxSizeBytes (3× the 64 MB default) so the forensic
    /// history survives more than a few hours on an active machine.
    /// Best-effort: SaveChanges needs elevation; false just means the
    /// default (shorter) retention stands — it never fails an install.
    /// Called after every successful install/repair/verify and from the
    /// startup diagnostics pass for machines where Sysmon predates this.
    /// </summary>
    static member EnsureChannelSize() : bool =
        try
            let config = new EventLogConfiguration(EventChannelName)
            if config.MaximumSizeInBytes >= SysmonInstallerService.ChannelMaxSizeBytes then true
            else
                config.MaximumSizeInBytes <- SysmonInstallerService.ChannelMaxSizeBytes
                config.SaveChanges()
                true
        with _ ->
            // Channel missing, or session not elevated — degrade, never guess
            false

    /// <summary>
    /// Removes leftovers of a previous failed/partial install. A half-installed
    /// Sysmon leaves its event-manifest provider registered; until that is gone,
    /// the next "-i" aborts with "wevtutil.exe returned failure /
    /// Event manifest installation failed".
    /// </summary>
    static member private cleanupStaleInstall (exePath: string) : unit =
        // Stops and removes the Sysmon64 service/driver and uninstalls the
        // event manifest; a no-op when Sysmon is not installed
        runWithDetails exePath "-u force" |> ignore

        // Orphaned provider registration (registry view) left behind when
        // a manifest install failed midway
        runWithDetails "reg.exe"
            (sprintf "delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Winevt\\Publishers\\%s\" /f"
                SysmonProviderGuid)
        |> ignore

        try
            let installedExe =
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), SysmonExeName)

            if File.Exists installedExe then File.Delete installedExe
        with
        | :? IOException -> ()
        | :? UnauthorizedAccessException -> ()

    static member private writePendingRepairMarker (details: string) : unit =
        try
            if not (Directory.Exists(tempDir ())) then Directory.CreateDirectory(tempDir ()) |> ignore

            // F# port: the C# interpolated $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}"
            // written as an explicit ToString — same invariant-format output.
            let stamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")

            File.WriteAllText(
                pendingRepairMarker (),
                stamp + Environment.NewLine + details
            )
        with _ ->
            // marker is best-effort
            ()

    static member private deletePendingRepairMarker () : unit =
        try
            if File.Exists(pendingRepairMarker ()) then File.Delete(pendingRepairMarker ())
        with _ ->
            ()
