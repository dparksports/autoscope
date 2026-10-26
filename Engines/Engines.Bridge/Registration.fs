// F# port of Core\Services\McpClientRegistration.cs (AutoScope.Services →
// AutoScope.Engines.Bridge). Faithful by contract: same client catalog,
// same upsert/backup/verify flow, same versioned-proxy install and the
// double DOTNET_ROOT preflight. The C# hardcoded the app's MCP entry id
// ("autoscope"), the proxy exe name ("AutoScope.AgentProxy.exe") and the
// tools root (%LOCALAPPDATA%\AutoScope\tools) — none of those live in
// AppIdentity, so the ported McpClientCatalog takes (identity, mcpId,
// proxyExeName) from the app; zero app names inside.
namespace AutoScope.Engines.Bridge

open System
open System.Collections.Generic
open System.Diagnostics
open System.IO
open System.Text.Json
open System.Text.Json.Nodes
open System.Threading.Tasks
open AutoScope.Engines.Core

/// <summary>
/// One MCP client the app knows how to register its server into, in one
/// click from the Be My Guest tab. F# port: the C#'s public fields are
/// properties now (same names — C# object initializers read the same);
/// everything else unchanged.
/// </summary>
type McpClientRegistration() =
    /// <summary>stable id (button Tag)</summary>
    member val Id: string = null with get, set
    /// <summary>button label</summary>
    member val DisplayName: string = null with get, set
    /// <summary>user-scope config file (may not exist yet)</summary>
    member val ConfigPath: string = null with get, set
    /// <summary>path to the servers map inside the file, '/'-separated:
    /// "mcp/servers" (ZCode), "servers" (VS Code), "mcpServers" (most)</summary>
    member val RootKeyPath: string = null with get, set
    /// <summary>VS Code entries want "type": "stdio"</summary>
    member val IncludeType = false with get, set
    /// <summary>existence probe for the client's install</summary>
    member val DetectDir: string = null with get, set
    /// <summary>appended to the success dialog, may be null</summary>
    member val Note: string = null with get, set

/// <summary>
/// F# port of the C# static McpClientCatalog, now an instance class —
/// the entry id, proxy exe name and tools root come from the constructor
/// instead of being hardcoded. Members match the C# names:
/// Catalog, IsDetected, Register, UpsertEntry, ResolveAndInstallProxy,
/// PreflightProxy.
/// </summary>
type McpClientCatalog (identity: AppIdentity, mcpId: string, proxyExeName: string) as this =

    // ── client catalog ────────────────────────────────────────────────
    // User-scope only (per-repo/project scopes are deliberately out of
    // scope here — 'Copy MCP config' covers them). Paths verified against
    // each client's current docs; see the Notes for known drift.

    // F# port: the C# used object initializers on public fields; this
    // local builder spells the same rows out (names/values unchanged).
    let client id displayName configPath rootKeyPath includeType detectDir note =
        let c = McpClientRegistration()
        c.Id <- id
        c.DisplayName <- displayName
        c.ConfigPath <- configPath
        c.RootKeyPath <- rootKeyPath
        c.IncludeType <- includeType
        c.DetectDir <- detectDir
        c.Note <- note
        c

    let catalog: IReadOnlyList<McpClientRegistration> =
        let userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
        let appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
        ResizeArray<McpClientRegistration>(
            [
                client "zcode" "ZCode"
                    (Path.Combine(userProfile, ".zcode", "cli", "config.json"))
                    "mcp/servers" false
                    (Path.Combine(userProfile, ".zcode")) null
                client "cursor" "Cursor"
                    (Path.Combine(userProfile, ".cursor", "mcp.json"))
                    "mcpServers" false
                    (Path.Combine(userProfile, ".cursor")) null
                client "windsurf" "Windsurf"
                    (Path.Combine(userProfile, ".codeium", "windsurf", "mcp_config.json"))
                    "mcpServers" false
                    (Path.Combine(userProfile, ".codeium", "windsurf")) null
                client "vscode" "VS Code"
                    (Path.Combine(appData, "Code", "User", "mcp.json"))
                    "servers" true
                    (Path.Combine(appData, "Code", "User"))
                    "In VS Code, run 'Developer: Reload Window' (or restart it) to pick up the new server."
                client "claude-desktop" "Claude Desktop"
                    (Path.Combine(appData, "Claude", "claude_desktop_config.json"))
                    "mcpServers" false
                    (Path.Combine(appData, "Claude")) null
                client "gemini" "Gemini Antigravity"
                    (Path.Combine(userProfile, ".gemini", "config", "mcp_config.json"))
                    "mcpServers" false
                    (Path.Combine(userProfile, ".gemini"))
                    ("Some Antigravity CLI versions read %USERPROFILE%\\.gemini\\antigravity-cli\\mcp_config.json " +
                     "instead — if the CLI doesn't pick the server up, copy the file there too.")
            ]) :> IReadOnlyList<McpClientRegistration>

    // ── proxy install helpers ─────────────────────────────────────────
    // (F# port: these were private statics after the registration members
    // in the C#; F# wants every let before every member, so they live up
    // here with their WHY comments.)

    // The proxy ships as a self-contained single-file exe (release.ps1
    // publishes it into the zip's tools\AgentProxy\): the runtime is
    // bundled, so no framework lookup happens at spawn time and a client
    // that exports its own DOTNET_ROOT (desktop MCP clients bundling an
    // older .NET do this) cannot break it. The framework-dependent
    // 4-file set this class used to copy is legacy — still honored as a
    // previously-installed fallback, never written anew.

    // F# port: the C# hardcoded the four AutoScope.AgentProxy file names;
    // they derive from proxyExeName now.
    let legacyProxyFiles =
        let baseName =
            if proxyExeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            then proxyExeName.Substring(0, proxyExeName.Length - 4)
            else proxyExeName
        [| proxyExeName
           baseName + ".dll"
           baseName + ".runtimeconfig.json"
           baseName + ".deps.json" |]

    // F# port: %LOCALAPPDATA%\AutoScope\tools → identity.DataRoot\tools.
    let toolsRoot = Path.Combine(identity.DataRoot, "tools")

    // A versioned install counts as complete only when its marker file
    // exists — the marker is written last, after every file copied
    // cleanly, so a half-copied folder is never handed to a client.
    let versionedInstallComplete (dir: string) =
        File.Exists(Path.Combine(dir, "proxy.installed"))

    let legacyComplete (dir: string) =
        legacyProxyFiles |> Array.forall (fun f -> File.Exists(Path.Combine(dir, f)))

    let tryParseVersion (versionedDir: string) =
        try Version(Path.GetFileName(versionedDir).Substring(1))
        with _ -> Version(0, 0)

    let appVersion () =
        try
            match FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion with
            | null -> "0"
            | v -> v
        with _ -> "0"

    let tryDeleteDir (dir: string) =
        try if Directory.Exists(dir) then Directory.Delete(dir, recursive = true) with _ -> ()

    let tryDeleteFile (file: string) =
        try if File.Exists(file) then File.Delete(file) with _ -> ()

    member _.Catalog = catalog

    // ── registration ──────────────────────────────────────────────────

    member _.IsDetected (client: McpClientRegistration) =
        Directory.Exists(client.DetectDir)

    /// <summary>
    /// Writes the MCP entry into the client's config: parse the existing
    /// file, back it up, upsert only our entry, verify by re-reading. A
    /// malformed or foreign-shaped file is never clobbered.
    /// </summary>
    member _.Register (client: McpClientRegistration, proxyPath: string) : bool * string =
        try
            let entry = JsonObject()
            if client.IncludeType then entry["type"] <- JsonValue.Create("stdio")
            entry["command"] <- JsonValue.Create(proxyPath)
            entry["args"] <- JsonArray()
            let ok, error = this.UpsertEntry(client.ConfigPath, client.RootKeyPath, mcpId, entry)
            if not ok then (false, error)
            else
                let mutable message =
                    "Registered the '" + mcpId + "' MCP server for " + client.DisplayName + " (user scope):\n" +
                    client.ConfigPath +
                    "\n\nProxy: " + proxyPath +
                    "\n\nNew " + client.DisplayName + " sessions will auto-connect it. Tools answer with " +
                    "setup guidance whenever no AI session is active here."
                if not (String.IsNullOrEmpty client.Note) then message <- message + "\n\n" + client.Note
                (true, message)
        with ex ->
            (false, "Could not update the " + client.DisplayName + " config:\n" + ex.Message +
                    "\n\nUse 'Copy MCP config' and add the entry by hand.")

    /// <summary>
    /// Shared merge: idempotent, backup-before-write, verify-after-write.
    /// rootKeyPath is '/'-separated ("mcp/servers" for ZCode, "servers"
    /// for VS Code, "mcpServers" for most) — missing levels are created,
    /// non-object levels abort instead of being overwritten.
    /// </summary>
    member internal _.UpsertEntry (configPath: string, rootKeyPath: string, serverName: string,
                                   entry: JsonObject) : bool * string =
        let mutable root: JsonObject = null
        let mutable refusal: string = null
        if File.Exists(configPath) then
            let text = File.ReadAllText(configPath)
            if not (String.IsNullOrWhiteSpace text) then
                let parsed =
                    try
                        match JsonNode.Parse(text) with
                        | :? JsonObject as o -> Some o
                        | _ -> None
                    with :? JsonException -> None // malformed → refuse below, never clobber
                match parsed with
                | Some o ->
                    root <- o
                    File.WriteAllText(configPath + "." + mcpId + "-backup", text) // revert is a rename away
                | None ->
                    refusal <- "The config is not a readable JSON object — not touching it:\n" + configPath +
                               "\n\nUse 'Copy MCP config' and add the entry by hand."
        if not (isNull refusal) then (false, refusal)
        else
            if isNull root then root <- JsonObject()

            let keys = rootKeyPath.Split('/')
            let mutable section = root
            let mutable abort: string = null
            let mutable i = 0
            while isNull abort && i < keys.Length do
                let existing = section[keys[i]]
                if not (isNull existing) && not (existing :? JsonObject) then
                    abort <- "The config already has a '" + keys[i] + "' that is not an object — not touching it:\n" +
                             configPath + "\n\nUse 'Copy MCP config' and add the entry by hand."
                else
                    let next =
                        match existing with
                        | :? JsonObject as o -> o
                        | _ -> JsonObject()
                    section[keys[i]] <- next
                    section <- next
                    i <- i + 1
            if not (isNull abort) then (false, abort)
            else
                section[serverName] <- entry.DeepClone() // clone: callers may reuse the node across registrations

                Directory.CreateDirectory(Path.GetDirectoryName(configPath)) |> ignore
                File.WriteAllText(configPath, root.ToJsonString(JsonSerializerOptions(WriteIndented = true)))

                // verify: the re-read file must carry our entry exactly
                let mutable check = JsonNode.Parse(File.ReadAllText(configPath))
                for k in keys do
                    if not (isNull check) then check <- check[k]
                let verified =
                    match (if isNull check then null else check[serverName]) with
                    | :? JsonObject as verifiedEntry ->
                        not (isNull verifiedEntry["command"]) &&
                        verifiedEntry["command"].GetValue<string>() = entry["command"].GetValue<string>()
                    | _ -> false
                if verified then (true, null)
                else
                    (false, "Wrote the config but verification re-read failed:\n" + configPath +
                            "\n\nCheck the file, or use 'Copy MCP config' by hand.")

    // ── proxy install ─────────────────────────────────────────────────

    /// <summary>
    /// Best-effort cleanup: drop older versioned folders and the legacy
    /// flat files once a newer versioned install exists. A running proxy
    /// holds its files locked — those deletes quietly fail and are
    /// retried on the next install. Never touches the folder just kept.
    /// </summary>
    member private _.CleanStaleInstalls (root: string, keep: string) =
        try
            for dir in Directory.GetDirectories(root, "v*") do
                if not (String.Equals(dir, keep, StringComparison.OrdinalIgnoreCase)) then
                    tryDeleteDir dir
            for file in legacyProxyFiles do // legacy flat set
                tryDeleteFile (Path.Combine(root, file))
        with _ -> () // cleanup is opportunistic

    /// <summary>
    /// Installs (or finds) the proxy MCP configs should spawn and returns
    /// its path plus a human-readable note about what happened. Installs
    /// go to tools\v&lt;appVersion&gt;\ — a fresh folder per app version, so a
    /// proxy still running from an older folder never locks the copy, and
    /// a version bump always refreshes the deployed bits (the old "files
    /// exist → skip" check left clients pinned to ancient builds forever).
    /// A dev-tree or in-zip source path is only ever a COPY SOURCE — on
    /// failure the previously-good install is kept and the failure is
    /// reported, never silently registered.
    /// Core with injectable inputs so self-tests can drive it.
    /// </summary>
    member internal _.ResolveAndInstallProxy (appVersion: string, root: string,
                                              sourceDirs: IEnumerable<string>) : string * string =
        let target = Path.Combine(root, "v" + appVersion)
        let targetExe = Path.Combine(target, proxyExeName)

        if versionedInstallComplete target then
            (targetExe, "proxy v" + appVersion + " already installed")
        else
            let mutable firstError: string = null
            let mutable installed: (string * string) option = None
            for src in sourceDirs do
                if installed.IsNone && File.Exists(Path.Combine(src, proxyExeName)) then
                    try
                        Directory.CreateDirectory(target) |> ignore
                        for file in Directory.GetFiles(src) do
                            File.Copy(file, Path.Combine(target, Path.GetFileName(file)), overwrite = true)
                        let marker = JsonObject()
                        marker["version"] <- JsonValue.Create(appVersion)
                        marker["copiedUtc"] <- JsonValue.Create(DateTime.UtcNow.ToString("o"))
                        File.WriteAllText(Path.Combine(target, "proxy.installed"), marker.ToJsonString())
                        this.CleanStaleInstalls(root, target)
                        installed <- Some(targetExe, "installed proxy v" + appVersion + " from " + src)
                    with ex ->
                        if isNull firstError then firstError <- ex.Message // remember why, try the next source
                        tryDeleteDir target                          // half-copied folder must not look complete
            match installed with
            | Some r -> r
            | None ->
                // nothing installable — keep the previously-good path (newest
                // complete versioned install, else the legacy flat set) and say so
                let keep what path =
                    (path, "could not install proxy v" + appVersion +
                           (if not (isNull firstError) then " (" + firstError + ")" else " (no source found)") +
                           " — keeping " + what)
                let mutable fallback: string = null
                try
                    if Directory.Exists(root) then
                        fallback <-
                            Directory.GetDirectories(root, "v*")
                            |> Seq.filter versionedInstallComplete
                            |> Seq.sortByDescending tryParseVersion
                            |> Seq.tryHead
                            |> Option.toObj
                with _ -> () // unreadable tools dir — fall through to legacy
                if not (isNull fallback) then
                    keep ("the existing " + Path.GetFileName(fallback)) (Path.Combine(fallback, proxyExeName))
                elif legacyComplete root then
                    keep "the legacy flat install" (Path.Combine(root, proxyExeName))
                else
                    (null, "no runnable " + proxyExeName + " found next to the app (sources: " +
                           String.Join("; ", sourceDirs) + ")" +
                           (if not (isNull firstError) then " — " + firstError else ""))

    /// <summary>
    /// Real-input wrapper: sources are searched best-first — the zip's
    /// tools\AgentProxy beside the running app (release layout), then the
    /// repo's publish\v*\tools\AgentProxy and the proxy's own bin\
    /// (dev layout; Release preferred over Debug, newest TFM wins — no
    /// hardcoded TFM string to go stale).
    /// </summary>
    member _.ResolveAndInstallProxy () : string * string =
        let sources = ResizeArray<string>()
        let mutable dir: string = AppContext.BaseDirectory
        let mutable levels = 0
        while not (isNull dir) && levels < 6 do
            sources.Add(Path.Combine(dir, "tools", "AgentProxy")) // release layout
            let publishRoot = Path.Combine(dir, "publish")        // dev: release.ps1 output
            if Directory.Exists(publishRoot) then
                for v in Directory.GetDirectories(publishRoot, "v*") |> Seq.sortByDescending tryParseVersion do
                    sources.Add(Path.Combine(v, "tools", "AgentProxy"))
            let proxyBin = Path.Combine(dir, "AgentProxy", "bin") // dev: any build output
            if Directory.Exists(proxyBin) then
                for cfg in [ "Release"; "Debug" ] do
                    let cfgDir = Path.Combine(proxyBin, cfg)
                    if Directory.Exists(cfgDir) then
                        for tfm in Directory.GetDirectories(cfgDir)
                                    |> Array.sortWith (fun a b -> StringComparer.OrdinalIgnoreCase.Compare(b, a)) do
                            sources.Add(tfm) // framework-dependent exe, plus any win-x64\publish under it
            levels <- levels + 1
            dir <- Path.GetDirectoryName(dir)
        // Where(Directory.Exists) then Distinct(OrdinalIgnoreCase), C# order
        let unique = ResizeArray<string>()
        for s in sources do
            if Directory.Exists(s) &&
               not (unique.Exists(fun x -> String.Equals(x, s, StringComparison.OrdinalIgnoreCase))) then
                unique.Add(s)
        this.ResolveAndInstallProxy(appVersion (), toolsRoot, unique)

    // ── proxy preflight ───────────────────────────────────────────────

    /// <summary>
    /// Proves the installed proxy actually starts and speaks MCP before
    /// any client config points at it — twice: once with this process's
    /// environment, and once with DOTNET_ROOT/DOTNET_ROOT_X64 pointed at
    /// an empty folder. That second case is the real-world trap: desktop
    /// MCP clients routinely bundle their own (older) .NET and export
    /// DOTNET_ROOT for everything they spawn, which kills a
    /// framework-dependent apphost before any managed code runs. A
    /// self-contained proxy ignores DOTNET_ROOT and passes both.
    /// </summary>
    member _.PreflightProxy (proxyExe: string) : bool * string =
        if isNull proxyExe || not (File.Exists(proxyExe)) then
            (false, proxyExeName + " is not where it was just installed:\n" + proxyExe)
        else
            match this.HandshakeOnce(proxyExe, null) with
            | Choice2Of2 err1 ->
                (false, "the proxy did not answer an MCP handshake when spawned normally:\n" + err1)
            | Choice1Of2 _ ->
                let emptyRoot = Path.Combine(Path.GetTempPath(), mcpId + "-empty-dotnet-root")
                Directory.CreateDirectory(emptyRoot) |> ignore
                match this.HandshakeOnce(proxyExe, emptyRoot) with
                | Choice2Of2 err2 ->
                    (false, "the proxy starts normally but dies under a hostile DOTNET_ROOT — " +
                            "the classic desktop-MCP-client failure. Reinstall " + identity.Name +
                            " and register again.\n" + err2)
                | Choice1Of2 _ ->
                    (true, null)

    /// <summary>Sends one initialize line, expects one JSON-RPC result
    /// line back. Choice1Of2 line on success, Choice2Of2 failure reason.
    /// (F# port of the C# string/out-error pair.)</summary>
    member private _.HandshakeOnce (exe: string, poisonRoot: string) : Choice<string, string> =
        try
            let psi = ProcessStartInfo(exe)
            psi.RedirectStandardInput <- true
            psi.RedirectStandardOutput <- true
            psi.UseShellExecute <- false
            psi.CreateNoWindow <- true
            if not (isNull poisonRoot) then
                psi.EnvironmentVariables["DOTNET_ROOT"] <- poisonRoot
                psi.EnvironmentVariables["DOTNET_ROOT_X64"] <- poisonRoot
            use p = Process.Start(psi)
            p.StandardInput.WriteLine("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"," +
                "\"params\":{\"protocolVersion\":\"2025-03-26\",\"clientInfo\":{\"name\":\"" + mcpId +
                "-preflight\",\"version\":\"0\"}}}")
            p.StandardInput.Flush()

            // read lines until a response (a result or an error) shows up;
            // notifications carry no "id" and are skipped
            let deadline = Task.Delay(TimeSpan.FromSeconds 10.0)
            let mutable found: string = null
            let mutable doneReading = false
            while isNull found && not doneReading && not deadline.IsCompleted do
                let lineTask = p.StandardOutput.ReadLineAsync()
                if Task.WhenAny(lineTask :> Task, Task.Delay 1000).Result <> (lineTask :> Task) then
                    () // keep waiting — same shape as the C# `continue`
                else
                    let line = lineTask.Result
                    if isNull line then doneReading <- true
                    elif line.Contains("\"result\"") || line.Contains("\"error\"") then found <- line
            if not (isNull found) then
                Choice1Of2 found
            else
                try p.Kill() with _ -> ()
                Choice2Of2 ("no JSON-RPC response within 10s (exit code " +
                            (if p.HasExited then p.ExitCode.ToString() else "none") + ")")
        with ex -> Choice2Of2 ex.Message
