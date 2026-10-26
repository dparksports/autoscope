// F# port of Core\Services\AgentBridgeService.cs (AutoScope.Services →
// AutoScope.Engines.Bridge). Faithful by contract: same trust model, same
// wire bytes (HTTP/1.1 subset, JSON-RPC shapes, status codes and reason
// phrases), same session-file JSON shape (the deployed
// AutoScope.AgentProxy.exe reads {port, token, pid} from it). The app
// values the C# hardcoded — port base 47921, %LOCALAPPDATA%\AutoScope,
// "autoscope", "AutoScope" — now come from the AppIdentity the host
// constructs; the tool surface is injected through IAgentTools instead of
// the static AgentToolRegistry.
namespace AutoScope.Engines.Bridge

open System
open System.Collections.Generic
open System.Diagnostics
open System.IO
open System.Net
open System.Net.Sockets
open System.Runtime.InteropServices
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Threading
open System.Threading.Tasks
open AutoScope.Engines.Core

/// <summary>
/// The AI-access bridge: a loopback-only MCP endpoint hosted INSIDE the
/// running (elevated) app process.
///
/// Trust model — the app is the broker:
///   • The user starts a session from Settings → "AI access" (or the app
///     is launched with --agent-headless). Starting writes
///     &lt;identity.DataRoot&gt;\agent\session.json {port, token, pid}.
///   • An MCP client spawns the proxy exe with --agent-stdio (headless,
///     inherits the caller's non-elevated token — no UAC), which reads the
///     session file and forwards JSON-RPC to the listener below.
///   • Every call must carry the session bearer token (constant-time
///     compare) and a 127.0.0.1 Host header (DNS-rebinding guard).
///   • Read-only tools answer immediately; mutating tools need the
///     session toggle AND a per-action confirmation dialog on the UI.
///   • Stopping the session (or exiting the app) deletes the session
///     file and kills the listener — revocation is instant.
///
/// Raw TcpListener instead of HttpListener: http.sys URL reservations
/// need admin or netsh setup; a hand-rolled HTTP/1.1 subset (POST-only,
/// one request per connection) has no ACL surface at all.
/// </summary>
type AgentBridgeService (identity: AppIdentity, tools: IAgentTools,
                         [<Optional; DefaultParameterValue(-1)>] portBaseOverride: int) as this =

    // F# port: interfaces/classes do not admit the null literal in F#, so
    // the C#'s `= null` initializers are Unchecked.defaultof here; C# code
    // still reads and assigns plain null.
    static let mutable ui: IAgentBridgeUI = Unchecked.defaultof<IAgentBridgeUI>

    // Protocol versions this bridge actually implements — must match the
    // proxy's set (see AgentProxy\Program.cs): initialize/notifications/*,
    // ping, tools/list, tools/call; resources/* and prompts/* answer -32601.
    static let SupportedProtocols = [| "2024-11-05"; "2025-03-26"; "2025-06-18" |]

    // F# port: the C# hardcoded PortBase = 47921; the port base lives on
    // AppIdentity.BridgePortBase. portBaseOverride exists so tests can
    // bind a non-production range (pass -1 to use the identity's base).
    let portBase = if portBaseOverride >= 0 then portBaseOverride else identity.BridgePortBase

    // F# port: %LOCALAPPDATA%\AutoScope\agent → identity.DataRoot\agent.
    let agentDir = Path.Combine(identity.DataRoot, "agent")
    let sessionPath = Path.Combine(agentDir, "session.json")
    let activityPath = Path.Combine(agentDir, "activity.jsonl")
    let feedPath = Path.Combine(agentDir, "feed.jsonl")

    let mutable listener: TcpListener = null
    let mutable cts: CancellationTokenSource = null
    let mutable token = ""
    let mutable port = 0
    let mutable allowMutating = false
    let mutable clientInitialized = false
    let mutable clientName = ""
    let mutable connectedCalls = 0
    let sessionToolsLock = obj ()
    let sessionAllowedTools = HashSet<string>(StringComparer.Ordinal)

    // event Action<string> Activity — same delegate shape the C# field-like
    // event exposed, so C# `bridge.Activity += s => ...` compiles unchanged.
    let activity = DelegateEvent<Action<string>>()

    /// <summary>Installed by the app at startup; without it the bridge
    /// still serves read-only tools but cannot confirm mutating ones
    /// (same behavior as headless sessions).</summary>
    static member Ui
        with get () = ui
        and set (value) = ui <- value

    /// <summary>F# port: the C# exposed a parameterless `Instance`
    /// singleton; the engine needs the app's identity and tool provider,
    /// so the host assigns Shared once at startup
    /// (AgentBridgeService.Shared = new AgentBridgeService(...)).</summary>
    static member val Shared: AgentBridgeService = Unchecked.defaultof<AgentBridgeService> with get, set

    // F# port: const → plain static members ([<Literal>] is not valid on
    // members); same values readable from C#.
    static member PortRange = 20
    static member MaxBodyBytes = 4 * 1024 * 1024
    static member ConfirmTimeoutMs = 90_000

    member _.AgentDir = agentDir
    member _.ClientName = clientName
    member _.ConnectedCalls = connectedCalls
    member _.IsRunning = not (isNull listener)
    member _.Port = port
    member _.AllowMutating = allowMutating

    /// <summary>Fires on bridge state changes (session started/stopped,
    /// tool calls) for UI status.</summary>
    [<CLIEvent>]
    member _.Activity = activity.Publish

    // ── session lifecycle ─────────────────────────────────────────────

    member _.Start (allowMutatingArg: bool) : bool * string =
        if this.IsRunning then
            (false, "AI access session is already running.")
        else
            token <- Convert.ToHexString(RandomNumberGenerator.GetBytes(32))
            allowMutating <- allowMutatingArg
            lock sessionToolsLock (fun () -> sessionAllowedTools.Clear())
            clientName <- ""
            clientInitialized <- false // a new session is a new MCP lifecycle
            connectedCalls <- 0

            let mutable bound: TcpListener = null
            let mutable boundPort = 0
            let mutable p = portBase
            let mutable trying = true
            while trying && p < portBase + AgentBridgeService.PortRange do
                try
                    let l = new TcpListener(IPAddress.Loopback, p)
                    l.Start()
                    bound <- l
                    boundPort <- p
                    trying <- false
                with _ -> p <- p + 1 // port taken — try the next
            // F# port: the C#'s `if (listener == null)` guard can never see
            // the last failed attempt (the ctor succeeds before Start()
            // throws), so a fully-blocked range would have written
            // session.json with port 0 — the port tracks success instead.
            if isNull bound then
                (false, $"No free port in {portBase}–{portBase + AgentBridgeService.PortRange - 1}.")
            else
                listener <- bound
                port <- boundPort
                cts <- new CancellationTokenSource()
                Task.Run(fun () -> this.AcceptLoop(bound, cts.Token)) |> ignore

                Directory.CreateDirectory(agentDir) |> ignore
                let session = JsonObject()
                session["port"] <- JsonValue.Create(port)
                session["token"] <- JsonValue.Create(token)
                session["pid"] <- JsonValue.Create(Process.GetCurrentProcess().Id)
                session["startedUtc"] <- JsonValue.Create(DateTime.UtcNow.ToString("o"))
                session["mutatingAllowed"] <- JsonValue.Create(allowMutating)
                let toolsJson = JsonArray()
                for n in tools.Names(allowMutating) do toolsJson.Add(JsonValue.Create(n))
                session["tools"] <- toolsJson
                File.WriteAllText(sessionPath, session.ToJsonString(JsonSerializerOptions(WriteIndented = true)))

                let snap = JsonObject()
                snap["type"] <- JsonValue.Create("session_started")
                snap["port"] <- JsonValue.Create(port)
                snap["mutatingAllowed"] <- JsonValue.Create(allowMutating)
                this.AppendFeed(snap)
                let mutText = if allowMutating then "on (each action asks)" else "off"
                this.LogActivity("session", "started", $"loopback port {port}, mutating {mutText}")
                activity.Trigger([| box "session started" |])
                (true, $"Listening on 127.0.0.1:{port}.")

    member _.Stop () =
        if this.IsRunning then
            if not (isNull cts) then (try cts.Cancel() with _ -> ())
            if not (isNull listener) then (try listener.Stop() with _ -> ())
            listener <- null
            if not (isNull cts) then cts.Dispose()
            cts <- null
            (try if File.Exists(sessionPath) then File.Delete(sessionPath) with _ -> ())
            this.LogActivity("session", "stopped", "")
            activity.Trigger([| box "session stopped" |])

    /// <summary>True when a live session file matches a running bridge
    /// (crash-cleanup helper for the stdio bridge).</summary>
    member _.ReadSession () : int * string =
        // F# port: static in the C# (fixed path); the engine derives the
        // path from the identity, so this is an instance member.
        let node =
            match JsonNode.Parse(File.ReadAllText(sessionPath)) with
            | :? JsonObject as o -> o
            | _ -> null
        let portValue =
            if isNull node || isNull node["port"] then 0 else node["port"].GetValue<int>()
        let tokenValue =
            if isNull node || isNull node["token"] then "" else node["token"].GetValue<string>()
        (portValue, tokenValue)

    member _.SessionFileExists = File.Exists(sessionPath)

    /// <summary>Last N activity lines (newest first) for the Settings
    /// card. F# port: static in the C#; instance here (identity-derived
    /// path).</summary>
    member _.RecentActivity ([<Optional; DefaultParameterValue(30)>] count: int) : ResizeArray<string> =
        let lines = ResizeArray<string>()
        try
            if File.Exists(activityPath) then
                for line in File.ReadLines(activityPath) |> Seq.rev |> Seq.truncate count do
                    lines.Add(line)
        with _ -> ()
        lines

    // ── accept + minimal HTTP/1.1 ─────────────────────────────────────

    member private _.AcceptLoop (listener: TcpListener, ct: CancellationToken) : Task =
        task {
            let mutable running = true
            while running && not ct.IsCancellationRequested do
                try
                    let! client = listener.AcceptTcpClientAsync(ct).AsTask()
                    Task.Run(fun () -> this.HandleClient(client, ct)) |> ignore
                with _ -> running <- false // listener stopped
        } :> Task

    member private _.HandleClient (client: TcpClient, ct: CancellationToken) : Task =
        task {
            try
                use __ = client
                client.ReceiveTimeout <- 120_000
                let stream = client.GetStream()

                let! head = AgentBridgeService.ReadUntilAsync(stream, "\r\n\r\n", 64 * 1024)
                if isNull head then
                    ()
                else
                    let lines = head.Split("\r\n")
                    let requestLine = lines.[0].Split(' ')
                    let method = if requestLine.Length > 0 then requestLine.[0] else ""
                    let headers = Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    for i = 1 to lines.Length - 1 do
                        let c = lines.[i].IndexOf(':')
                        if c > 0 then
                            headers.[lines.[i].Substring(0, c).Trim()] <- lines.[i].Substring(c + 1).Trim()

                    if method <> "POST" then
                        do! AgentBridgeService.WriteJsonResponse(stream,
                            (if method = "GET" then 405 else 400),
                            "{\"error\":\"POST only (MCP streamable HTTP, stateless)\"}")
                    else
                        let hostOk =
                            match headers.TryGetValue("Host") with
                            | true, host ->
                                host.StartsWith("127.0.0.1:", StringComparison.OrdinalIgnoreCase) ||
                                host.StartsWith("localhost:", StringComparison.OrdinalIgnoreCase)
                            | _ -> false
                        if not hostOk then
                            do! AgentBridgeService.WriteJsonResponse(stream, 403, "{\"error\":\"loopback only\"}")
                        else
                            let authOk =
                                match headers.TryGetValue("Authorization") with
                                | true, auth -> this.TokenMatches(auth)
                                | _ -> false
                            if not authOk then
                                do! AgentBridgeService.WriteJsonResponse(stream, 401, "{\"error\":\"bad or missing session token\"}")
                            else
                                let contentLength =
                                    match headers.TryGetValue("Content-Length") with
                                    | true, cl -> (match Int32.TryParse(cl) with true, n -> n | _ -> 0)
                                    | _ -> 0
                                if contentLength < 0 || contentLength > AgentBridgeService.MaxBodyBytes then
                                    do! AgentBridgeService.WriteJsonResponse(stream, 413, "{\"error\":\"body too large\"}")
                                else
                                    match headers.TryGetValue("Expect") with
                                    | true, expect when expect.Contains("100-continue") ->
                                        do! AgentBridgeService.WriteRaw(stream, "HTTP/1.1 100 Continue\r\n\r\n")
                                    | _ -> ()

                                    let bodyTask =
                                        if contentLength = 0 then Task.FromResult("")
                                        else AgentBridgeService.ReadExactAsync(stream, contentLength)
                                    let! body = bodyTask

                                    // C# `JsonNode.Parse(body) as JsonObject`:
                                    // valid-but-not-an-object JSON gets the
                                    // -32700 parse error; invalid JSON throws
                                    // and lands in the catch-all below (same
                                    // split as the C#).
                                    match JsonNode.Parse(body) with
                                    | :? JsonObject as rpc ->
                                        let rpcId =
                                            if isNull rpc["id"] then null else rpc["id"].ToJsonString()
                                        let! jsonResponse =
                                            this.DispatchAsync(rpc,
                                                (match headers.TryGetValue("User-Agent") with
                                                 | true, ua -> ua | _ -> ""))
                                        if isNull rpcId || isNull jsonResponse then
                                            do! AgentBridgeService.WriteRaw(stream,
                                                "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                        else
                                            do! AgentBridgeService.WriteResponse(stream, 200,
                                                JsonNode.Parse(jsonResponse) :?> JsonObject)
                                    | _ ->
                                        do! AgentBridgeService.WriteJsonResponse(stream, 400,
                                            AgentBridgeService.RpcError(null, -32700, "Parse error"))
            with _ -> () // client vanished mid-request — nothing to salvage
        } :> Task

    member private _.TokenMatches (authHeader: string) : bool =
        if isNull authHeader || token.Length = 0 then false
        else
            let prefix = "Bearer "
            if not (authHeader.StartsWith(prefix, StringComparison.Ordinal)) then false
            else
                let given = Encoding.UTF8.GetBytes(authHeader.Substring(prefix.Length))
                let expected = Encoding.UTF8.GetBytes(token)
                given.Length = expected.Length && CryptographicOperations.FixedTimeEquals(given, expected)

    // ── MCP dispatch ──────────────────────────────────────────────────

    static member private NegotiateProtocol (requested: string) =
        if not (String.IsNullOrEmpty requested) && Array.IndexOf(SupportedProtocols, requested) >= 0
        then requested
        else SupportedProtocols.[SupportedProtocols.Length - 1]

    member internal _.DispatchAsync (rpc: JsonObject, userAgent: string) : Task<string> =
        task {
            let method =
                let m = rpc["method"]
                if isNull m then "" else m.GetValue<string>()
            let prm =
                match box rpc["params"] with
                | :? JsonObject as o -> o
                | _ -> null
            let isNotification = isNull rpc["id"]

            // MCP lifecycle: requests before initialize are refused (-32002).
            // ping stays answerable (clients probe with it), notifications
            // are dropped — there is nobody to answer. Mirrored in the proxy
            // so both halves enforce the same rule.
            if not isNotification && not clientInitialized && method <> "initialize" && method <> "ping" then
                return AgentBridgeService.RpcError(rpc["id"], -32002, "Server not initialized — send initialize first.")
            else
                try
                    match method with
                    | "initialize" ->
                        let requested =
                            if isNull prm then null
                            else
                                let pv = prm["protocolVersion"]
                                if isNull pv then null else pv.GetValue<string>()
                        let clientInfo =
                            match (if isNull prm then null else prm["clientInfo"]) with
                            | :? JsonObject as o -> o
                            | _ -> null
                        let initName =
                            if isNull clientInfo then null
                            else
                                let n = clientInfo["name"]
                                if isNull n then null else n.GetValue<string>()
                        clientName <-
                            if not (String.IsNullOrEmpty initName) then initName
                            elif not (String.IsNullOrEmpty userAgent) then userAgent
                            else "unknown"
                        clientInitialized <- true
                        this.LogActivity("client", "connected", clientName)
                        activity.Trigger([| box $"client connected: {clientName}" |])
                        let negotiated = AgentBridgeService.NegotiateProtocol(requested)
                        if negotiated <> requested then
                            let reqText = if isNull requested then "(none)" else requested
                            this.LogActivity("client", "protocol", $"requested {reqText} — answered {negotiated}")
                        let result = JsonObject()
                        result["protocolVersion"] <- JsonValue.Create(negotiated)
                        let caps = JsonObject()
                        let toolsCap = JsonObject()
                        toolsCap["listChanged"] <- JsonValue.Create(false)
                        caps["tools"] <- toolsCap
                        result["capabilities"] <- caps
                        let serverInfo = JsonObject()
                        serverInfo["name"] <- JsonValue.Create(identity.McpId)
                        // same title offline and online so the client UI
                        // never relabels the server when a session flips
                        serverInfo["title"] <- JsonValue.Create(identity.Name + " (agent bridge)")
                        let exePath =
                            match Environment.ProcessPath with
                            | null -> identity.Name + ".exe"
                            | path -> path
                        serverInfo["version"] <- JsonValue.Create(
                            (match FileVersionInfo.GetVersionInfo(exePath).ProductVersion with
                             | null -> "?" | v -> v))
                        result["serverInfo"] <- serverInfo
                        result["instructions"] <- JsonValue.Create(
                            "Read-only security telemetry from the locally running " + identity.Name + " app " +
                            "(process monitor, svchost identity, PID provenance, Sysmon tail, trace analysis). " +
                            "Mutating tools (block/kill/disable) ask the user for confirmation in the app UI on every call " +
                            "and are only present when the user enabled them for the session.")
                        return AgentBridgeService.RpcResult(rpc["id"], result)

                    | "notifications/initialized"
                    | "notifications/cancelled" ->
                        return null

                    | "ping" ->
                        return AgentBridgeService.RpcResult(rpc["id"], JsonObject())

                    | "tools/list" ->
                        let result = JsonObject()
                        result["tools"] <- JsonNode.Parse(tools.ListTools(allowMutating))
                        return AgentBridgeService.RpcResult(rpc["id"], result)

                    | "tools/call" ->
                        let name =
                            if isNull prm then ""
                            else
                                let n = prm["name"]
                                if isNull n then "" else n.GetValue<string>()
                        let args =
                            match (if isNull prm then null else prm["arguments"]) with
                            | :? JsonObject as o -> o
                            | _ -> JsonObject()
                        connectedCalls <- connectedCalls + 1
                        let! (content, isError) = this.CallToolAsync(name, args)
                        let outcomeText = if isError then "error" else "ok"
                        this.LogActivity("tool", name, AgentBridgeService.SummarizeArgs(args), outcomeText)
                        activity.Trigger([| box $"tool {name} → {outcomeText}" |])
                        let result = JsonObject()
                        let contentObj = JsonObject()
                        contentObj["type"] <- JsonValue.Create("text")
                        contentObj["text"] <- JsonValue.Create(content)
                        let contentArr = JsonArray()
                        contentArr.Add(contentObj)
                        result["content"] <- contentArr
                        result["isError"] <- JsonValue.Create(isError)
                        return AgentBridgeService.RpcResult(rpc["id"], result)

                    | _ ->
                        if isNotification then return null
                        else return AgentBridgeService.RpcError(rpc["id"], -32601, $"Unknown method: {method}")
                with ex ->
                    if isNotification then return null
                    else
                        let result = JsonObject()
                        let contentObj = JsonObject()
                        contentObj["type"] <- JsonValue.Create("text")
                        contentObj["text"] <- JsonValue.Create("tool failed: " + ex.Message)
                        let contentArr = JsonArray()
                        contentArr.Add(contentObj)
                        result["content"] <- contentArr
                        result["isError"] <- JsonValue.Create(true)
                        return AgentBridgeService.RpcResult(rpc["id"], result)
        }

    member private _.CallToolAsync (name: string, args: JsonObject) : Task<string * bool> =
        task {
            let tool = tools.Find(name, allowMutating)
            if isNull (box tool) then
                return ($"Unknown tool '{name}' (or mutating tools are disabled for this session).", true)
            elif tool.Mutating && not (this.SessionGranted(name)) then
                let allowed, note = this.RequestConfirmation(name, tool.ConfirmDetail(args.ToJsonString()))
                if not allowed then
                    return ($"User denied '{name}'" + (if note.Length > 0 then $" — {note}" else "") + ".", true)
                else
                    let! output = Task.Run(fun () -> tool.Invoke(args.ToJsonString()))
                    return (output, false)
            else
                let! output = Task.Run(fun () -> tool.Invoke(args.ToJsonString()))
                return (output, false)
        }

    member private _.SessionGranted (toolName: string) =
        lock sessionToolsLock (fun () -> sessionAllowedTools.Contains(toolName))

    // ── per-action confirmation (Tier 3) ──────────────────────────────

    /// <summary>
    /// Asks the user at the app's UI. Runs on the dispatcher; returns
    /// after the user answers or the timeout elapses (deny). "Always for
    /// this session" grants are remembered per tool until Stop().
    /// </summary>
    member _.RequestConfirmation (toolName: string, detail: string) : bool * string =
        if not allowMutating then (false, "mutating tools are disabled for this session")
        else
            let uiInstance = AgentBridgeService.Ui
            if isNull (box uiInstance) || not uiInstance.IsUiAvailable then
                (false, "headless session has no UI to confirm with — restart the session from "
                        + identity.Name + " Settings to allow mutating tools")
            else
                let tcs = TaskCompletionSource<bool * bool * string>(TaskCreationOptions.RunContinuationsAsynchronously)
                uiInstance.BeginInvokeOnUI(Action(fun () ->
                    // F# port: the C# passed an `async` lambda where Action
                    // accepted it (async void) — a task{} started eagerly is
                    // the same fire-and-forget, with continuations posted
                    // back to the UI context by the await.
                    let dialog =
                        task {
                            try
                                let! (allowed, always) = uiInstance.ShowConfirmAsync(toolName, detail)
                                tcs.TrySetResult((allowed, always,
                                    (if allowed then "allowed by user" else "denied by user"))) |> ignore
                            with ex ->
                                tcs.TrySetResult((false, false, "confirm dialog failed: " + ex.Message)) |> ignore
                        }
                    ignore dialog))

                let completed =
                    Task.WhenAny(tcs.Task, Task.Delay(AgentBridgeService.ConfirmTimeoutMs))
                        .GetAwaiter().GetResult()
                if completed <> (tcs.Task :> Task) then
                    (false, $"no answer in {AgentBridgeService.ConfirmTimeoutMs / 1000}s")
                else
                    let allowed, always, note = tcs.Task.Result
                    if allowed && always then
                        lock sessionToolsLock (fun () -> sessionAllowedTools.Add(toolName) |> ignore)
                        this.LogActivity("session", "grant", $"{toolName} allowed for the rest of the session")
                    (allowed, note)

    // ── activity log + feed (Phase 1) ─────────────────────────────────

    member private _.LogActivity (kind: string, what: string, detail: string,
                                  [<Optional; DefaultParameterValue(null: string)>] outcome: string) =
        try
            Directory.CreateDirectory(agentDir) |> ignore
            let line = JsonObject()
            line["t"] <- JsonValue.Create(DateTime.Now.ToString("o"))
            line["kind"] <- JsonValue.Create(kind)
            line["what"] <- JsonValue.Create(what)
            line["client"] <- JsonValue.Create(if isNull clientName then "" else clientName)
            if not (String.IsNullOrEmpty detail) then line["detail"] <- JsonValue.Create(detail)
            if not (isNull outcome) then line["outcome"] <- JsonValue.Create(outcome)
            File.AppendAllText(activityPath, line.ToJsonString() + "\n")
        with _ -> () // best-effort audit trail

    member private _.AppendFeed (snapshot: JsonObject) =
        try
            Directory.CreateDirectory(agentDir) |> ignore
            snapshot["t"] <- JsonValue.Create(DateTime.Now.ToString("o"))
            File.AppendAllText(feedPath, snapshot.ToJsonString() + "\n")
        with _ -> () // best-effort feed

    /// <summary>Phase 1: periodic full snapshot so offline agents can read
    /// state from the file alone. F# port: like the C#, StartFeed/FeedLoop
    /// are present but unreferenced (the C# never wired the feed loop into
    /// Start); the snapshot now comes from IAgentTools.</summary>
    member private _.FeedLoop (ct: CancellationToken) : Task =
        task {
            let mutable running = true
            while running && not ct.IsCancellationRequested do
                try
                    let snapshotJson = tools.BuildMonitorSnapshot()
                    if not (isNull snapshotJson) then
                        this.AppendFeed(match JsonNode.Parse(snapshotJson) with
                                        | :? JsonObject as o -> o
                                        | _ -> JsonObject())
                with _ -> ()
                try
                    do! Task.Delay(60_000, ct)
                with _ -> running <- false
        } :> Task

    member private _.StartFeed () =
        Task.Run(fun () -> this.FeedLoop(cts.Token)) |> ignore

    // ── plumbing ──────────────────────────────────────────────────────

    static member private ReadUntilAsync (stream: NetworkStream, terminator: string, maxBytes: int) : Task<string> =
        task {
            let buffer = Array.zeroCreate<byte> 1
            let sb = StringBuilder()
            let raw = new MemoryStream()
            let mutable finished = false
            let mutable result: string = null
            while not finished do
                let s = sb.ToString()
                if s.EndsWith(terminator, StringComparison.Ordinal) || raw.Length >= maxBytes then
                    finished <- true
                    result <- s
                else
                    let! n = stream.ReadAsync(buffer, 0, 1)
                    if n = 0 then
                        finished <- true
                        result <- (if sb.Length = 0 then null else sb.ToString())
                    else
                        raw.WriteByte(buffer.[0])
                        sb.Append(char buffer.[0]) |> ignore
            return result
        }

    static member private ReadExactAsync (stream: NetworkStream, count: int) : Task<string> =
        task {
            let buffer = Array.zeroCreate<byte> count
            let mutable read = 0
            let mutable reading = true
            while reading && read < count do
                let! n = stream.ReadAsync(buffer, read, count - read)
                if n = 0 then reading <- false else read <- read + n
            return Encoding.UTF8.GetString(buffer, 0, read)
        }

    static member private WriteRaw (stream: NetworkStream, text: string) : Task =
        task {
            let bytes = Encoding.ASCII.GetBytes(text)
            do! stream.WriteAsync(bytes, 0, bytes.Length)
            do! stream.FlushAsync()
        } :> Task

    static member private WriteResponse (stream: NetworkStream, status: int, body: JsonObject) : Task =
        AgentBridgeService.WriteJsonResponse(stream, status, (if isNull body then "" else body.ToJsonString()))

    static member private WriteJsonResponse (stream: NetworkStream, status: int, json: string) : Task =
        task {
            let payload = Encoding.UTF8.GetBytes(if isNull json then "" else json)
            let reason =
                match status with
                | 200 -> "OK" | 202 -> "Accepted" | 400 -> "Bad Request" | 401 -> "Unauthorized"
                | 403 -> "Forbidden" | 405 -> "Method Not Allowed" | 413 -> "Payload Too Large"
                | _ -> "Error"
            let head = $"HTTP/1.1 {status} {reason}\r\n" +
                       "Content-Type: application/json\r\n" +
                       $"Content-Length: {payload.Length}\r\n" +
                       "Connection: close\r\n\r\n"
            do! AgentBridgeService.WriteRaw(stream, head)
            if payload.Length > 0 then do! stream.WriteAsync(payload, 0, payload.Length)
            do! stream.FlushAsync()
        } :> Task

    static member private RpcResult (id: JsonNode, result: JsonObject) : string =
        let o = JsonObject()
        o["jsonrpc"] <- JsonValue.Create("2.0")
        o["id"] <- (if isNull id then null else id.DeepClone())
        o["result"] <- result
        o.ToJsonString()

    static member private RpcError (id: JsonNode, code: int, message: string) : string =
        let o = JsonObject()
        o["jsonrpc"] <- JsonValue.Create("2.0")
        o["id"] <- (if isNull id then null else id.DeepClone())
        let err = JsonObject()
        err["code"] <- JsonValue.Create(code)
        err["message"] <- JsonValue.Create(message)
        o["error"] <- err
        o.ToJsonString()

    static member private SummarizeArgs (args: JsonObject) =
        try args.ToJsonString()
        with _ -> ""
