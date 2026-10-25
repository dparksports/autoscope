// AutoScope.AgentProxy — the process an MCP client spawns for the
// "autoscope" server entry. Deliberately tiny and privilege-free:
//
//   • reads %LOCALAPPDATA%\AutoScope\agent\session.json — written only
//     while the user's AI session is active in the running (elevated) app
//   • forwards each stdin JSON-RPC line to 127.0.0.1:<port> with the
//     session bearer token, writes the response to stdout
//   • with no session active, completes the MCP handshake anyway and
//     answers every tool call with setup guidance, so the client connects
//     cleanly at any time and self-describes
//
// The session token never appears in any config file — the MCP
// registration is just "spawn this exe".
//
// Startup note: this exe is published self-contained (single file, runtime
// bundled) precisely so a client that exports its own DOTNET_ROOT — desktop
// MCP clients bundling an older .NET do — cannot break the spawn. A
// framework-dependent build dies in the apphost before any code here runs.

using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

// offline tools/list surface: minimal descriptors (real schemas arrive from
// the app once a session is active — that list is authoritative)
const string OfflineToolsJson = """
[
  { "name": "get_monitor_rows", "description": "Live established-connection snapshot with process attribution and svchost identity (needs an active AutoScope AI session)." },
  { "name": "get_svchost_identity", "description": "SCM services + -k/-s identity of one svchost instance (needs an active session)." },
  { "name": "run_pid_inquiry", "description": "Full PID provenance report (needs an active session)." },
  { "name": "tail_sysmon", "description": "Recent Sysmon/Operational events (needs an active session)." },
  { "name": "trace_analyze", "description": "svchost trace capture + pattern analysis (needs an active session)." },
  { "name": "classify_ip", "description": "Destination-range classification, block-warning text and blocked-list status (needs an active session)." },
  { "name": "list_blocks", "description": "Inventory of every AutoScope firewall block with recent hit counts (needs an active session)." },
  { "name": "list_recent_block_hits", "description": "Live process-attributed feed of connects hitting firewall blocks — the 'who is being blocked' view (needs an active session)." },
  { "name": "check_host", "description": "'Why can't I reach this site?' — resolve, check blocked-list membership per address, plain-English verdict (needs an active session)." }
]
""";

// ── MCP protocol surface ────────────────────────────────────────────────
// Protocol versions this proxy AND the app's bridge actually implement:
// initialize / notifications/*, ping, tools/list, tools/call (resources/*
// and prompts/* are honestly refused with -32601 in both halves). Echo the
// client's version when it is one of these; otherwise answer with the
// newest supported one. Blindy echoing whatever arrived used to make us
// claim protocols (e.g. "1999-01-01") we never spoke.
string[] SupportedProtocols = { "2024-11-05", "2025-03-26", "2025-06-18" };
string Negotiate(string requested) =>
    !string.IsNullOrEmpty(requested) && Array.IndexOf(SupportedProtocols, requested) >= 0
        ? requested
        : SupportedProtocols[^1];

// same identity online and offline, so the client's UI does not relabel the
// server when a session flips: version comes from this exe's file version,
// which release.ps1 keeps in lockstep with the app's
string ServerVersion()
{
    try { return FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion ?? "?"; }
    catch { return "?"; }
}

// ── activity trail ──────────────────────────────────────────────────────
// Proxy lifetimes belong in the same audit trail as sessions and tool
// calls. Never to stdout — stdout is JSON-RPC and nothing else.
string AgentDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                               "AutoScope", "agent");
string ClientName = ""; // from initialize clientInfo, when the client sends one
void LogProxy(string what, string detail)
{
    try
    {
        Directory.CreateDirectory(AgentDir);
        var line = new JsonObject
        {
            ["t"] = DateTime.Now.ToString("o"),
            ["kind"] = "proxy",
            ["what"] = what,
            ["client"] = ClientName,
        };
        if (!string.IsNullOrEmpty(detail)) line["detail"] = detail;
        File.AppendAllText(Path.Combine(AgentDir, "activity.jsonl"), line.ToJsonString() + "\n");
    }
    catch { /* best-effort audit trail */ }
}

var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true };
var http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };

(int Port, string Token)? ReadSession()
{
    try
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                   "AutoScope", "agent", "session.json");
        var o = JsonNode.Parse(File.ReadAllText(path)) as JsonObject;
        return (o["port"].GetValue<int>(), o["token"].GetValue<string>());
    }
    catch { return null; }
}

async Task<string> ForwardAsync(int port, string token, string body, JsonNode id)
{
    try
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{port}/");
        req.Content = new StringContent(body, Encoding.UTF8, "application/json");
        req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        req.Headers.Accept.ParseAdd("application/json");
        req.Headers.Accept.ParseAdd("text/event-stream");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(110));
        using var resp = await http.SendAsync(req, cts.Token);
        if (resp.StatusCode == System.Net.HttpStatusCode.Accepted) return null; // notification accepted
        return await resp.Content.ReadAsStringAsync();
    }
    catch (Exception ex)
    {
        // -32603 internal error: the session disappearing is a transport
        // failure on our side, not an MCP lifecycle state — -32002 used to
        // tell well-behaved clients we were never initialized, which is a
        // lie (they DID initialize; the app just went away). The error must
        // echo the request id — a null id here made strict clients drop
        // the response entirely.
        return Error(id, -32603,
            "The AutoScope AI session ended (app closed or session stopped). " +
            "Start AutoScope → Settings → AI access → Start session, then retry. (" + ex.Message + ")");
    }
}

static string Result(JsonNode id, JsonObject result) =>
    new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id?.DeepClone(), ["result"] = result }.ToJsonString();

static string Error(JsonNode id, int code, string message) =>
    new JsonObject
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id?.DeepClone(),
        ["error"] = new JsonObject { ["code"] = code, ["message"] = message },
    }.ToJsonString();

string AnswerOffline(JsonObject rpc)
{
    JsonNode id = rpc["id"];
    if (id == null) return null; // notification — nothing to answer
    string method = rpc["method"]?.GetValue<string>() ?? "";
    var @params = rpc["params"] as JsonObject;

    switch (method)
    {
        case "initialize":
            string requested = @params?["protocolVersion"]?.GetValue<string>();
            return Result(id, new JsonObject
            {
                ["protocolVersion"] = Negotiate(requested),
                ["capabilities"] = new JsonObject { ["tools"] = new JsonObject { ["listChanged"] = false } },
                // identity matches the app bridge's online answer (name,
                // title, version) so the client UI never sees it change
                ["serverInfo"] = new JsonObject
                {
                    ["name"] = "autoscope",
                    ["title"] = "AutoScope (agent bridge)",
                    ["version"] = ServerVersion(),
                },
                ["instructions"] = "Bridge to the locally running AutoScope app. No AI session is currently " +
                    "active — every tool call answers with setup guidance until the user starts one " +
                    "(AutoScope → Settings → AI access → Start session).",
            });
        case "ping":
            return Result(id, new JsonObject());
        case "tools/list":
            return Result(id, new JsonObject
            {
                ["tools"] = JsonNode.Parse(OfflineToolsJson),
                ["_note"] = "inactive session — full schemas arrive from the app once a session starts",
            });
        case "tools/call":
            string name = @params?["name"]?.GetValue<string>() ?? "";
            return Result(id, new JsonObject
            {
                ["content"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["type"] = "text",
                        ["text"] = "AutoScope is not running or its AI session is off.\n" +
                            "Ask the user to open AutoScope → Settings → 'AI access' → Start session, then retry.",
                    },
                },
                ["isError"] = true,
            });
        default:
            return Error(id, -32601, $"Unknown method: {method} (no active AutoScope session)");
    }
}

// ── orphan guard ────────────────────────────────────────────────────────
// stdin EOF is the normal shutdown: the client closes its write end, and a
// crashed client's handles are reaped by Windows so EOF still arrives. The
// rare leak case (the pipe handle inherited into a long-lived bystander)
// would strand this proxy forever — so also watch the parent PID and exit
// when it is gone. GetProcessById can be fooled by PID reuse in theory; the
// 5-second poll plus EOF make that irrelevant in practice.
(int ParentPid, string ParentName) FindParent()
{
    try
    {
        var self = Process.GetCurrentProcess().Id;
        var entries = Native.SnapshotProcesses();
        var mine = entries.FirstOrDefault(e => e.Pid == self);
        if (mine == null) return (0, "?");
        var parent = entries.FirstOrDefault(e => e.Pid == mine.ParentPid);
        return ((int)mine.ParentPid, parent?.Name ?? "?" + mine.ParentPid);
    }
    catch { return (0, "?"); }
}
var (parentPid, parentName) = FindParent();
if (parentPid != 0)
{
    int watched = parentPid;
    _ = Task.Run(async () =>
    {
        while (true)
        {
            await Task.Delay(5000);
            try { Process.GetProcessById(watched).Dispose(); }
            catch { LogProxy("stop", $"parent {parentName} ({watched}) is gone"); Environment.Exit(0); }
        }
    });
}
LogProxy("start", $"spawned by {parentName} ({parentPid}), proxy v{ServerVersion()}");

// ── main loop ───────────────────────────────────────────────────────────
// The session file is re-read on every incoming message: the client spawns
// this proxy at ITS startup, possibly long before the user presses "Start
// AI session" — when that flip happens mid-connection, calls must start
// working immediately, and the client should re-list tools.
bool clientInitialized = false; // MCP lifecycle: no requests before initialize
bool wasOnline = false;
try
{
    string line;
    while ((line = Console.ReadLine()) != null)
    {
        line = line.Trim();
        if (line.Length == 0) continue;

        JsonObject rpc = null;
        try { rpc = JsonNode.Parse(line) as JsonObject; } catch { }

        if (rpc == null)
        {
            stdout.WriteLine(Error(null, -32700, "Parse error"));
            continue;
        }

        string method = rpc["method"]?.GetValue<string>() ?? "";
        bool isRequest = rpc["id"] != null;

        // lifecycle: requests other than initialize/ping before the
        // handshake completed are refused (-32002); notifications are
        // simply ignored (there is nobody to answer). Mirrored in the app
        // bridge so both halves enforce the same rule.
        if (isRequest && !clientInitialized && method != "initialize" && method != "ping")
        {
            stdout.WriteLine(Error(rpc["id"], -32002, "Server not initialized — send initialize first."));
            continue;
        }
        if (method == "initialize")
        {
            clientInitialized = true;
            ClientName = (rpc["params"]?["clientInfo"] as JsonObject)?["name"]?.GetValue<string>() ?? "";
            if (ClientName.Length > 0) LogProxy("client", ClientName);
        }

        var session = ReadSession();
        bool online = session != null;
        bool flipped = online != wasOnline;
        wasOnline = online;

        string response;
        if (online)
            response = await ForwardAsync(session.Value.Port, session.Value.Token, line, rpc["id"]);
        else
            response = AnswerOffline(rpc);

        if (isRequest && !string.IsNullOrEmpty(response))
            stdout.WriteLine(response);

        // the session flipped while this proxy was connected: the client's
        // cached tool list is stale. Tell it only AFTER the response to the
        // in-flight message (usually initialize) has been written, and only
        // if the client finished initializing — a notification racing the
        // initialize response confuses strict clients.
        if (flipped && clientInitialized)
            stdout.WriteLine(new JsonObject
            {
                ["jsonrpc"] = "2.0",
                ["method"] = "notifications/tools/list_changed",
                ["params"] = new JsonObject(),
            }.ToJsonString());
    }
    LogProxy("stop", "stdin closed (client exited)");
}
catch (Exception ex) { LogProxy("stop", "crashed: " + ex.Message); }
// stdin closed — the MCP client is gone

// ── native: Toolhelp32 process snapshot (parent lookup) ─────────────────
static class Native
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll")] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll")] private static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll")] private static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

    public sealed record Entry(uint Pid, uint ParentPid, string Name);

    public static List<Entry> SnapshotProcesses()
    {
        const uint TH32CS_SNAPPROCESS = 2;
        var result = new List<Entry>();
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == IntPtr.Zero) return result;
        try
        {
            var e = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (Process32FirstW(snap, ref e))
                do
                {
                    result.Add(new Entry(e.th32ProcessID, e.th32ParentProcessID, e.szExeFile));
                } while (Process32NextW(snap, ref e));
        }
        finally { CloseHandle(snap); }
        return result;
    }
}
