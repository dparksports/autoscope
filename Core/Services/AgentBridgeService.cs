using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;


namespace AutoScope.Services
{
    /// <summary>
    /// UI hooks the WinUI front end installs at startup so the bridge can
    /// marshal to the UI thread and ask the user to confirm mutating tool
    /// calls (the port of AutoCommand's WPF AgentConfirmWindow flow).
    /// </summary>
    public interface IAgentBridgeUI
    {
        /// <summary>True when a window exists to confirm with.</summary>
        bool IsUiAvailable { get; }

        /// <summary>Runs the action on the UI thread (fire-and-forget).</summary>
        void BeginInvokeOnUI(System.Action action);

        /// <summary>Shows the confirmation dialog and returns the user's
        /// answer: (allowed, always-for-this-tool). Async because WinUI
        /// dialogs are async; the bridge already waits on a
        /// TaskCompletionSource with a timeout.</summary>
        System.Threading.Tasks.Task<(bool Allowed, bool AlwaysForTool)> ShowConfirmAsync(string tool, string detail);
    }

    /// <summary>
    /// The AI-access bridge: a loopback-only MCP endpoint hosted INSIDE the
    /// running (elevated) AutoScope process.
    ///
    /// Trust model — the app is the broker:
    ///   • The user starts a session from Settings → "AI access" (or the app
    ///     is launched with --agent-headless). Starting writes
    ///     %LOCALAPPDATA%\AutoScope\agent\session.json {port, token, pid}.
    ///   • An MCP client spawns THIS SAME EXE with --agent-stdio (headless,
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
    public class AgentBridgeService
    {
        public static AgentBridgeService Instance { get; } = new();

        /// <summary>Installed by the WinUI app at startup; without it the
        /// bridge still serves read-only tools but cannot confirm mutating
        /// ones (same behavior as AutoCommand's headless sessions).</summary>
        public static IAgentBridgeUI Ui { get; set; }

        private const int PortBase = 47921;
        private const int PortRange = 20;
        private const int MaxBodyBytes = 4 * 1024 * 1024;
        private const int ConfirmTimeoutMs = 90_000;

        public static string AgentDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoScope", "agent");
        private static string SessionPath => Path.Combine(AgentDir, "session.json");
        private static string ActivityPath => Path.Combine(AgentDir, "activity.jsonl");
        private static string FeedPath => Path.Combine(AgentDir, "feed.jsonl");

        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private string _token = "";
        private int _port;
        private bool _allowMutating;
        private bool _clientInitialized;
        private readonly object _sessionToolsLock = new();
        private readonly HashSet<string> _sessionAllowedTools = new(System.StringComparer.Ordinal);
        public string ClientName { get; private set; } = "";
        public int ConnectedCalls { get; private set; }

        public bool IsRunning => _listener != null;
        public int Port => _port;
        public bool AllowMutating => _allowMutating;

        /// <summary>Fires on bridge state changes (session started/stopped, tool calls) for UI status.</summary>
        public event Action<string> Activity;

        // ── session lifecycle ─────────────────────────────────────────────

        public (bool Ok, string Message) Start(bool allowMutating)
        {
            if (IsRunning) return (false, "AI access session is already running.");

            _token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            _allowMutating = allowMutating;
            lock (_sessionToolsLock) _sessionAllowedTools.Clear();
            ClientName = "";
            _clientInitialized = false; // a new session is a new MCP lifecycle
            ConnectedCalls = 0;

            TcpListener listener = null;
            int port = 0;
            for (int p = PortBase; p < PortBase + PortRange; p++)
            {
                try
                {
                    listener = new TcpListener(IPAddress.Loopback, p);
                    listener.Start();
                    port = p;
                    break;
                }
                catch { /* port taken — try the next */ }
            }
            if (listener == null) return (false, $"No free port in {PortBase}–{PortBase + PortRange - 1}.");

            _listener = listener;
            _port = port;
            _cts = new CancellationTokenSource();
            _ = Task.Run(() => AcceptLoop(listener, _cts.Token));

            Directory.CreateDirectory(AgentDir);
            var session = new JsonObject
            {
                ["port"] = port,
                ["token"] = _token,
                ["pid"] = Process.GetCurrentProcess().Id,
                ["startedUtc"] = DateTime.UtcNow.ToString("o"),
                ["mutatingAllowed"] = allowMutating,
                ["tools"] = new JsonArray(AgentToolRegistry.Names(_allowMutating).Select(n => (JsonNode)n).ToArray()),
            };
            File.WriteAllText(SessionPath, session.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));

            AppendFeed(new JsonObject { ["type"] = "session_started", ["port"] = port, ["mutatingAllowed"] = allowMutating });
            LogActivity("session", "started", $"loopback port {port}, mutating {(allowMutating ? "on (each action asks)" : "off")}");
            Activity?.Invoke("session started");
            return (true, $"Listening on 127.0.0.1:{port}.");
        }

        public void Stop()
        {
            if (!IsRunning) return;
            try { _cts?.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }
            _listener = null;
            _cts?.Dispose();
            _cts = null;
            try { if (File.Exists(SessionPath)) File.Delete(SessionPath); } catch { }
            LogActivity("session", "stopped", "");
            Activity?.Invoke("session stopped");
        }

        /// <summary>True when a live session file matches a running bridge (crash-cleanup helper for the stdio bridge).</summary>
        public static (int Port, string Token) ReadSession()
        {
            var node = JsonNode.Parse(File.ReadAllText(SessionPath)) as JsonObject;
            return (node?["port"]?.GetValue<int>() ?? 0, node?["token"]?.GetValue<string>() ?? "");
        }

        public static bool SessionFileExists => File.Exists(SessionPath);

        /// <summary>Last N activity lines (newest first) for the Settings card.</summary>
        public static List<string> RecentActivity(int count = 30)
        {
            var lines = new List<string>();
            try
            {
                if (File.Exists(ActivityPath))
                    foreach (string line in File.ReadLines(ActivityPath).Reverse().Take(count))
                        lines.Add(line);
            }
            catch { }
            return lines;
        }

        // ── accept + minimal HTTP/1.1 ─────────────────────────────────────

        private async Task AcceptLoop(TcpListener listener, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(ct); }
                catch { break; } // listener stopped
                _ = Task.Run(() => HandleClient(client, ct));
            }
        }

        private async Task HandleClient(TcpClient client, CancellationToken ct)
        {
            try
            {
                using (client)
                {
                    client.ReceiveTimeout = 120_000;
                    var stream = client.GetStream();

                    string head = await ReadUntilAsync(stream, "\r\n\r\n", 64 * 1024);
                    if (head == null) return;
                    var lines = head.Split("\r\n");
                    string[] requestLine = lines[0].Split(' ');
                    string method = requestLine.Length > 0 ? requestLine[0] : "";
                    var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 1; i < lines.Length; i++)
                    {
                        int c = lines[i].IndexOf(':');
                        if (c > 0) headers[lines[i][..c].Trim()] = lines[i][(c + 1)..].Trim();
                    }

                    if (method != "POST")
                    {
                        await WriteJsonResponse(stream, method == "GET" ? 405 : 400,
                            "{\"error\":\"POST only (MCP streamable HTTP, stateless)\"}");
                        return;
                    }
                    if (!headers.TryGetValue("Host", out string host) ||
                        !(host.StartsWith("127.0.0.1:", StringComparison.OrdinalIgnoreCase) ||
                          host.StartsWith("localhost:", StringComparison.OrdinalIgnoreCase)))
                    {
                        await WriteJsonResponse(stream, 403, "{\"error\":\"loopback only\"}");
                        return;
                    }
                    if (!headers.TryGetValue("Authorization", out string auth) || !TokenMatches(auth))
                    {
                        await WriteJsonResponse(stream, 401, "{\"error\":\"bad or missing session token\"}");
                        return;
                    }

                    int contentLength = headers.TryGetValue("Content-Length", out string cl) && int.TryParse(cl, out int n) ? n : 0;
                    if (contentLength is < 0 or > MaxBodyBytes)
                    {
                        await WriteJsonResponse(stream, 413, "{\"error\":\"body too large\"}");
                        return;
                    }
                    if (headers.TryGetValue("Expect", out string expect) && expect.Contains("100-continue"))
                        await WriteRaw(stream, "HTTP/1.1 100 Continue\r\n\r\n");

                    string body = contentLength == 0 ? "" : await ReadExactAsync(stream, contentLength);

                    var rpc = JsonNode.Parse(body) as JsonObject;
                    if (rpc == null)
                    {
                        await WriteJsonResponse(stream, 400, RpcError(null, -32700, "Parse error"));
                        return;
                    }

                    string rpcId = rpc["id"]?.ToJsonString(); // null for notifications
                    string jsonResponse = await DispatchAsync(rpc, headers.TryGetValue("User-Agent", out var ua) ? ua : "");
                    if (rpcId == null || jsonResponse == null)
                    {
                        await WriteRaw(stream, "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        return;
                    }
                    await WriteResponse(stream, 200, JsonNode.Parse(jsonResponse) as JsonObject);
                }
            }
            catch { /* client vanished mid-request — nothing to salvage */ }
        }

        private bool TokenMatches(string authHeader)
        {
            if (authHeader == null || _token.Length == 0) return false;
            const string prefix = "Bearer ";
            if (!authHeader.StartsWith(prefix, StringComparison.Ordinal)) return false;
            byte[] given = Encoding.UTF8.GetBytes(authHeader[prefix.Length..]);
            byte[] expected = Encoding.UTF8.GetBytes(_token);
            return given.Length == expected.Length && CryptographicOperations.FixedTimeEquals(given, expected);
        }

        // ── MCP dispatch ──────────────────────────────────────────────────

        // Protocol versions this bridge actually implements — must match the
        // proxy's set (see AgentProxy\Program.cs): initialize/notifications/*,
        // ping, tools/list, tools/call; resources/* and prompts/* answer -32601.
        private static readonly string[] SupportedProtocols = { "2024-11-05", "2025-03-26", "2025-06-18" };

        private static string NegotiateProtocol(string requested) =>
            !string.IsNullOrEmpty(requested) && Array.IndexOf(SupportedProtocols, requested) >= 0
                ? requested
                : SupportedProtocols[^1];

        internal async Task<string> DispatchAsync(JsonObject rpc, string userAgent)
        {
            string method = rpc["method"]?.GetValue<string>() ?? "";
            JsonObject @params = rpc["params"] as JsonObject;
            bool isNotification = rpc["id"] == null;

            // MCP lifecycle: requests before initialize are refused (-32002).
            // ping stays answerable (clients probe with it), notifications
            // are dropped — there is nobody to answer. Mirrored in the proxy
            // so both halves enforce the same rule.
            if (!isNotification && !_clientInitialized && method != "initialize" && method != "ping")
                return RpcError(rpc["id"], -32002, "Server not initialized — send initialize first.");

            try
            {
                switch (method)
                {
                    case "initialize":
                        string requested = @params?["protocolVersion"]?.GetValue<string>();
                        var clientInfo = @params?["clientInfo"] as JsonObject;
                        string clientName = clientInfo?["name"]?.GetValue<string>();
                        ClientName = !string.IsNullOrEmpty(clientName) ? clientName
                            : !string.IsNullOrEmpty(userAgent) ? userAgent : "unknown";
                        _clientInitialized = true;
                        LogActivity("client", "connected", ClientName);
                        Activity?.Invoke($"client connected: {ClientName}");
                        string negotiated = NegotiateProtocol(requested);
                        if (negotiated != requested)
                            LogActivity("client", "protocol", $"requested {requested ?? "(none)"} — answered {negotiated}");
                        return RpcResult(rpc["id"], new JsonObject
                        {
                            // negotiate, never blind-echo: echoing an arbitrary
                            // version string claimed protocols we do not speak
                            ["protocolVersion"] = negotiated,
                            ["capabilities"] = new JsonObject { ["tools"] = new JsonObject { ["listChanged"] = false } },
                            ["serverInfo"] = new JsonObject
                            {
                                ["name"] = "autoscope",
                                // same title offline and online so the client UI
                                // never relabels the server when a session flips
                                ["title"] = "AutoScope (agent bridge)",
                                ["version"] = FileVersionInfo.GetVersionInfo(Environment.ProcessPath ?? "AutoScope.exe").ProductVersion ?? "?",
                            },
                            ["instructions"] = "Read-only security telemetry from the locally running AutoScope app " +
                                "(process monitor, svchost identity, PID provenance, Sysmon tail, trace analysis). " +
                                "Mutating tools (block/kill/disable) ask the user for confirmation in the app UI on every call " +
                                "and are only present when the user enabled them for the session.",
                        });

                    case "notifications/initialized":
                    case "notifications/cancelled":
                        return null;

                    case "ping":
                        return RpcResult(rpc["id"], new JsonObject());

                    case "tools/list":
                        return RpcResult(rpc["id"], new JsonObject { ["tools"] = AgentToolRegistry.Descriptors(_allowMutating) });

                    case "tools/call":
                        string name = @params?["name"]?.GetValue<string>() ?? "";
                        var args = @params?["arguments"] as JsonObject ?? new JsonObject();
                        ConnectedCalls++;
                        var (content, isError) = await CallToolAsync(name, args);
                        LogActivity("tool", name, SummarizeArgs(args), isError ? "error" : "ok");
                        Activity?.Invoke($"tool {name} → {(isError ? "error" : "ok")}");
                        return RpcResult(rpc["id"], new JsonObject
                        {
                            ["content"] = new JsonArray { new JsonObject { ["type"] = "text", ["text"] = content } },
                            ["isError"] = isError,
                        });

                    default:
                        if (isNotification) return null;
                        return RpcError(rpc["id"], -32601, $"Unknown method: {method}");
                }
            }
            catch (Exception ex)
            {
                if (isNotification) return null;
                return RpcResult(rpc["id"], new JsonObject
                {
                    ["content"] = new JsonArray { new JsonObject { ["type"] = "text", ["text"] = "tool failed: " + ex.Message } },
                    ["isError"] = true,
                });
            }
        }

        private async Task<(string content, bool isError)> CallToolAsync(string name, JsonObject args)
        {
            var tool = AgentToolRegistry.Find(name, _allowMutating);
            if (tool == null) return ($"Unknown tool '{name}' (or mutating tools are disabled for this session).", true);

            if (tool.Mutating && !SessionGranted(name))
            {
                var (allowed, note) = RequestConfirmation(name, tool.ConfirmDetail(args));
                if (!allowed) return ($"User denied '{name}'" + (note.Length > 0 ? $" — {note}" : "") + ".", true);
            }
            string output = await Task.Run(() => tool.Handler(args));
            return (output, false);
        }

        private bool SessionGranted(string tool)
        {
            lock (_sessionToolsLock) return _sessionAllowedTools.Contains(tool);
        }

        // ── per-action confirmation (Tier 3) ──────────────────────────────

        /// <summary>
        /// Asks the user at the app's UI. Runs on the dispatcher; returns
        /// after the user answers or the timeout elapses (deny). "Always for
        /// this session" grants are remembered per tool until Stop().
        /// </summary>
        public (bool Allowed, string Note) RequestConfirmation(string tool, string detail)
        {
            if (!_allowMutating) return (false, "mutating tools are disabled for this session");

            var ui = Ui;
            if (ui == null || !ui.IsUiAvailable)
                return (false, "headless session has no UI to confirm with — restart the session from AutoScope Settings to allow mutating tools");

            var tcs = new TaskCompletionSource<(bool, bool, string)>(TaskCreationOptions.RunContinuationsAsynchronously);
            ui.BeginInvokeOnUI(async () =>
            {
                try
                {
                    var (allowed, always) = await ui.ShowConfirmAsync(tool, detail);
                    tcs.TrySetResult((allowed, always, allowed ? "allowed by user" : "denied by user"));
                }
                catch (Exception ex) { tcs.TrySetResult((false, false, "confirm dialog failed: " + ex.Message)); }
            });

            var completed = Task.WhenAny(tcs.Task, Task.Delay(ConfirmTimeoutMs)).GetAwaiter().GetResult();
            if (completed != tcs.Task) return (false, $"no answer in {ConfirmTimeoutMs / 1000}s");
            var (allowed, always, note) = tcs.Task.Result;
            if (allowed && always)
            {
                lock (_sessionToolsLock) _sessionAllowedTools.Add(tool);
                LogActivity("session", "grant", $"{tool} allowed for the rest of the session");
            }
            return (allowed, note);
        }

        // ── activity log + feed (Phase 1) ─────────────────────────────────

        private void LogActivity(string kind, string what, string detail, string outcome = null)
        {
            try
            {
                Directory.CreateDirectory(AgentDir);
                var line = new JsonObject
                {
                    ["t"] = DateTime.Now.ToString("o"),
                    ["kind"] = kind,
                    ["what"] = what,
                    ["client"] = ClientName ?? "",
                };
                if (!string.IsNullOrEmpty(detail)) line["detail"] = detail;
                if (outcome != null) line["outcome"] = outcome;
                File.AppendAllText(ActivityPath, line.ToJsonString() + "\n");
            }
            catch { /* best-effort audit trail */ }
        }

        private void AppendFeed(JsonObject snapshot)
        {
            try
            {
                Directory.CreateDirectory(AgentDir);
                snapshot["t"] = DateTime.Now.ToString("o");
                File.AppendAllText(FeedPath, snapshot.ToJsonString() + "\n");
            }
            catch { /* best-effort feed */ }
        }

        /// <summary>Phase 1: periodic full snapshot so offline agents can read state from the file alone.</summary>
        private async Task FeedLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try { AppendFeed(AgentToolRegistry.BuildMonitorSnapshot()); } catch { }
                try { await Task.Delay(60_000, ct); } catch { break; }
            }
        }

        private void StartFeed()
        {
            _ = Task.Run(() => FeedLoop(_cts.Token));
        }

        // ── plumbing ──────────────────────────────────────────────────────

        private static async Task<string> ReadUntilAsync(NetworkStream stream, string terminator, int maxBytes)
        {
            var buffer = new byte[1];
            var sb = new StringBuilder();
            var raw = new MemoryStream();
            while (sb.ToString().EndsWith(terminator, StringComparison.Ordinal) == false && raw.Length < maxBytes)
            {
                int n = await stream.ReadAsync(buffer, 0, 1);
                if (n == 0) return sb.Length == 0 ? null : sb.ToString();
                raw.WriteByte(buffer[0]);
                sb.Append((char)buffer[0]);
            }
            return sb.ToString();
        }

        private static async Task<string> ReadExactAsync(NetworkStream stream, int count)
        {
            var buffer = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = await stream.ReadAsync(buffer, read, count - read);
                if (n == 0) break;
                read += n;
            }
            return Encoding.UTF8.GetString(buffer, 0, read);
        }

        private static async Task WriteRaw(NetworkStream stream, string text)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(text);
            await stream.WriteAsync(bytes, 0, bytes.Length);
            await stream.FlushAsync();
        }

        private static async Task WriteResponse(NetworkStream stream, int status, JsonObject body)
        {
            await WriteJsonResponse(stream, status, body?.ToJsonString() ?? "");
        }

        private static async Task WriteJsonResponse(NetworkStream stream, int status, string json)
        {
            byte[] payload = Encoding.UTF8.GetBytes(json ?? "");
            string reason = status switch { 200 => "OK", 202 => "Accepted", 400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 405 => "Method Not Allowed", 413 => "Payload Too Large", _ => "Error" };
            string head = $"HTTP/1.1 {status} {reason}\r\n" +
                          "Content-Type: application/json\r\n" +
                          $"Content-Length: {payload.Length}\r\n" +
                          "Connection: close\r\n\r\n";
            await WriteRaw(stream, head);
            if (payload.Length > 0) await stream.WriteAsync(payload, 0, payload.Length);
            await stream.FlushAsync();
        }

        private static string RpcResult(JsonNode id, JsonObject result)
        {
            return new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id?.DeepClone(), ["result"] = result }.ToJsonString();
        }

        private static string RpcError(JsonNode id, int code, string message)
        {
            return new JsonObject
            {
                ["jsonrpc"] = "2.0",
                ["id"] = id?.DeepClone(),
                ["error"] = new JsonObject { ["code"] = code, ["message"] = message },
            }.ToJsonString();
        }

        private static string SummarizeArgs(JsonObject args)
        {
            try { return args.ToJsonString(); }
            catch { return ""; }
        }
    }
}
