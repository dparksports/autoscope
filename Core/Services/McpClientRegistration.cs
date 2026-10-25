using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AutoScope.Services
{
    /// <summary>
    /// One MCP client AutoScope knows how to register the 'autoscope'
    /// server into, in one click from the Be My Guest tab.
    /// </summary>
    public sealed class McpClientRegistration
    {
        public string Id;            // stable id (button Tag)
        public string DisplayName;   // button label
        public string ConfigPath;    // user-scope config file (may not exist yet)
        public string RootKeyPath;   // path to the servers map inside the file,
                                     // '/'-separated: "mcp/servers" (ZCode),
                                     // "servers" (VS Code), "mcpServers" (most)
        public bool IncludeType;     // VS Code entries want "type": "stdio"
        public string DetectDir;     // existence probe for the client's install
        public string Note;          // appended to the success dialog, may be null
    }

    public static class McpClientCatalog
    {
        // ── client catalog ────────────────────────────────────────────────
        // User-scope only (per-repo/project scopes are deliberately out of
        // scope here — 'Copy MCP config' covers them). Paths verified against
        // each client's current docs; see the Notes for known drift.

        private static string Env(Environment.SpecialFolder folder) => Environment.GetFolderPath(folder);

        public static readonly IReadOnlyList<McpClientRegistration> Catalog = new[]
        {
            new McpClientRegistration
            {
                Id = "zcode", DisplayName = "ZCode",
                ConfigPath = Path.Combine(Env(Environment.SpecialFolder.UserProfile), ".zcode", "cli", "config.json"),
                RootKeyPath = "mcp/servers", DetectDir = Path.Combine(Env(Environment.SpecialFolder.UserProfile), ".zcode"),
                Note = null,
            },
            new McpClientRegistration
            {
                Id = "cursor", DisplayName = "Cursor",
                ConfigPath = Path.Combine(Env(Environment.SpecialFolder.UserProfile), ".cursor", "mcp.json"),
                RootKeyPath = "mcpServers", DetectDir = Path.Combine(Env(Environment.SpecialFolder.UserProfile), ".cursor"),
                Note = null,
            },
            new McpClientRegistration
            {
                Id = "windsurf", DisplayName = "Windsurf",
                ConfigPath = Path.Combine(Env(Environment.SpecialFolder.UserProfile), ".codeium", "windsurf", "mcp_config.json"),
                RootKeyPath = "mcpServers", DetectDir = Path.Combine(Env(Environment.SpecialFolder.UserProfile), ".codeium", "windsurf"),
                Note = null,
            },
            new McpClientRegistration
            {
                Id = "vscode", DisplayName = "VS Code",
                ConfigPath = Path.Combine(Env(Environment.SpecialFolder.ApplicationData), "Code", "User", "mcp.json"),
                RootKeyPath = "servers", IncludeType = true,
                DetectDir = Path.Combine(Env(Environment.SpecialFolder.ApplicationData), "Code", "User"),
                Note = "In VS Code, run 'Developer: Reload Window' (or restart it) to pick up the new server.",
            },
            new McpClientRegistration
            {
                Id = "claude-desktop", DisplayName = "Claude Desktop",
                ConfigPath = Path.Combine(Env(Environment.SpecialFolder.ApplicationData), "Claude", "claude_desktop_config.json"),
                RootKeyPath = "mcpServers", DetectDir = Path.Combine(Env(Environment.SpecialFolder.ApplicationData), "Claude"),
                Note = null,
            },
            new McpClientRegistration
            {
                Id = "gemini", DisplayName = "Gemini Antigravity",
                ConfigPath = Path.Combine(Env(Environment.SpecialFolder.UserProfile), ".gemini", "config", "mcp_config.json"),
                RootKeyPath = "mcpServers", DetectDir = Path.Combine(Env(Environment.SpecialFolder.UserProfile), ".gemini"),
                Note = "Some Antigravity CLI versions read %USERPROFILE%\\.gemini\\antigravity-cli\\mcp_config.json " +
                       "instead — if the CLI doesn't pick the server up, copy the file there too.",
            },
        };

        // ── registration ──────────────────────────────────────────────────

        public static bool IsDetected(McpClientRegistration client) =>
            Directory.Exists(client.DetectDir);

        /// <summary>
        /// Writes the 'autoscope' entry into the client's config: parse the
        /// existing file, back it up, upsert only our entry, verify by
        /// re-reading. A malformed or foreign-shaped file is never clobbered.
        /// </summary>
        public static (bool ok, string message) Register(McpClientRegistration client, string proxyPath)
        {
            try
            {
                var entry = new JsonObject();
                if (client.IncludeType) entry["type"] = "stdio";
                entry["command"] = proxyPath;
                entry["args"] = new JsonArray();

                var (ok, error) = UpsertEntry(client.ConfigPath, client.RootKeyPath, "autoscope", entry);
                if (!ok) return (false, error);

                string message =
                    "Registered the 'autoscope' MCP server for " + client.DisplayName + " (user scope):\n" +
                    client.ConfigPath +
                    "\n\nProxy: " + proxyPath +
                    "\n\nNew " + client.DisplayName + " sessions will auto-connect it. Tools answer with " +
                    "setup guidance whenever no AI session is active here.";
                if (!string.IsNullOrEmpty(client.Note)) message += "\n\n" + client.Note;
                return (true, message);
            }
            catch (Exception ex)
            {
                return (false, "Could not update the " + client.DisplayName + " config:\n" + ex.Message +
                    "\n\nUse 'Copy MCP config' and add the entry by hand.");
            }
        }

        /// <summary>
        /// Shared merge: idempotent, backup-before-write, verify-after-write.
        /// rootKeyPath is '/'-separated ("mcp/servers" for ZCode, "servers"
        /// for VS Code, "mcpServers" for most) — missing levels are created,
        /// non-object levels abort instead of being overwritten.
        /// </summary>
        internal static (bool ok, string error) UpsertEntry(string configPath, string rootKeyPath, string serverName, JsonObject entry)
        {
            JsonObject root = null;
            if (File.Exists(configPath))
            {
                string text = File.ReadAllText(configPath);
                if (!string.IsNullOrWhiteSpace(text))
                {
                    try { root = JsonNode.Parse(text) as JsonObject; }
                    catch (JsonException) { root = null; } // malformed → refuse below, never clobber
                    if (root == null)
                        return (false, "The config is not a readable JSON object — not touching it:\n" + configPath +
                            "\n\nUse 'Copy MCP config' and add the entry by hand.");
                    File.WriteAllText(configPath + ".autoscope-backup", text); // revert is a rename away
                }
            }
            root ??= new JsonObject();

            var keys = rootKeyPath.Split('/');
            JsonObject section = root;
            for (int i = 0; i < keys.Length; i++)
            {
                var next = section[keys[i]] as JsonObject;
                if (next == null && section[keys[i]] != null)
                    return (false, "The config already has a '" + keys[i] + "' that is not an object — not touching it:\n" +
                        configPath + "\n\nUse 'Copy MCP config' and add the entry by hand.");
                next ??= new JsonObject();
                section[keys[i]] = next;
                section = next;
            }
            section[serverName] = entry.DeepClone(); // clone: callers may reuse the node across registrations

            Directory.CreateDirectory(Path.GetDirectoryName(configPath));
            File.WriteAllText(configPath, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));

            // verify: the re-read file must carry our entry exactly
            var check = JsonNode.Parse(File.ReadAllText(configPath));
            foreach (string k in keys) check = check?[k];
            var verifiedEntry = check?[serverName] as JsonObject;
            bool verified = verifiedEntry != null &&
                            verifiedEntry["command"]?.GetValue<string>() == entry["command"]!.GetValue<string>();
            return verified
                ? (true, null)
                : (false, "Wrote the config but verification re-read failed:\n" + configPath +
                    "\n\nCheck the file, or use 'Copy MCP config' by hand.");
        }

        // ── proxy install ─────────────────────────────────────────────────

        // The proxy ships as a self-contained single-file exe (release.ps1
        // publishes it into the zip's tools\AgentProxy\): the runtime is
        // bundled, so no framework lookup happens at spawn time and a client
        // that exports its own DOTNET_ROOT (desktop MCP clients bundling an
        // older .NET do this) cannot break it. The framework-dependent
        // 4-file set this class used to copy is legacy — still honored as a
        // previously-installed fallback, never written anew.

        private static readonly string[] LegacyProxyFiles =
        {
            "AutoScope.AgentProxy.exe",
            "AutoScope.AgentProxy.dll",
            "AutoScope.AgentProxy.runtimeconfig.json",
            "AutoScope.AgentProxy.deps.json",
        };

        private static string ToolsRoot => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoScope", "tools");

        // A versioned install counts as complete only when its marker file
        // exists — the marker is written last, after every file copied
        // cleanly, so a half-copied folder is never handed to a client.
        private static bool VersionedInstallComplete(string dir) =>
            File.Exists(Path.Combine(dir, "proxy.installed"));

        private static bool LegacyComplete(string dir) =>
            LegacyProxyFiles.All(f => File.Exists(Path.Combine(dir, f)));

        private static string AppVersion()
        {
            try { return FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion ?? "0"; }
            catch { return "0"; }
        }

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
        /// Core with injectable inputs so ProxyInstallSelfTest can drive it.
        /// </summary>
        internal static (string ProxyPath, string Message) ResolveAndInstallProxy(
            string appVersion, string toolsRoot, IEnumerable<string> sourceDirs)
        {
            string target = Path.Combine(toolsRoot, "v" + appVersion);
            string targetExe = Path.Combine(target, "AutoScope.AgentProxy.exe");

            if (VersionedInstallComplete(target))
                return (targetExe, "proxy v" + appVersion + " already installed");

            string firstError = null;
            foreach (string src in sourceDirs)
            {
                if (!File.Exists(Path.Combine(src, "AutoScope.AgentProxy.exe"))) continue;
                try
                {
                    Directory.CreateDirectory(target);
                    foreach (string file in Directory.GetFiles(src))
                        File.Copy(file, Path.Combine(target, Path.GetFileName(file)), overwrite: true);
                    File.WriteAllText(Path.Combine(target, "proxy.installed"),
                        new JsonObject { ["version"] = appVersion, ["copiedUtc"] = DateTime.UtcNow.ToString("o") }.ToJsonString());
                    CleanStaleInstalls(toolsRoot, keep: target);
                    return (targetExe, "installed proxy v" + appVersion + " from " + src);
                }
                catch (Exception ex)
                {
                    firstError ??= ex.Message; // remember why, try the next source
                    TryDeleteDir(target);      // half-copied folder must not look complete
                }
            }

            // nothing installable — keep the previously-good path (newest
            // complete versioned install, else the legacy flat set) and say so
            (string ProxyPath, string Message) Keep(string what, string path) =>
                (path, "could not install proxy v" + appVersion +
                       (firstError != null ? " (" + firstError + ")" : " (no source found)") +
                       " — keeping " + what);

            string fallback = null;
            try
            {
                fallback = Directory.Exists(toolsRoot)
                    ? Directory.GetDirectories(toolsRoot, "v*")
                        .Where(VersionedInstallComplete)
                        .OrderByDescending(TryParseVersion)
                        .FirstOrDefault()
                    : null;
            }
            catch { /* unreadable tools dir — fall through to legacy */ }
            if (fallback != null)
                return Keep("the existing " + Path.GetFileName(fallback), Path.Combine(fallback, "AutoScope.AgentProxy.exe"));
            if (LegacyComplete(toolsRoot))
                return Keep("the legacy flat install", Path.Combine(toolsRoot, "AutoScope.AgentProxy.exe"));
            return (null, "no runnable AutoScope.AgentProxy.exe found next to the app (sources: " +
                          string.Join("; ", sourceDirs) + ")" +
                          (firstError != null ? " — " + firstError : ""));
        }

        private static Version TryParseVersion(string versionedDir)
        {
            try { return new Version(Path.GetFileName(versionedDir).Substring(1)); }
            catch { return new Version(0, 0); }
        }

        /// <summary>
        /// Best-effort cleanup: drop older versioned folders and the legacy
        /// flat files once a newer versioned install exists. A running proxy
        /// holds its files locked — those deletes quietly fail and are
        /// retried on the next install. Never touches the folder just kept.
        /// </summary>
        private static void CleanStaleInstalls(string toolsRoot, string keep)
        {
            try
            {
                foreach (string dir in Directory.GetDirectories(toolsRoot, "v*"))
                    if (!string.Equals(dir, keep, StringComparison.OrdinalIgnoreCase))
                        TryDeleteDir(dir);
                foreach (string file in LegacyProxyFiles) // legacy flat set
                    TryDeleteFile(Path.Combine(toolsRoot, file));
            }
            catch { /* cleanup is opportunistic */ }
        }

        private static void TryDeleteDir(string dir)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); } catch { }
        }

        private static void TryDeleteFile(string file)
        {
            try { if (File.Exists(file)) File.Delete(file); } catch { }
        }

        /// <summary>
        /// Real-input wrapper: sources are searched best-first — the zip's
        /// tools\AgentProxy beside the running app (release layout), then the
        /// repo's publish\v*\tools\AgentProxy and the proxy's own bin\
        /// (dev layout; Release preferred over Debug, newest TFM wins — no
        /// hardcoded TFM string to go stale).
        /// </summary>
        public static (string ProxyPath, string Message) ResolveAndInstallProxy()
        {
            var sources = new List<string>();
            string dir = AppContext.BaseDirectory;
            for (int i = 0; i < 6 && dir != null; i++, dir = Path.GetDirectoryName(dir))
            {
                sources.Add(Path.Combine(dir, "tools", "AgentProxy")); // release layout
                string publishRoot = Path.Combine(dir, "publish");     // dev: release.ps1 output
                if (Directory.Exists(publishRoot))
                    foreach (string v in Directory.GetDirectories(publishRoot, "v*").OrderByDescending(TryParseVersion))
                        sources.Add(Path.Combine(v, "tools", "AgentProxy"));
                string proxyBin = Path.Combine(dir, "AgentProxy", "bin"); // dev: any build output
                if (Directory.Exists(proxyBin))
                    foreach (string cfg in new[] { "Release", "Debug" })
                    {
                        string cfgDir = Path.Combine(proxyBin, cfg);
                        if (!Directory.Exists(cfgDir)) continue;
                        foreach (string tfm in Directory.GetDirectories(cfgDir).OrderByDescending(n => n, StringComparer.OrdinalIgnoreCase))
                            sources.Add(tfm); // framework-dependent exe, plus any win-x64\publish under it
                    }
            }
            return ResolveAndInstallProxy(AppVersion(), ToolsRoot,
                sources.Where(s => Directory.Exists(s)).Distinct(StringComparer.OrdinalIgnoreCase));
        }

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
        public static (bool Ok, string Message) PreflightProxy(string proxyExe)
        {
            if (proxyExe == null || !File.Exists(proxyExe))
                return (false, "AutoScope.AgentProxy.exe is not where it was just installed:\n" + proxyExe);

            string plain = HandshakeOnce(proxyExe, null, out string err1);
            if (plain == null)
                return (false, "the proxy did not answer an MCP handshake when spawned normally:\n" + err1);

            string emptyRoot = Path.Combine(Path.GetTempPath(), "autoscope-empty-dotnet-root");
            Directory.CreateDirectory(emptyRoot);
            string poisoned = HandshakeOnce(proxyExe, emptyRoot, out string err2);
            if (poisoned == null)
                return (false, "the proxy starts normally but dies under a hostile DOTNET_ROOT — " +
                    "the classic desktop-MCP-client failure. Reinstall AutoScope and register again.\n" + err2);

            return (true, null);
        }

        /// <summary>Sends one initialize line, expects one JSON-RPC result line back.</summary>
        private static string HandshakeOnce(string exe, string poisonRoot, out string error)
        {
            error = null;
            try
            {
                var psi = new ProcessStartInfo(exe)
                {
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                if (poisonRoot != null)
                {
                    psi.EnvironmentVariables["DOTNET_ROOT"] = poisonRoot;
                    psi.EnvironmentVariables["DOTNET_ROOT_X64"] = poisonRoot;
                }
                using var p = Process.Start(psi);
                p.StandardInput.WriteLine("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"," +
                    "\"params\":{\"protocolVersion\":\"2025-03-26\",\"clientInfo\":{\"name\":\"autoscope-preflight\",\"version\":\"0\"}}}");
                p.StandardInput.Flush();

                // read lines until a response (a result or an error) shows up;
                // notifications carry no "id" and are skipped
                var deadline = Task.Delay(TimeSpan.FromSeconds(10));
                while (!deadline.IsCompleted)
                {
                    var lineTask = p.StandardOutput.ReadLineAsync();
                    if (Task.WhenAny(lineTask, Task.Delay(1000)).Result != lineTask) continue;
                    string line = lineTask.Result;
                    if (line == null) break;
                    if (line.Contains("\"result\"") || line.Contains("\"error\"")) return line;
                }
                try { p.Kill(); } catch { }
                error = "no JSON-RPC response within 10s (exit code " + (p.HasExited ? p.ExitCode.ToString() : "none") + ")";
                return null;
            }
            catch (Exception ex) { error = ex.Message; return null; }
        }
    }
}
