using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using AutoScope.Engines.Bridge;
using AutoScope.Engines.Core;
using AutoScope.Services;

namespace AutoScope
{
    /// <summary>
    /// App-side composition for the F# AI-bridge engine: adapts the C#
    /// AgentToolRegistry to the engine's IAgentTools seam, constructs the
    /// McpClientCatalog with the app's identity/MCP id/proxy name, and
    /// installs both once at startup (Wire()). The engine carries no app
    /// values; this file is the only place they appear.
    /// </summary>
    public static class BridgeHost
    {
        private sealed class ToolAdapter : IAgentTool
        {
            private readonly AgentToolRegistry.Tool _tool;
            public ToolAdapter(AgentToolRegistry.Tool tool) { _tool = tool; }

            public string Name => _tool.Name;
            public bool Mutating => _tool.Mutating;

            public string ConfirmDetail(string argsJson)
            {
                var confirm = _tool.ConfirmDetail;
                if (confirm == null) return null;
                var args = JsonNode.Parse(argsJson ?? "{}") as JsonObject ?? new JsonObject();
                return confirm(args);
            }

            public string Invoke(string argsJson)
            {
                var args = JsonNode.Parse(argsJson ?? "{}") as JsonObject ?? new JsonObject();
                return _tool.Handler(args);
            }
        }

        private sealed class ToolRegistryAdapter : IAgentTools
        {
            public IList<string> Names(bool allowMutating) =>
                new List<string>(AgentToolRegistry.Names(allowMutating));

            public string ListTools(bool allowMutating) =>
                AgentToolRegistry.Descriptors(allowMutating).ToJsonString();

            public IAgentTool Find(string name, bool allowMutating)
            {
                var tool = AgentToolRegistry.Find(name, allowMutating);
                return tool == null ? null : new ToolAdapter(tool);
            }

            public string BuildMonitorSnapshot() =>
                AgentToolRegistry.BuildMonitorSnapshot().ToJsonString();
        }

        public static readonly McpClientCatalog Catalog =
            new McpClientCatalog(Identity.autoscope(), "autoscope", "AutoScope.AgentProxy.exe");

        /// <summary>Call once at app startup, before any session can start.</summary>
        public static void Wire()
        {
            AutoScope.Engines.Bridge.AgentBridgeService.Ui = new AgentBridgeUI();
            AutoScope.Engines.Bridge.AgentBridgeService.Shared =
                new AutoScope.Engines.Bridge.AgentBridgeService(
                    Identity.autoscope(), new ToolRegistryAdapter());
        }
    }
}
