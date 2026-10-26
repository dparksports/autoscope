// F# port of the AI-bridge seam types. IAgentBridgeUI is lifted from
// Core\Services\AgentBridgeService.cs; IAgentTool / IAgentTools stand in
// for the static AgentToolRegistry (Core\Services\AgentToolRegistry.cs)
// the C# bridge called directly — this library is the transport/session
// layer only, the tool surface stays app-side and is injected here.
// C#-friendly surface: same member names, no Option/DU in the public API,
// Task shapes match the C#, and JSON crosses as string so node ownership
// never becomes a shared-parent trap between bridge and app.
namespace AutoScope.Engines.Bridge

open System
open System.Collections.Generic
open System.Threading.Tasks

/// <summary>
/// UI hooks the app front end installs at startup (AgentBridgeService.Ui)
/// so the bridge can marshal to the UI thread and ask the user to confirm
/// mutating tool calls (the port of AutoCommand's WPF AgentConfirmWindow
/// flow). Same members as the C# IAgentBridgeUI.
/// </summary>
type IAgentBridgeUI =
    /// <summary>True when a window exists to confirm with.</summary>
    abstract IsUiAvailable: bool

    /// <summary>Runs the action on the UI thread (fire-and-forget).</summary>
    abstract BeginInvokeOnUI: action: Action -> unit

    /// <summary>Shows the confirmation dialog and returns the user's
    /// answer: (allowed, always-for-this-tool). Async because UI dialogs
    /// are async; the bridge already waits on a TaskCompletionSource with
    /// a timeout. F# port: the pair crosses as Task&lt;(bool, bool)&gt; —
    /// tuple element names (Allowed, AlwaysForTool) are C# metadata; a C#
    /// implementation declares them as usual and still satisfies this
    /// interface.</summary>
    abstract ShowConfirmAsync: tool: string * detail: string -> Task<bool * bool>

/// <summary>
/// One tool the app publishes through the bridge. F# port: the C#
/// AgentToolRegistry.Tool record (Name, Description, Schema, Mutating,
/// Handler, ConfirmDetail) reduced to what the bridge's control flow
/// actually reads — description and inputSchema travel inside the
/// ListTools JSON. argsJson is the MCP call's "arguments" object
/// serialized; handlers re-parse it.
/// </summary>
type IAgentTool =
    /// <summary>Tool name as MCP clients see it (e.g. "block_ip").</summary>
    abstract Name: string

    /// <summary>True when every call needs the per-action confirmation
    /// dialog before it may run.</summary>
    abstract Mutating: bool

    /// <summary>Human text shown in the confirmation dialog for this call
    /// (e.g. "Create outbound firewall BLOCK rules for 1.2.3.4?").</summary>
    abstract ConfirmDetail: argsJson: string -> string

    /// <summary>Executes the tool (the bridge runs it on a background
    /// thread) and returns its text output.</summary>
    abstract Invoke: argsJson: string -> string

/// <summary>
/// The tool surface an app injects into AgentBridgeService. F# port: the
/// C# bridge called the static AgentToolRegistry directly; those exact
/// dispatch call sites became these members so the app's registry can
/// implement them (in C#) at integration:
/// AgentToolRegistry.Names → Names, Descriptors → ListTools,
/// Find → Find, BuildMonitorSnapshot → BuildMonitorSnapshot.
/// </summary>
type IAgentTools =
    /// <summary>Names of the tools visible for a session — written into
    /// session.json's "tools" array. C# source: AgentToolRegistry.Names
    /// (allowMutating=false filters the mutating tools out).</summary>
    abstract Names: allowMutating: bool -> IList<string>

    /// <summary>The tools/list payload: JSON ARRAY text of the MCP tool
    /// descriptors ([{ "name": ..., "description": ...,
    /// "inputSchema": ... }, ...]). C# source:
    /// AgentToolRegistry.Descriptors(allowMutating).</summary>
    abstract ListTools: allowMutating: bool -> string

    /// <summary>Looks one tool up; null when unknown, or when it is
    /// mutating and the session does not allow mutating. C# source:
    /// AgentToolRegistry.Find(name, includeMutating).</summary>
    abstract Find: name: string * allowMutating: bool -> IAgentTool

    /// <summary>Full monitor snapshot as JSON OBJECT text for the periodic
    /// feed (feed.jsonl); may return null when the host has nothing to
    /// publish (the feed line is skipped). C# source:
    /// AgentToolRegistry.BuildMonitorSnapshot.</summary>
    abstract BuildMonitorSnapshot: unit -> string
