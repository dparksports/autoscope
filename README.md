# AutoScope — see what your Windows PC is really doing

AutoScope is a native Windows app (WinUI 3 / Windows App SDK 2.5, .NET 10) porting six
tabs from [AutoCommand](https://github.com/dparksports/autocommand-windows):

| Tab | What it does |
|---|---|
| 🔍 **Process Monitor** | Every program talking to the internet, who started it, one-click reversible blocking |
| 🩺 **Site Doctor** | "Why is this site slow?" — a 60-second check that measures, compares and explains |
| 🛡 **Firewall** | Windows Defender Firewall profiles and rules via native COM (INetFwPolicy2) |
| ⛔ **Blocks** | Every firewall block this app created, grouped by the Windows service that made the connection |
| 🤖 **Be My Guest** | Invite an AI assistant (MCP) to read this machine's telemetry — consent-first, revocable |
| ⚙ **Settings** | MOTW unblock, startup task, adapter security, enforcer cadence |

## Running it

Build (or take a self-contained publish) and run `AutoScope.exe` **as administrator** —
same as AutoCommand: no installer, unzip anywhere, elevate, look around.

```powershell
dotnet build App/AutoScope.csproj -c Release
# self-contained (zip-and-run shape)
dotnet publish App/AutoScope.csproj -c Release -r win-x64 --self-contained -o publish_out
```

## Structure

- `Core/` — the engine layer ported from AutoCommand (Services/Helpers/Models +
  SecurityEnforcer + the vendored SvchostAnalyzer core). UI-framework-free; 88 files.
- `App/` — the WinUI 3 front end: NavigationView shell, the six tab pages, dialogs.
- `AgentProxy/` — the tiny asInvoker console exe MCP clients spawn; forwards stdio
  JSON-RPC to the running elevated app over loopback.
- `SiteDoctorSelfTest/` — the offline + loopback self-test for the site-diagnosis
  pipeline, run against the Core copies (`dotnet run --project SiteDoctorSelfTest`).

## Coexisting with AutoCommand

AutoScope keeps its own footprint so both apps can run on the same machine: its
firewall block rules use the `AS-BLOCK` prefix (AutoCommand's are `AC-BLOCK`), data
lives under `%LOCALAPPDATA%\AutoScope`, the AI bridge listens on ports 47921+, and
MCP registrations use the `autoscope` server id. Each app's panic button undoes only
its own rules.

## Not ported (yet)

Tray toasts (WinUI notification API differs), the light theme (this port is fixed
dark), DataGrid grouping and live CollectionView sorting (the toolkit DataGrid has
neither — see the `// WinUI port:` notes in the views), and the community/share
buttons (AutoCommand endpoints).

Apache License 2.0 — engine code ported from AutoCommand, © 2026 Dan Park, magicpoint.ai.
