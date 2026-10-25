# AutoScope v0.1.0 — first release

The first six tabs of [AutoCommand](https://github.com/dparksports/autocommand-windows),
rebuilt as a native Windows app on **WinUI 3 (Windows App SDK 2.5.1) + .NET 10** — same
engines, same undo-first design, new shell.

## What's inside

- **🔍 Process Monitor** — every program talking to the internet, live; PID provenance,
  TX-only lens, one-click reversible blocking (`AS-BLOCK` rules), Blocked-rules fleet
  view with bulk unblock / restore-except-Microsoft / CSV export.
- **🩺 Site Doctor** — "Why is this site slow?" in one 60-second check: recorded-traffic
  fingerprint, capped live probe with control sites, dependency-block analysis, one
  plain-English verdict with the math one expander away.
- **🛡 Firewall** — profile presets (Shields Up and friends), full rule grid over native
  COM (`INetFwPolicy2`), baseline capture with drift auto-fix.
- **⛔ Blocks** — every block grouped by the Windows service that actually made the
  connection, Sysmon-archive attribution repair, and the "a feature broke" restore guide.
- **🤖 Be My Guest** — invite an MCP-capable AI assistant to read this machine's
  telemetry: consent-first sessions, per-action confirmation for mutating tools,
  one-click client registration, headless-safe `autoscope` proxy.
- **⚙ Settings** — Mark-of-the-Web unblock, startup task, adapter auto-mitigation,
  enforcer cadence.

## Verified in this build

- Site Doctor self-test: **ALL PASS** (offline verdict/fingerprint rules + the live
  loopback black-hole TLS probe).
- The published `AutoScope.AgentProxy.exe` answers a real MCP `initialize` handshake.
- Self-contained win-x64 publish builds clean; engines byte-derived from AutoCommand's
  tested service layer.

## Install

Download `AutoScope-v0.1.0-win-x64.zip`, unzip anywhere, right-click `AutoScope.exe` →
**Run as administrator**. No installer; deleting the folder uninstalls it.

## Coexists with AutoCommand

Own rule prefix (`AS-BLOCK` vs `AC-BLOCK`), own data under `%LOCALAPPDATA%\AutoScope`,
own bridge ports (47921+), own `autoscope` MCP entry — both apps can run side by side
and each panic button undoes only its own rules.

## Known porting notes (v0.1.0)

Dark theme only; no tray toasts; DataGrid grouping/live-sort approximated (the WinUI
toolkit DataGrid has neither); tabs start their feeds on first visit; CSV export writes
to Downloads. Details in the `// WinUI port:` comments throughout the code.

— AutoScope, engine © 2026 Dan Park, magicpoint.ai · Apache 2.0
