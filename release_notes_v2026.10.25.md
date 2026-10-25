# AutoScope v2026.10.25

AutoScope is a native Windows app — **WinUI 3 (Windows App SDK 2.5.1) + .NET 10** —
porting six tabs from
[AutoCommand](https://github.com/dparksports/autocommand-windows) with the same
engines and the same undo-first design.

## The tabs

- **🔍 Process Monitor** — every program talking to the internet, live: PID
  provenance, svchost identity, TX-only lens, live re-sorting, one-click
  reversible blocking, blocked/ignored management popups.
- **🩺 Site Doctor** — "Why is this site slow?" in one 60-second check:
  recorded-traffic fingerprint, capped live probe against control sites,
  dependency-block analysis, one plain-English verdict with the math one
  expander away. Self-test: ALL PASS.
- **🛡 Firewall** — profile presets (Shields Up and friends), full rule grid
  over native COM (`INetFwPolicy2`), baseline capture with drift auto-fix.
- **⛔ Blocks** — every block grouped by the Windows service that actually made
  the connection, Sysmon-archive attribution repair, and the "a feature broke"
  restore guide.
- **🤖 Be My Guest** — invite an MCP-capable AI assistant to read this machine's
  telemetry: consent-first sessions, per-action confirmation for mutating
  tools, one-click client registration.
- **⚙ Settings** — Mark-of-the-Web unblock, startup task, adapter
  auto-mitigation, enforcer cadence.

## Switching from AutoCommand

First run adopts your existing install: block records and the ignored-process
list merge in, existing `AC-BLOCK` firewall rules are managed in place (never
renamed — AutoCommand keeps working), and every launch reconciles against the
firewall so the two lists stay in step. AutoScope's own rules use `AS-BLOCK`,
its data lives under `%LOCALAPPDATA%\AutoScope`, its AI bridge listens on ports
47921+, and MCP registrations use the `autoscope` id — the apps coexist.

## Install

Download `AutoScope-v2026.10.25-win-x64.zip`, unzip anywhere, right-click
`AutoScope.exe` → **Run as administrator**. No installer; deleting the folder
uninstalls it.

## Known porting notes

Dark theme only; no tray toasts; DataGrid grouping/live-sort approximated (the
WinUI toolkit DataGrid has neither — see the `// WinUI port:` comments); tabs
start their feeds on first visit; CSV export writes to Downloads.

— AutoScope, engine © 2026 Dan Park, magicpoint.ai · Apache 2.0
