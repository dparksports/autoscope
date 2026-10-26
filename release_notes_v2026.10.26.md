# AutoScope v2026.10.26 — the F# engine foundation

The invisible half of this release is a rebuild: every engine AutoScope ships —
diagnosis, firewall, the whole watch stack, and the AI bridge — is now **F# in
four app-agnostic libraries** (`Engines.Core/Diagnosis/Firewall/Watch/Bridge`,
~16k lines), consumed through an injected `AppIdentity` (data root, rule
prefixes, ports, MCP id). The app layer is C# shell, joins and composition.

## What that buys you

- **Nothing visible changed** — same tabs, same behavior — but every engine now
  passes its own offline/live self-test gates: Site Doctor ALL PASS, NetWatch
  ALL CHECKS (live dual-family TCP + the full Sysmon archive suite), the
  Sysmon archive round-trips **byte-identical** with files written by the old
  C# engine, and a synthetic TLS 1.2 flow decrypts end-to-end.
- **Reload-safe block store** — the class of bug that once zeroed your blocked
  list (a latched empty load) is structurally gone.
- **17 files of dead code deleted** (BITS/Defender/privacy leftovers from tabs
  this app never had).
- Found and flagged (preserved, not fixed): the upstream body-archiving bug
  where content rows never reached the transmissions archive.

Same install as always: unzip, right-click `AutoScope.exe` → **Run as administrator**.

— AutoScope, engine © 2026 Dan Park, magicpoint.ai · Apache 2.0
