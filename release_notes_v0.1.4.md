# AutoScope v0.1.4 — popups that close, blocked list that keeps up

## Fixed

- **Ignored/Blocked popups now close on any click** — the outside-press handler
  was wired as a normal bubbling event, and the DataGrid marks pointer presses
  handled, so clicks over the grid (most of the window) never reached it. The
  handler now registers for handled events too, with a guard so clicks *inside*
  a popup don't dismiss it — the same close-on-any-outside-click feel as
  AutoCommand.
- **Blocked list keeps up with AutoCommand** — it was frozen at the migration
  snapshot (254 records) while AutoCommand's live store grew (273). AutoScope now
  reconciles its store against the firewall block rules (its own `AS-BLOCK` and
  adopted `AC-BLOCK`) at every startup, adopting any target the store doesn't
  know — the same reconcile the Blocks tab runs. Verified on the dev machine:
  19 records adopted, both stores at 273.

— AutoScope, engine © 2026 Dan Park, magicpoint.ai · Apache 2.0
