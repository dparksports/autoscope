# AutoScope v0.1.1 — first-run fixes

Two bugs from the first real launch, both fixed:

## Fixed

- **Process column was empty** — the port set the process cell's foreground to WinUI's
  default (black) when a process wasn't blocked; on the dark palette that's invisible.
  It now uses the theme's primary text brush like every other column.
- **Nothing imported from AutoCommand** — v0.1.0 kept the two apps fully separate,
  which meant your existing blocked list and ignored processes started empty here.
  AutoScope now adopts an existing AutoCommand install on first run:
  - **Blocked list** — all `blocks.txt` records (targets, service attribution, history)
    merge into AutoScope's store, and the existing `AC-BLOCK` firewall rules are
    recognized and managed **in place** (never renamed — AutoCommand keeps seeing them
    too). Verified on the dev machine: 250 records + 127 live rule targets imported.
  - **Ignored processes** — merges from AutoCommand's `ignored_processes.txt`
    (found next to its exe via its startup task, in its data dir, via the
    `AUTOCOMMAND_IGNORE_LIST` env var, or a sibling source checkout).
  - One-shot per install; delete `%LOCALAPPDATA%\AutoScope\migration-autocommand.done`
    to re-run. Note: because AC-BLOCK rules are now adopted, AutoScope's 🚑 Restore
    Internet covers them too.

Site Doctor self-test: **ALL PASS**.

## Install

Download `AutoScope-v0.1.1-win-x64.zip`, unzip, right-click `AutoScope.exe` →
**Run as administrator**. The first launch imports from AutoCommand before any tab loads.

— AutoScope, engine © 2026 Dan Park, magicpoint.ai · Apache 2.0
