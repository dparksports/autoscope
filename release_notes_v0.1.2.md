# AutoScope v0.1.2 — the import that actually imports

v0.1.1's migration looked like it worked and didn't: BlocksStore's loader is a
one-shot lazy parse, so pointing it at AutoCommand's data made "our" records BE
AutoCommand's — every import deduped against itself and nothing was ever written
to disk. The ignore list had it worse: its file was CWD-relative, and an elevated
launch starts in `C:\Windows\System32`, so the merged entries landed there,
invisible.

## Fixed

- **Blocked import** — the migration now merges at the file level, before anything
  loads: AutoCommand's `blocks.txt` is copied/merged into
  `%LOCALAPPDATA%\AutoScope\blocks.txt` verbatim (attribution, history and
  unrecognized lines all survive). Verified on the dev machine with a fresh-process
  readback: **254 block records** persisted and loading.
- **Ignored import** — the ignore list is anchored at
  `%LOCALAPPDATA%\AutoScope\ignored_processes.txt` (no more CWD guessing), the
  Process Monitor's "Ignored: N" count now refreshes at launch, and the stray
  `System32\ignored_processes.txt` v0.1.1 left behind is cleaned up on next run.
- `AC-BLOCK` firewall rules remain adopted in place (from v0.1.1).

The dev machine is already migrated — the next launch shows the real numbers.

## Install

Download `AutoScope-v0.1.2-win-x64.zip`, unzip, right-click `AutoScope.exe` →
**Run as administrator**.

— AutoScope, engine © 2026 Dan Park, magicpoint.ai · Apache 2.0
