# AutoScope v2026.10.30.16 — one engine, working gates, honest blocks

AutoScope now compiles against AutoCommand III's shared F# engines instead
of carrying its own drifted copies — one fix benefits both apps — and this
release carries the review pass that came with the swap.

## The bridge works

- **Every mutating tool used to crash before it could ask.** The UI
  availability pre-check read a COM-marshalled WinUI property on the RPC
  listener thread — the exact crash class AutoCommand III fixed in
  v2026.10.30.15. `block_ip` / `unblock_ip` / `kill_process` /
  `disable_task` now reach their confirmation dialog.
- **`dry_run` previews on all four mutating tools** — validate and see
  what would happen (which rules exist, which process is live) without a
  confirmation prompt or any change.
- **"Always allow" is per-target.** Granting `kill_process` for one PID
  covers that PID; every other process asks again. Grant keys ride the
  shared engine.
- **`kill_process` refuses on PID reuse** — pass `expect_name` and the
  kill refuses if the PID now belongs to a different process than the one
  the user confirmed.

## The Blocks tab renders

The bound view-model members were public *fields* — WinUI bindings to
fields silently produce nothing — so rows rendered without text, brushes
or remembered expand state. Properties now.

## Hardening

- Telemetry DNS probe validates domains before PowerShell interpolation
  (a tampered rules file was an elevated command-injection surface).
- `\Microsoft\WindowsCE` scheduled-task paths survive the display-prefix
  strip and reconstruct correctly.

## Removed

Dead modules per the three-app family scan (441 types cross-checked
against every repo): `AuthenticodeVerifier` (Shields Up ships and uses its
own), the `NetworkAdapterItem` / `EfiFileResult` / `NetworkConnectionItem`
model copies, three XAML-orphan converters. Net −16,400 lines including
the retired local engine copies.

## Upgrade notes

Unzip and run `AutoScope.exe` as Administrator, as before. Sessions,
blocks and baselines are untouched; existing MCP client registrations keep
working (the AgentProxy rides in the zip and registers to the stable
per-version tools path).
