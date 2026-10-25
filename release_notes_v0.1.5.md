# AutoScope v0.1.5 — the v0.1.4 crash, fixed and runtime-verified

v0.1.4's popup-dismiss fix crashed at startup with `InvalidCastException`: the
WinRT `AddHandler` projection requires the handler wrapped in an explicit
`PointerEventHandler` — a bare method group compiles but fails to marshal. The
throw aborted the Process Monitor's `Loaded` handler **before** the blocked and
ignored lists loaded, so both counters stayed at their XAML defaults of 0. Your
data was never lost — both files were healthy on disk the whole time (273 block
records; the ignore list at 2 entries after ZCode.exe was removed during that
session — re-add it from the Ignored popup if that wasn't intentional).

## Fixed

- The handler is now wrapped in `PointerEventHandler` — **verified by running
  the exact call in a live WinUI process** (an unelevated probe app), not just
  compiled.
- The registration is also wrapped in try/catch: light-dismiss is cosmetic and
  must never be able to abort page loading again.

— AutoScope, engine © 2026 Dan Park, magicpoint.ai · Apache 2.0
