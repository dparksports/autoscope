# AutoScope v0.1.6 — popup dismissal done the platform way

## What was going on

AutoCommand's popups use WPF `StaysOpen="False"` — dismissal at the **platform**
level: the popup layer itself closes on any outside click, no matter what the
controls underneath do with the event. The port approximated that with a
hand-rolled routed-event handler instead of using WinUI's equivalent:
v0.1.4's version crashed (`InvalidCastException` — the zeroed counters), and
v0.1.5's version, while it registered correctly, does not reliably receive
presses through the toolkit DataGrid — which is most of the window. Hence
"popups don't close," twice.

## Fixed

- Both popups now use **`Popup.IsLightDismissEnabled`** — the direct WinUI
  equivalent of `StaysOpen="False"`, dismissed at the input layer where control
  event handling can't interfere.
- The anchor buttons now **toggle**: clicking "Blocked"/"Ignored" while its popup
  is open closes it (AutoCommand reopened it instead).
- Verified with **injected real mouse input** in a live WinUI probe window:
  `after-plain-click closed=True`, `after-datagrid-row-click closed=True`.

— AutoScope, engine © 2026 Dan Park, magicpoint.ai · Apache 2.0
