# AutoScope v0.1.3 — instant row updates + an apology to AutoCommand

## Fixed

- **Rows now re-sort near-instantly (≤0.5 s)** — AutoCommand re-sorted its grid on
  every packet via WPF live shaping; the port only re-sorted on a 10-second tick,
  so busy rows visibly lagged. Live shaping is now ported: shaping-property changes
  (last packet, high-transmitter, TX-only) mark rows dirty off the sniffer threads
  and a 500 ms coalescing tick repositions them.
- **Restored AutoCommand's elevated ignore list** — v0.1.2 deleted
  `System32\ignored_processes.txt` as "our stray". It wasn't only ours: AutoCommand
  reads and writes that exact file whenever it runs elevated (its list is
  CWD-relative too), so deleting it emptied AutoCommand's ignore list — which is
  why AutoCommand suddenly reported *everything* (ZCode included) more frequently.
  v0.1.3 restores the file's last known entries once and never touches it again.

After this, the two apps behave consistently again: processes on the ignore list
(including ZCode) are filtered in both — remove an entry from Process Monitor →
Ignored → Remove if you want it visible — and everything else updates instantly in
both.

— AutoScope, engine © 2026 Dan Park, magicpoint.ai · Apache 2.0
