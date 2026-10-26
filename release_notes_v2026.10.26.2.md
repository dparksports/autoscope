# AutoScope v2026.10.26.2 — parse-time handler guards

The UI regression audit introduced alongside AutoTrack's release gate flagged three handlers in the Process Monitor that fire during window construction (a ComboBox default selection) without null guards — the same bug class that blank-launched AutoTrack v2026.10.26.2. Latent here, never triggered, now guarded. No behavior change.

Shipped the classic way this one last time; AutoScope's own audit + smoke gate (SelfTest.cs, SMOKE variant, tools/release.ps1 port) is the next item on the plan.

— © 2026 Dan Park, magicpoint.ai · Apache 2.0
