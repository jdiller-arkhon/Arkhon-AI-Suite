# arkhon-engine

The suite's single command surface. People, roles, teams and connected apps all go through
`Suite::execute(actor, Command)`:

1. the rules in `arkhon-org` decide;
2. every attempt, including refusals, goes to the activity log;
3. `Store` saves atomically.

`Suite::view(viewer)` returns screen-shaped data with the viewer's capabilities, so the UI never
holds permission rules of its own. The Tauri app (Phase 5) calls this crate directly; the dev
server (`suite/devserver`) exposes it over HTTP on 127.0.0.1.

`demo_state()` builds the "Coastline Mechanical" example company used by the prototype and tests.
