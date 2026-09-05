# chock's plugin bundles, measured by context-report v0.1

Every hook bundle was measured twice: with the plugin-root variable the client would set (`resolved`) and without it (`unresolved`). Latency is per hook invocation with a benign PreToolUse payload, n=20, on the build machine -- `environmentSensitive`, so read the shape, not the absolute number.

`allow on malformed JSON` counts bundles whose hook exited 0 with no deny in stdout when fed unparseable stdin. `unresolved` runs with no plugin-root variable at all, which is how a hook runs when the client does not set one.

| format | bundles | with hook | reachable (resolved) | reachable (unresolved) | allow on malformed JSON (resolved / unresolved) | latency p50 ms (median across bundles) | latency p95 ms (median) | latency Error when unresolved | context tokens (median per bundle) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| claude | 22 | 4 | 4 | 0 | 4 / 0 | 46.6 | 51.7 | 4 | 222.0 |
| codex | 22 | 4 | 4 | 0 | 4 / 0 | 44.5 | 46.6 | 4 | 222.0 |
| copilot | 22 | 4 | 4 | 4 | 4 / 4 | 42.0 | 43.4 | 0 | 222.0 |
| cursor | 22 | 4 | 4 | 0 | 4 / 0 | 43.7 | 45.9 | 4 | 222.0 |
