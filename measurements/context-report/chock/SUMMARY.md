# chock's plugin bundles, measured by context-report v0.1

Every hook bundle was measured twice: with the plugin-root variable the client would set (`resolved`) and without it (`unresolved`). Latency is per hook invocation with a benign PreToolUse payload, n=20, on the build machine -- `environmentSensitive`, so read the shape, not the absolute number.

`allow on malformed JSON` counts bundles whose hook exited 0 with no deny in stdout when fed unparseable stdin. `unresolved` sets the plugin-root variable to empty, which expands like unset -- how a hook runs when the client sets nothing.

| format | bundles | with hook | reachable (resolved) | reachable (unresolved) | allow on malformed JSON (resolved / unresolved) | latency p50 ms (median across bundles) | latency p95 ms (median) | latency Error when unresolved | context tokens (median per bundle) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| claude | 22 | 4 | 4 | 0 | 4 / 0 | 42.8 | 46.0 | 4 | 222.0 |
| codex | 22 | 4 | 4 | 0 | 4 / 0 | 39.8 | 44.2 | 4 | 222.0 |
| copilot | 22 | 4 | 4 | 4 | 4 / 4 | 38.1 | 41.2 | 0 | 222.0 |
| cursor | 22 | 4 | 4 | 0 | 4 / 0 | 38.3 | 40.8 | 4 | 222.0 |
