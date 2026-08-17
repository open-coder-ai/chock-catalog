---
name: owasp-asi06-memory-context-poisoning
description: "Stop untrusted content from being written into an agent's durable memory or retrieval index, where it silently steers behaviour in later sessions. Keep context ephemeral by default, validate and attribute every memory write, scope memory per user and per task, and let operators inspect and flush it. Use when adding long-term memory, a vector index, session summarisation, or user preference storage. Do NOT use for the coding agent's own memory files \u2014 that is `memory-discipline`."
metadata:
  chock:
    artifact: rule
    enforcement: advise
    coverage_without_chock: advisory
---

# OWASP ASI06 — Memory & Context Poisoning

Stop untrusted content from being written into an agent's durable memory or retrieval index, where it silently steers behaviour in later sessions. Keep context ephemeral by default, validate and attribute every memory write, scope memory per user and per task, and let operators inspect and flush it. Use when adding long-term memory, a vector index, session summarisation, or user preference storage. Do NOT use for the coding agent's own memory files — that is `memory-discipline`.

```
default(context): ephemeral; before(write: memory|index): validate + attribute(source) + reject(instruction_shaped_content)
scope(memory): per_user + per_task; provide(operator): inspect + flush + expire; see .agents/policies/owasp-asi06-memory-context-poisoning/references/memory-poisoning.md
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
