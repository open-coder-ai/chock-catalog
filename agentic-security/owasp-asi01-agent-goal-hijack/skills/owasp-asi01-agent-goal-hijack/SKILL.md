---
name: owasp-asi01-agent-goal-hijack
description: "Keep an agent's objective under the operator's control when the agent ingests untrusted content. Separate retrieved data from instructions, refuse tool-scope expansion requested by that data, and confirm sensitive actions against the raw action rather than a summary. Use when building RAG pipelines, email/ticket/doc readers, browser agents, or any planner whose context includes fetched content. Do NOT use for the coding agent's own session hygiene \u2014 that is `injection-defense`."
metadata:
  chock:
    artifact: rule
    enforcement: advise
    coverage_without_chock: advisory
---

# OWASP ASI01 — Agent Goal Hijack

Keep an agent's objective under the operator's control when the agent ingests untrusted content. Separate retrieved data from instructions, refuse tool-scope expansion requested by that data, and confirm sensitive actions against the raw action rather than a summary. Use when building RAG pipelines, email/ticket/doc readers, browser agents, or any planner whose context includes fetched content. Do NOT use for the coding agent's own session hygiene — that is `injection-defense`.

```
build(agent): partition(context){trusted: operator_instructions, untrusted: retrieved_content}; never(let untrusted) expand(tool_scope|goal|recipient)
before(sensitive_action): confirm(human, raw_action); see .agents/policies/owasp-asi01-agent-goal-hijack/references/goal-hijack.md
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
