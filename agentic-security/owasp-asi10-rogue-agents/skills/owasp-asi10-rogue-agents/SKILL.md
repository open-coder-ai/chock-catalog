---
name: owasp-asi10-rogue-agents
description: "Make an agent that has drifted, been compromised, or was never inventoried detectable and stoppable. Require an owner, expiry, and inventory entry for every agent, sandbox by default, baseline behaviour and alert on deviation, and keep a tested kill switch. Use when deploying a long-running or autonomous agent, allowing sub-agent spawning, or reviewing agent lifecycle and monitoring. Do NOT use for a single hijacked request within a supervised session \u2014 that is `owasp-asi01-agent-goal-hijack`."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# OWASP ASI10 — Rogue Agents

Make an agent that has drifted, been compromised, or was never inventoried detectable and stoppable. Require an owner, expiry, and inventory entry for every agent, sandbox by default, baseline behaviour and alert on deviation, and keep a tested kill switch. Use when deploying a long-running or autonomous agent, allowing sub-agent spawning, or reviewing agent lifecycle and monitoring. Do NOT use for a single hijacked request within a supervised session — that is `owasp-asi01-agent-goal-hijack`.

```
every(agent): owner + purpose + expiry + inventory_entry + kill_switch(tested); default(runtime): sandboxed; never(allow): uninventoried_subagent_spawn
baseline(behavior) + alert(deviation) continuously; on(deviation): halt + escalate(human); see .agents/policies/owasp-asi10-rogue-agents/references/rogue-agents.md
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
