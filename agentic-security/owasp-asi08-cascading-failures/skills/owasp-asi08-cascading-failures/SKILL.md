---
name: owasp-asi08-cascading-failures
description: "Keep one agent's bad output from propagating through everything downstream. Isolate blast radius per agent and per environment, separate development from production access, validate agent-to-agent handoffs, and add circuit breakers that halt automation on behavioural deviation. Use when chaining agents, designing orchestration, granting production access, or wiring agent output into downstream automation. Do NOT use for the transport security of those handoffs \u2014 that is `owasp-asi07-insecure-inter-agent-communication`."
metadata:
  chock:
    artifact: rule
    enforcement: advise
    coverage_without_chock: advisory
---

# OWASP ASI08 — Cascading Failures

Keep one agent's bad output from propagating through everything downstream. Isolate blast radius per agent and per environment, separate development from production access, validate agent-to-agent handoffs, and add circuit breakers that halt automation on behavioural deviation. Use when chaining agents, designing orchestration, granting production access, or wiring agent output into downstream automation. Do NOT use for the transport security of those handoffs — that is `owasp-asi07-insecure-inter-agent-communication`.

```
isolate(blast_radius): per_agent + per_environment; separate(dev, prod) hard; never(chain): agent_output -> agent_input | downstream_automation without(validation)
circuit_breaker(on: behavioral_deviation | error_rate | volume_spike) -> halt + escalate(human); see .agents/policies/owasp-asi08-cascading-failures/references/cascading-failures.md
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
