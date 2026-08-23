---
name: owasp-asi07-insecure-inter-agent-communication
description: "Authenticate and integrity-protect the channels agents use to talk to each other, so a peer cannot be impersonated, a message tampered with, or a fake agent registered in discovery. Use when building multi-agent orchestration, agent-to-agent protocols, delegation between agents, message buses, or agent discovery services. Do NOT use for a single agent calling ordinary tools \u2014 that is `owasp-asi02-tool-misuse`."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# OWASP ASI07 — Insecure Inter-Agent Communication

Authenticate and integrity-protect the channels agents use to talk to each other, so a peer cannot be impersonated, a message tampered with, or a fake agent registered in discovery. Use when building multi-agent orchestration, agent-to-agent protocols, delegation between agents, message buses, or agent discovery services. Do NOT use for a single agent calling ordinary tools — that is `owasp-asi02-tool-misuse`.

```
between(agents): mutual_auth + signed_messages + integrity + replay_protection; allowlist(delegation_edges) explicitly
never(accept): peer from(unverified_discovery) | instruction from(unauthenticated_sender); log(inter_agent_traffic) as_sensitive; see .agents/policies/owasp-asi07-insecure-inter-agent-communication/references/inter-agent-comms.md
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
