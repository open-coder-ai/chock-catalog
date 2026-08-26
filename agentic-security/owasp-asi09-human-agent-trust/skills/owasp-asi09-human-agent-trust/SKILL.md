---
name: owasp-asi09-human-agent-trust
description: "Stop an agent from controlling the information a human approves against. Show the raw action rather than a model-authored summary at every confirmation step, forbid persuasive framing in sensitive workflows, and keep an immutable record of what was presented versus what executed. Use when designing approval prompts, human-in-the-loop checkpoints, agent-written PR descriptions, or consent and disclosure flows. Do NOT use for what the agent is permitted to do once approved \u2014 that is `owasp-asi02-tool-misuse`."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# OWASP ASI09 — Human-Agent Trust Exploitation

Stop an agent from controlling the information a human approves against. Show the raw action rather than a model-authored summary at every confirmation step, forbid persuasive framing in sensitive workflows, and keep an immutable record of what was presented versus what executed. Use when designing approval prompts, human-in-the-loop checkpoints, agent-written PR descriptions, or consent and disclosure flows. Do NOT use for what the agent is permitted to do once approved — that is `owasp-asi02-tool-misuse`.

```
at(approval_step): render(raw_action + real_target + real_scope); never(substitute): agent_summary for(the_thing_approved)
forbid(persuasive_framing | urgency | false_confidence) in(sensitive_workflow); log(immutable): presented vs executed; see .agents/policies/owasp-asi09-human-agent-trust/references/human-trust.md
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
