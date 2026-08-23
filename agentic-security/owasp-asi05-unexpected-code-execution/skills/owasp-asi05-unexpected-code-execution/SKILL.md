---
name: owasp-asi05-unexpected-code-execution
description: "Contain code an agent generates or is induced to run. Execute in a sandboxed container with least privilege and deny-by-default egress, prefer parameterised APIs over raw shell, and treat any string reaching a subprocess or interpreter as attacker-controlled. Use when adding a code interpreter, shell tool, subprocess call, or eval-style API to an agent. Do NOT use for eval/exec appearing in ordinary application code \u2014 that is `code-safety`."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# OWASP ASI05 — Unexpected Code Execution

Contain code an agent generates or is induced to run. Execute in a sandboxed container with least privilege and deny-by-default egress, prefer parameterised APIs over raw shell, and treat any string reaching a subprocess or interpreter as attacker-controlled. Use when adding a code interpreter, shell tool, subprocess call, or eval-style API to an agent. Do NOT use for eval/exec appearing in ordinary application code — that is `code-safety`.

```
run(agent_generated_code): container(least_privilege) + egress(deny_by_default) + filesystem(scoped) + timeout; never(host_execution)
never(pass): untrusted_string -> shell | eval | interpreter | deserializer; prefer(parameterized_api) over(raw_shell); see .agents/policies/owasp-asi05-unexpected-code-execution/references/code-execution.md
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
