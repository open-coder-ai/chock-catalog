---
name: owasp-asi02-tool-misuse
description: "Constrain what an agent's legitimate tools can be made to do. Grant least agency per task, validate tool parameters at the runtime boundary, authorise every invocation rather than only the first, and distrust tool metadata from unverified registries. Use when defining tool schemas, wiring an MCP server, granting shell or cloud-CLI access, or reviewing a tool-calling loop. Do NOT use for the credentials the tool authenticates with \u2014 that is `owasp-asi03-identity-privilege-abuse`."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# OWASP ASI02 — Tool Misuse & Exploitation

Constrain what an agent's legitimate tools can be made to do. Grant least agency per task, validate tool parameters at the runtime boundary, authorise every invocation rather than only the first, and distrust tool metadata from unverified registries. Use when defining tool schemas, wiring an MCP server, granting shell or cloud-CLI access, or reviewing a tool-calling loop. Do NOT use for the credentials the tool authenticates with — that is `owasp-asi03-identity-privilege-abuse`.

```
grant(tools): least_agency(per_task) + explicit_allowlist; validate(params) at_runtime; authorize(every_invocation)
never(trust): tool_description|metadata from(unverified_source); assess(tool_chains) not_just(single_calls); see .agents/policies/owasp-asi02-tool-misuse/references/tool-misuse.md
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
