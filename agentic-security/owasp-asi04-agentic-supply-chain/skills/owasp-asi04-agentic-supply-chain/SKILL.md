---
name: owasp-asi04-agentic-supply-chain
description: "Verify agent components before loading them, and keep verifying, because runtime tool discovery changes the supply chain after deployment. Use when adding an MCP server, agent framework, plugin, tool registry, or model artifact, and when reviewing what an agent may pull at runtime. Do NOT use for ordinary application dependencies already covered by `verify-dependency-exists`."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# OWASP ASI04 — Agentic Supply Chain Vulnerabilities

Verify agent components before loading them, and keep verifying, because runtime tool discovery changes the supply chain after deployment. Use when adding an MCP server, agent framework, plugin, tool registry, or model artifact, and when reviewing what an agent may pull at runtime. Do NOT use for ordinary application dependencies already covered by `verify-dependency-exists`.

```
before(load: tool|mcp_server|framework|model): verify(signature + provenance) + pin(version) + record(AIBOM); apply(SCA) pre_pull
re_verify(runtime_discovered_components) each_load; never(auto_trust): registry_listing | popularity; see .agents/policies/owasp-asi04-agentic-supply-chain/references/supply-chain.md
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
