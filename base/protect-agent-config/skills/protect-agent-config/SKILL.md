---
name: protect-agent-config
description: "Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md, .claude/settings, MCP/hook client configs (.mcp.json, ...), .git/{hooks,config}, policy implementations/, .chock/{config.yaml,*security.json,allowlist,bin,compiled,state}: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore. Coarse: also eval or sh -c of computed text, shells fed by pipe/variable, interpreter one-liners naming such a path. Reads, `chock sync` pass. Edit/Write: tool gate."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Protect Agent Config

Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md, .claude/settings, MCP/hook client configs (.mcp.json, ...), .git/{hooks,config}, policy implementations/, .chock/{config.yaml,*security.json,allowlist,bin,compiled,state}: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore. Coarse: also eval or sh -c of computed text, shells fed by pipe/variable, interpreter one-liners naming such a path. Reads, `chock sync` pass. Edit/Write: tool gate.

```
agent_config(AGENTS.md+wrappers|.claude/settings|.mcp.json|.chock/{config.yaml,*security.json,*allowlist.txt,bin,compiled,state}|.git/{hooks,config}|.agents/policies/*/implementations|.{cursor,codex,windsurf}/hooks.json|.{cursor,vscode}/mcp.json|.{codex,grok}/config.toml|.gemini/settings.json|.junie/mcp/mcp.json|.devin/{mcp_config,config,hooks.v1}.json|.grok/hooks/|.agents/{mcp_config,hooks}.json|.tabnine/agent/settings.json|.github/hooks/): never(edit|delete)
else ask_person; no marker passes
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs; blocks on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
