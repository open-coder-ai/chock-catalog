---
name: protect-agent-config
description: "Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md and wrappers, .claude/settings, MCP and hook client configs (.mcp.json, .cursor/mcp.json, .gemini/settings.json, more), .git/{hooks,config}, policy implementations/ and .chock/{config.yaml,security.json,agentic-security.json,dependency-allowlist.txt,bin,compiled,state}: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore. Reads and `chock sync` pass. Edit/Write: tool_use gate."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Protect Agent Config

Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md and wrappers, .claude/settings, MCP and hook client configs (.mcp.json, .cursor/mcp.json, .gemini/settings.json, more), .git/{hooks,config}, policy implementations/ and .chock/{config.yaml,security.json,agentic-security.json,dependency-allowlist.txt,bin,compiled,state}: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore. Reads and `chock sync` pass. Edit/Write: tool_use gate.

```
agent_config(AGENTS.md+wrappers|.claude/settings|.mcp.json|.chock/{config.yaml,*security.json,*allowlist.txt,bin,compiled,state}|.git/{hooks,config}|.agents/policies/*/implementations|.{cursor,codex,windsurf}/hooks.json|.{cursor,vscode}/mcp.json|.{codex,grok}/config.toml|.gemini/settings.json|.junie/mcp/mcp.json|.devin/{mcp_config,config,hooks.v1}.json|.grok/hooks/|.agents/{mcp_config,hooks}.json|.tabnine/agent/settings.json|.github/hooks/): never(edit|delete)
else ask_person; no marker passes
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs; blocks on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
