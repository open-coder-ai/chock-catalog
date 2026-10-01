---
name: protect-agent-config
description: "Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md and wrappers, .claude/settings, MCP client configs (.mcp.json, .cursor/mcp.json, .gemini/settings.json, .codex/config.toml, more), .git/hooks, policy implementations/ and .chock/{config.yaml,security.json,agentic-security.json,dependency-allowlist.txt,bin,compiled,state}: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore. Reads and `chock sync` pass. Edit/Write: tool_use gate."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Protect Agent Config

Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md and wrappers, .claude/settings, MCP client configs (.mcp.json, .cursor/mcp.json, .gemini/settings.json, .codex/config.toml, more), .git/hooks, policy implementations/ and .chock/{config.yaml,security.json,agentic-security.json,dependency-allowlist.txt,bin,compiled,state}: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore. Reads and `chock sync` pass. Edit/Write: tool_use gate.

```
agent_config(AGENTS.md|wrappers|.claude/settings|.mcp.json|mcp_files(.cursor|.vscode|.gemini|.codex|.junie|.devin|.grok|.agents|.tabnine)|.chock/config.yaml|.chock/security.json|.chock/agentic-security.json|.chock/dependency-allowlist.txt|.chock/bin|.chock/compiled|.chock/state|.git/hooks|.agents/policies/*/implementations): never(hand_edit|delete); regenerate_via(chock sync)
if(config_change_needed): ask_person; person edits from own shell; no marker passes  # an agent must not disarm itself
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs; blocks on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
