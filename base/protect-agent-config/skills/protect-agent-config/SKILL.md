---
name: protect-agent-config
description: "Stops an agent hand-editing its own guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md and wrappers, .claude/settings, .mcp.json, .chock/dependency-allowlist.txt, .chock/bin, .chock/compiled, .git/hooks and policy implementations/: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, Set-Content/Out-File. Reads, cp out, `chock sync` pass. Coarse. No marker bypass: a person edits from their own shell. Edit/Write: tool_use gate (incl. turn's end), never at commit."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Protect Agent Config

Stops an agent hand-editing its own guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md and wrappers, .claude/settings, .mcp.json, .chock/dependency-allowlist.txt, .chock/bin, .chock/compiled, .git/hooks and policy implementations/: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, Set-Content/Out-File. Reads, cp out, `chock sync` pass. Coarse. No marker bypass: a person edits from their own shell. Edit/Write: tool_use gate (incl. turn's end), never at commit.

```
agent_config(AGENTS.md|wrappers|.claude/settings|.mcp.json|.chock/dependency-allowlist.txt|.chock/bin|.chock/compiled|.git/hooks|.agents/policies/*/implementations): never(hand_edit|delete); regenerate_via(chock sync)
if(config_change_needed): ask_person; person edits from own shell; no agent-typed marker passes  # an agent must not widen or disarm its own guardrails
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs; blocks on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
