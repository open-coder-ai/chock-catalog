---
name: protect-agent-config
description: "Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md, whole agent folders (.claude/, .cursor/, .codex/, .gemini/, .windsurf/, .agents/, .chock/, ...), MCP/hook client configs (.mcp.json, ...), guardrails toggles ([~/].chock/guardrails.json, its state/ record), plugin install markers (chock.selection.json), hook files of Cline, Kiro, Augment, Windsurf and Devin (user and machine level too), ~/.claude.json, Claude Code plugin roots (.claude-plugin/, their hooks/), .git/{hooks,config}, policy implementations/: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, a write through a symlink to one; CLAUDE_CODE_PLUGIN_DIRS, claude --plugin-dir (best effort). Folder names match without regard to case. An instruction file under docs/ asks a person instead. Coarse: also eval or sh -c of computed text, shells fed by pipe/variable, interpreter one-liners naming such a path. Reads, `chock sync` pass. Edit/Write: tool gate, the same set and verdicts."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Protect Agent Config

Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md, whole agent folders (.claude/, .cursor/, .codex/, .gemini/, .windsurf/, .agents/, .chock/, ...), MCP/hook client configs (.mcp.json, ...), guardrails toggles ([~/].chock/guardrails.json, its state/ record), plugin install markers (chock.selection.json), hook files of Cline, Kiro, Augment, Windsurf and Devin (user and machine level too), ~/.claude.json, Claude Code plugin roots (.claude-plugin/, their hooks/), .git/{hooks,config}, policy implementations/: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, a write through a symlink to one; CLAUDE_CODE_PLUGIN_DIRS, claude --plugin-dir (best effort). Folder names match without regard to case. An instruction file under docs/ asks a person instead. Coarse: also eval or sh -c of computed text, shells fed by pipe/variable, interpreter one-liners naming such a path. Reads, `chock sync` pass. Edit/Write: tool gate, the same set and verdicts.

```
agent_config(AGENTS.md+wrappers|.{claude,cursor,codex,gemini,windsurf,agents,chock,junie,devin,grok,tabnine,augment,claude-plugin}/|.github/{copilot*,hooks/}|.{clinerules,kiro}/hooks/|.kiro/agents/|<plugin>/hooks/|{.,.vscode/}mcp.json|~/.claude.json|chock.selection.json|.git/{hooks,config}): never(edit|delete|CLAUDE_CODE_PLUGIN_DIRS|--plugin-dir); any case; links same
docs/**/{AGENTS,CLAUDE,GEMINI,copilot-instructions}.md|.cursorrules|.windsurfrules|.aider.conf.yml: ask_person; no marker passes
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs; blocks on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
