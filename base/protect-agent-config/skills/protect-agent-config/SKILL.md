---
name: protect-agent-config
description: "Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md, whole agent folders (.claude/, .cursor/, .codex/, .gemini/, .agents/, .chock/, ...), MCP/hook client configs (.mcp.json, ...), guardrails toggles, plugin install markers, hook files of Cline, Kiro, Augment, Windsurf and Devin (user and machine level too), ~/.claude.json, Claude Code plugin roots, project config of Kilo Code, opencode, Factory, Amp, Continue and Goose, .git/{hooks,config}, policy implementations/: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, a write through a symlink; CLAUDE_CODE_PLUGIN_DIRS, claude --plugin-dir, chock resume (best effort). Any case. An instruction file under docs/ asks a person instead. Coarse: also eval or sh -c of computed text, shells fed by pipe/variable, interpreter one-liners naming such a path. Reads, `chock sync` pass. Edit/Write: tool gate, same set and verdicts. Misses: user config under ~/.config/, writes a script makes, an existing hard link."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Protect Agent Config

Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md, whole agent folders (.claude/, .cursor/, .codex/, .gemini/, .agents/, .chock/, ...), MCP/hook client configs (.mcp.json, ...), guardrails toggles, plugin install markers, hook files of Cline, Kiro, Augment, Windsurf and Devin (user and machine level too), ~/.claude.json, Claude Code plugin roots, project config of Kilo Code, opencode, Factory, Amp, Continue and Goose, .git/{hooks,config}, policy implementations/: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, a write through a symlink; CLAUDE_CODE_PLUGIN_DIRS, claude --plugin-dir, chock resume (best effort). Any case. An instruction file under docs/ asks a person instead. Coarse: also eval or sh -c of computed text, shells fed by pipe/variable, interpreter one-liners naming such a path. Reads, `chock sync` pass. Edit/Write: tool gate, same set and verdicts. Misses: user config under ~/.config/, writes a script makes, an existing hard link.

```
agent_config(AGENTS.md+wrappers|.goosehints|.{claude,cursor,codex,gemini,windsurf,agents,chock,junie,devin,grok,tabnine,augment,claude-plugin,kilo{,code},opencode,factory,amp,continue}/|{opencode,kilo}.json*|.continuerc.json|.github/{copilot*,hooks/}|.{clinerules,kiro}/hooks/|.kiro/agents/|<plugin>/hooks/|{.,.vscode/}mcp.json|~/.claude.json|chock.selection.json|.git/{hooks,config}): never(edit|delete|*PLUGIN_DIRS|--plugin-dir); any case; links same
docs/**/<instruction>: ask_person; no waiver
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs; blocks on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
