---
name: protect-agent-config
description: "Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md, whole agent folders (.claude/, .cursor/, .codex/, .gemini/, .windsurf/, .agents/, .chock/, ...), MCP/hook client configs (.mcp.json, ...), .git/{hooks,config}, policy implementations/: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, a write through a symlink to one. Folder names match without regard to case. An instruction file under docs/ asks a person instead. Coarse: also eval or sh -c of computed text, shells fed by pipe/variable, interpreter one-liners naming such a path. Reads, `chock sync` pass. Edit/Write: tool gate, the same set and verdicts."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Protect Agent Config

Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md, whole agent folders (.claude/, .cursor/, .codex/, .gemini/, .windsurf/, .agents/, .chock/, ...), MCP/hook client configs (.mcp.json, ...), .git/{hooks,config}, policy implementations/: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, a write through a symlink to one. Folder names match without regard to case. An instruction file under docs/ asks a person instead. Coarse: also eval or sh -c of computed text, shells fed by pipe/variable, interpreter one-liners naming such a path. Reads, `chock sync` pass. Edit/Write: tool gate, the same set and verdicts.

```
agent_config(AGENTS.md+wrappers|.{claude,cursor,codex,gemini,windsurf,agents,chock,junie,devin,grok,tabnine}/**|.github/{copilot*,hooks/}|.mcp.json|.vscode/mcp.json|.git/{hooks,config}): never(edit|delete); folder names match as whole path segments, any case; a write through a symlink to one is the same write
docs/**/{AGENTS,CLAUDE,GEMINI,copilot-instructions}.md|.cursorrules|.windsurfrules|.aider.conf.yml: ask_person; else ask_person; no marker passes
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs; blocks on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
