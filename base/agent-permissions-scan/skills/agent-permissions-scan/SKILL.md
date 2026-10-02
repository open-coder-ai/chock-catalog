---
name: agent-permissions-scan
description: "Warns only (observe): parses agent permission configs (.claude/settings*, .codex, .gemini, .vscode, .cursor/cli.json, opencode, .aider, .continue) and flags added bare or wildcard allows (Bash, curl/rm/sudo/git push, WebFetch, Write/Edit globs, mcp__*), removed deny entries, bypass/auto modes, codex never+danger, yolo, autoAccept, yes-always, regex-all VS Code approve. Misses: MCP configs, scripts, Read."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Agent Permissions Scan

Warns only (observe): parses agent permission configs (.claude/settings*, .codex, .gemini, .vscode, .cursor/cli.json, opencode, .aider, .continue) and flags added bare or wildcard allows (Bash, curl/rm/sudo/git push, WebFetch, Write/Edit globs, mcp__*), removed deny entries, bypass/auto modes, codex never+danger, yolo, autoAccept, yes-always, regex-all VS Code approve. Misses: MCP configs, scripts, Read.

```
agent_permissions(.claude/settings*|.codex/config.toml|.gemini/settings.json|.vscode/settings.json|.cursor/cli.json|opencode.json|.aider.conf.yml|.continue/**): grant named, scoped actions only
never(add): bare|wildcard allow, bypass|auto default mode, yolo|autoAccept|yes-always, regex-all auto-approve; never(remove): deny entry; observe: warns at commit+tool_use, enforce later
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs; warns at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
