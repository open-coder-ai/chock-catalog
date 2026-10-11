---
name: agent-permissions-scan
description: "Blocks: parses agent permission configs (.claude/settings*, .codex, .gemini, .vscode, .cursor/cli.json, opencode, .aider, .continue) and flags added bare or wildcard allows (Bash, curl/rm/sudo/git push, WebFetch, Write/Edit globs, mcp__*), removed deny entries, bypass/auto modes, codex never+danger, yolo, autoAccept, yes-always, regex-all VS Code approve, Claude project env API-endpoint overrides and .mcp.json server pre-enables. Misses: other MCP configs, user-level settings, scripts, Read."
metadata:
  chock.artifact: rule
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Agent Permissions Scan

Blocks: parses agent permission configs (.claude/settings*, .codex, .gemini, .vscode, .cursor/cli.json, opencode, .aider, .continue) and flags added bare or wildcard allows (Bash, curl/rm/sudo/git push, WebFetch, Write/Edit globs, mcp__*), removed deny entries, bypass/auto modes, codex never+danger, yolo, autoAccept, yes-always, regex-all VS Code approve, Claude project env API-endpoint overrides and .mcp.json server pre-enables. Misses: other MCP configs, user-level settings, scripts, Read.

```
agent_permissions(.claude/settings*|.codex/config.toml|.gemini/settings.json|.vscode/settings.json|.cursor/cli.json|opencode.json|.aider.conf.yml|.continue/**): grant named, scoped actions only
never(add): bare|wildcard allow, bypass|auto default mode, yolo|autoAccept|yes-always, regex-all auto-approve, claude env ANTHROPIC_*_URL|OPENAI_BASE_URL|*_API_BASE, enableAllProjectMcpServers|enabledMcpjsonServers; never(remove): deny entry; blocks at commit+tool_use
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs; blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
