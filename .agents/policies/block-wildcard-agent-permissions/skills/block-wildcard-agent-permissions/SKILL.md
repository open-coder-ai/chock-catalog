---
name: block-wildcard-agent-permissions
description: "Blocks agent grants that allow everything: a bare Bash wildcard, a `*` in an allow/alwaysAllow/tools array on the same line, or quoted defaultMode bypassPermissions. Any file is judged. Not caught: a multi-line array (`\"*\"` alone on a line, YAML `- \"*\"` list), unquoted defaultMode: bypassPermissions. Runs: commit, agent write, turn's end. Waiver: 'pragma: allowlist broad-agency' same line. Person's commit: honoured. Agent: only if already in HEAD; MCP gateway: never. Agent asks a person."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Wildcard Agent Permissions

Blocks agent grants that allow everything: a bare Bash wildcard, a `*` in an allow/alwaysAllow/tools array on the same line, or quoted defaultMode bypassPermissions. Any file is judged. Not caught: a multi-line array (`"*"` alone on a line, YAML `- "*"` list), unquoted defaultMode: bypassPermissions. Runs: commit, agent write, turn's end. Waiver: 'pragma: allowlist broad-agency' same line. Person's commit: honoured. Agent: only if already in HEAD; MCP gateway: never. Agent asks a person.

```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+broad-agency content_pattern(regex)
Wildcard agent permission grant detected. Scope the grant to specific tools or commands (e.g. Bash(git status:*), a named tool list); replace defaultMode bypassPermissions with a mode that asks (default or acceptEdits). Waiver: 'pragma: allowlist broad-agency' on the same line. A person's commit honours it; in the agent (write, the turn's end, an agent's commit) only a line already in HEAD counts, and the MCP gateway never does. An agent asks a person; it never writes the pragma.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
