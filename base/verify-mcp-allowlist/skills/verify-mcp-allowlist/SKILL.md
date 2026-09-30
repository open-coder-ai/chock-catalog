---
name: verify-mcp-allowlist
description: "Gates MCP servers by name+source vs an allowlist. Shell guard refuses a write to .mcp.json or `claude mcp add|add-json` unless every server is listed, plus add-from-claude-desktop and a write with no entry. Allowlist lives in the guard source; shell edits to it are refused, no marker bypass. Script gate (commit, tool use incl. turn's end) parses written MCP configs (.mcp.json, .cursor, .vscode, claude_desktop, .gemini, .codex): added/altered unlisted servers and unparseable configs refused."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Verify MCP Allowlist

Gates MCP servers by name+source vs an allowlist. Shell guard refuses a write to .mcp.json or `claude mcp add|add-json` unless every server is listed, plus add-from-claude-desktop and a write with no entry. Allowlist lives in the guard source; shell edits to it are refused, no marker bypass. Script gate (commit, tool use incl. turn's end) parses written MCP configs (.mcp.json, .cursor, .vscode, claude_desktop, .gemini, .codex): added/altered unlisted servers and unparseable configs refused.

```
mcp_config(.mcp.json): server(name,source=cmd+args|url) must(match: allowlist(this_guard_source)); block(unlisted|source_mismatch); allow(exact_match)
allowlist: lives in implementations/verify-mcp-allowlist.py; also gates `claude mcp add|add-json`; no agent-typed marker passes, a person edits it; also gates written configs: .mcp.json|.cursor|.vscode|claude_desktop|.gemini|.codex added-only at commit+tool_use
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
