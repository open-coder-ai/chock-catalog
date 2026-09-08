---
name: verify-mcp-allowlist
description: "Gate MCP server configuration as protected content. A shell write to .mcp.json is refused unless every mcpServers entry on the line matches a name+source pair on the allowlist -- an unlisted name blocks, and an allowed name whose command/args/url changed blocks too (catches a server renamed to an allowed name but pointed elsewhere). The allowlist ships inside this guard's own script, protected like every policy's implementations/ source -- edit only with 'chock: approved-config-change'. Claude Code's .mcp.json only: agentseam 0.2.1 records no per-vendor MCP config path, so other agents are left out, not guessed at. Tool-time (Bash) only, best-effort: PreToolUse fails open on a crash, a file-write tool bypasses this guard, a write with no visible content fails closed. No commit-time gate -- chock 0.8.0 has no gate kind pairing name+source against an external allowlist. Matching and path checks are exact-string and substring-coarse. No pragma for .mcp.json -- matching the allowlist is the only way through."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Verify MCP Allowlist

Gate MCP server configuration as protected content. A shell write to .mcp.json is refused unless every mcpServers entry on the line matches a name+source pair on the allowlist -- an unlisted name blocks, and an allowed name whose command/args/url changed blocks too (catches a server renamed to an allowed name but pointed elsewhere). The allowlist ships inside this guard's own script, protected like every policy's implementations/ source -- edit only with 'chock: approved-config-change'. Claude Code's .mcp.json only: agentseam 0.2.1 records no per-vendor MCP config path, so other agents are left out, not guessed at. Tool-time (Bash) only, best-effort: PreToolUse fails open on a crash, a file-write tool bypasses this guard, a write with no visible content fails closed. No commit-time gate -- chock 0.8.0 has no gate kind pairing name+source against an external allowlist. Matching and path checks are exact-string and substring-coarse. No pragma for .mcp.json -- matching the allowlist is the only way through.

```
mcp_config(.mcp.json): server(name,source=cmd+args|url) must(match: allowlist(this_guard_source)); block(unlisted|source_mismatch); allow(exact_match)
allowlist: lives in implementations/verify-mcp-allowlist.sh; edit requires 'chock: approved-config-change'; scope: claude_code only, tool-time(Bash) only
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
