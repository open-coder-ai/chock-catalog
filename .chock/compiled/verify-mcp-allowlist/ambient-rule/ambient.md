<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/verify-mcp-allowlist/) -->
```
mcp_config(.mcp.json): server(name,source=cmd+args|url) must(match: allowlist(this_guard_source)); block(unlisted|source_mismatch); allow(exact_match)
allowlist: lives in implementations/verify-mcp-allowlist.py; also gates `claude mcp add|add-json`; edit requires 'chock: approved-config-change'; also gates written configs: .mcp.json|.cursor|.vscode|claude_desktop|.gemini|.codex added-only at commit+tool_use
```
<!-- chock:hooks:end -->
