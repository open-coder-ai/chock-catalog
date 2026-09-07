<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/verify-mcp-allowlist/) -->
```
mcp_config(.mcp.json): server(name,source=cmd+args|url) must(match: allowlist(this_guard_source)); block(unlisted|source_mismatch); allow(exact_match)
allowlist: lives in implementations/verify-mcp-allowlist.sh; edit requires 'chock: approved-config-change'; scope: claude_code only, tool-time(Bash) only
```
<!-- chock:hooks:end -->
