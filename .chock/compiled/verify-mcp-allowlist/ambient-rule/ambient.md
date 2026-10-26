<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/verify-mcp-allowlist/) -->
```
mcp_server(any client config): must(name+launcher+exact_args+env+headers+cwd+type|url_host in .chock/mcp-allowlist.json); block(unlisted|command_args_url_differ); warn(unpinned|shell_launcher|http|literal_credential|below_floor|enable_all)
allowlist: file, empty by default; an agent is judged by HEAD's copy and cannot grow it, a person edits it; guard: `<agent> mcp add`, shell writes; gate: commit|tool_use|stop
```
<!-- chock:hooks:end -->
