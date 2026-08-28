<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/block-wildcard-agent-permissions/) -->
```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+broad-agency ...
Wildcard agent permission grant detected. Scope the grant to specific tools or commands (e.g. Bash(git status:*), a named tool list). At commit, 'pragma: allowlist broad-agency' on the same line marks a reviewed exception; the pragma is NOT honored at tool-use, where the scanned text is a live tool argument an appended token could neutralize.
```
<!-- chock:hooks:end -->
