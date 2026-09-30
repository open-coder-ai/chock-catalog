<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/pin-github-actions/) -->
```
on(commit|tool_use): block(content_regex) paths=.github/workflows/*|.github/actions/* scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+unpinned-action content_pattern(regex)
Unpinned GitHub Action detected: a workflow references an action by a tag or branch (owner/repo at a movable ref) rather than a full 40-character commit SHA. Pin it to the SHA -- keep the version in a trailing comment for readability -- so a re-tagged or compromised release cannot change what runs. Waiver: 'pragma: allowlist unpinned-action' on the same line. A person's commit honours it; in the agent (write, the turn's end, an agent's commit) only a line already in HEAD counts, and the MCP gateway never does. An agent asks a person; it never writes the pragma.
```
<!-- chock:hooks:end -->
