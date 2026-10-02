---
name: pin-github-actions
description: "Blocks uses: of an action or reusable workflow at a movable ref (not a lowercase 40-hex SHA) and a docker:// image without @sha256, in quoted, JSON, flow, anchored and next-line forms; local ./ passes. Scope: .github/workflows/, .github/actions/, action.y*ml. Line regex, not a YAML parser: container/services image tags, impostor SHAs and a tag named like a SHA pass. Waiver: 'pragma: allowlist unpinned-action' same line. Person's commit: honoured. Agent: only if in HEAD; MCP gateway: never."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Pin GitHub Actions

Blocks uses: of an action or reusable workflow at a movable ref (not a lowercase 40-hex SHA) and a docker:// image without @sha256, in quoted, JSON, flow, anchored and next-line forms; local ./ passes. Scope: .github/workflows/, .github/actions/, action.y*ml. Line regex, not a YAML parser: container/services image tags, impostor SHAs and a tag named like a SHA pass. Waiver: 'pragma: allowlist unpinned-action' same line. Person's commit: honoured. Agent: only if in HEAD; MCP gateway: never.

```
on(commit|tool_use): block(content_regex) paths=.github/workflows/*|.github/actions/*|action.y*ml|*/action.y*ml scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+unpinned-action content_pattern(regex)
Unpinned GitHub Action detected: a workflow references an action by a tag or branch (owner/repo at a movable ref) rather than a full 40-character commit SHA, a docker:// image has no @sha256: digest, or a line check cannot read the ref (an escape, an open quote). Pin it to the lowercase SHA or digest -- keep the version in a trailing comment for readability -- so a re-tagged or compromised release cannot change what runs. Waiver: 'pragma: allowlist unpinned-action' on the same line. A person's commit honours it; in the agent (write, the turn's end, an agent's commit) only a line already in HEAD counts, and the MCP gateway never does. An agent asks a person; it never writes the pragma.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
