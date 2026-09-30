---
name: pin-github-actions
description: "Blocks a workflow that references a GitHub Action by a movable ref (tag or branch) instead of a full 40-char commit SHA. Every owner/repo@non-SHA is blocked, actions/* and reusable workflows included; a SHA pin and a local action (no ref) pass. Bounded to .github/workflows/ and .github/actions/. Runs: commit, agent write, turn's end. Waiver: 'pragma: allowlist unpinned-action' same line. Person's commit: honoured. Agent: only if already in HEAD; MCP gateway: never. Agent asks a person."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Pin GitHub Actions

Blocks a workflow that references a GitHub Action by a movable ref (tag or branch) instead of a full 40-char commit SHA. Every owner/repo@non-SHA is blocked, actions/* and reusable workflows included; a SHA pin and a local action (no ref) pass. Bounded to .github/workflows/ and .github/actions/. Runs: commit, agent write, turn's end. Waiver: 'pragma: allowlist unpinned-action' same line. Person's commit: honoured. Agent: only if already in HEAD; MCP gateway: never. Agent asks a person.

```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+unpinned-action ...
Unpinned GitHub Action detected: a workflow references an action by a tag or branch (owner/repo at a movable ref) rather than a full 40-character commit SHA. Pin it to the SHA -- keep the version in a trailing comment for readability -- so a re-tagged or compromised release cannot change what runs. Waiver: 'pragma: allowlist unpinned-action' on the same line. A person's commit honours it; in the agent (write, the turn's end, an agent's commit) only a line already in HEAD counts, and the MCP gateway never does. An agent asks a person; it never writes the pragma.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
