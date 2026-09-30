---
name: guard-memory-writes
description: "Refuses agent-memory writes that hold what memory must never hold: pasted git history (diff headers, hunk headers, commit and index lines), a fenced code block longer than 20 lines, a line that duplicates another, and secrets (scan-secrets' pattern). Judges only memory files -- MEMORY.md at any depth, CLAUDE.local.md, .claude/memory/**, memory/**/*.md, and at agent tool-use the agent's own stores outside the repository (~/.claude/projects/*/memory/**, ~/.claude/CLAUDE.md, /memories/**) -- and only what the change adds. No waiver exists. Mechanised slice of memory-discipline's never_persist and chock-mise's never(store): secrets. Structural checks only."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Guard Memory Writes

Refuses agent-memory writes that hold what memory must never hold: pasted git history (diff headers, hunk headers, commit and index lines), a fenced code block longer than 20 lines, a line that duplicates another, and secrets (scan-secrets' pattern). Judges only memory files -- MEMORY.md at any depth, CLAUDE.local.md, .claude/memory/**, memory/**/*.md, and at agent tool-use the agent's own stores outside the repository (~/.claude/projects/*/memory/**, ~/.claude/CLAUDE.md, /memories/**) -- and only what the change adds. No waiver exists. Mechanised slice of memory-discipline's never_persist and chock-mise's never(store): secrets. Structural checks only.

```
on(commit|tool_use): block(script) script=guard-memory-writes-gate.py
Memory write refused: it pastes git history, a code block over 20 lines, a duplicate line, or a secret. Store the non-derivable fact in one short line; link to the commit or file instead of pasting it. Rotate any secret that was written.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
