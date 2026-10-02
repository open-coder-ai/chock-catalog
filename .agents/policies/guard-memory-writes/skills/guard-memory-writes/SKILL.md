---
name: guard-memory-writes
description: "Refuses agent-memory writes holding what memory must never hold: pasted git history (diff, hunk, commit, index lines), a fenced code block over 20 lines, a duplicate line, or a secret (scan-secrets' pattern). Judges only memory files (MEMORY.md at any depth, CLAUDE.local.md, .claude/memory/**, memory/**/*.md; at agent tool-use also ~/.claude/projects/*/memory/**, ~/.claude/CLAUDE.md, /memories/**) and only what the change adds. No waiver. Structural checks only."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Guard Memory Writes

Refuses agent-memory writes holding what memory must never hold: pasted git history (diff, hunk, commit, index lines), a fenced code block over 20 lines, a duplicate line, or a secret (scan-secrets' pattern). Judges only memory files (MEMORY.md at any depth, CLAUDE.local.md, .claude/memory/**, memory/**/*.md; at agent tool-use also ~/.claude/projects/*/memory/**, ~/.claude/CLAUDE.md, /memories/**) and only what the change adds. No waiver. Structural checks only.

```
on(commit|tool_use): block(script) script=guard-memory-writes-gate.py
Memory write refused: it pastes git history, a code block over 20 lines, a duplicate line, or a secret. Store the non-derivable fact in one short line; link to the commit or file instead of pasting it. Rotate any secret that was written.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
