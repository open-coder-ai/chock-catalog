---
name: guard-deletion
description: "trigger: a change that removes a check, auth decorator, middleware registration, sanitizer call or path check with none like it in the same hunk (ask), or removes or weakens a hardening flag, security header, cookie attribute, TLS verification, row-level security or file mode (block). Hunk-local, line-level; misses a guard moved to another hunk or file, a semantic replacement, a deletion-only commit, and tests, docs and vendored code (not judged)."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Guard Deletion and Mitigation Removal

trigger: a change that removes a check, auth decorator, middleware registration, sanitizer call or path check with none like it in the same hunk (ask), or removes or weakens a hardening flag, security header, cookie attribute, TLS verification, row-level security or file mode (block). Hunk-local, line-level; misses a guard moved to another hunk or file, a semantic replacement, a deletion-only commit, and tests, docs and vendored code (not judged).

```
on(commit|tool_use): block(script) script=guard-deletion-gate.py
guard-deletion: this change removes a check or a security mitigation (the refusal above names the file, line and family). Keep it, or move its replacement into the same hunk. A removed guard asks a person; a removed or weakened mitigation (hardening flag, security header, cookie attribute, TLS verification, row-level security, file mode) is refused. A person who has reviewed the removal waives one line with 'pragma: allowlist guard-removal' or 'pragma: allowlist mitigation-removal'; an agent's own pragma counts only once that exact line is committed.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
