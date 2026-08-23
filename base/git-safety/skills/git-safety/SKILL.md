---
name: git-safety
description: "trigger: force push, hard reset, destructive branch delete, hook bypass, direct main commits. avoid: rewriting remote history, discarding uncommitted work, skipping pre-commit checks."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Git Safety Rule

trigger: force push, hard reset, destructive branch delete, hook bypass, direct main commits. avoid: rewriting remote history, discarding uncommitted work, skipping pre-commit checks.

```
never(without_approval): force_push|reset_hard|branch_-D|rm_-rf; never: --no-verify|skip_hooks
before(commit): feature_branch(not main|master); prefer: atomic_commits; ask_if(diff > 500_lines)
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
