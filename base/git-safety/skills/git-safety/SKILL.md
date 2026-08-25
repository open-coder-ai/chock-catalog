---
name: git-safety
description: "trigger: force push, hard reset, destructive branch delete, hook bypass, direct main commits. avoid: rewriting remote history, discarding uncommitted work, skipping pre-commit checks. Install block-destructive-commands, block-no-verify and protect-main-branch to enforce the hard controls deterministically; this rule is the advisory layer over them plus atomic-commit and diff-size guidance no gate can decide."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Git Safety Rule

trigger: force push, hard reset, destructive branch delete, hook bypass, direct main commits. avoid: rewriting remote history, discarding uncommitted work, skipping pre-commit checks. Install block-destructive-commands, block-no-verify and protect-main-branch to enforce the hard controls deterministically; this rule is the advisory layer over them plus atomic-commit and diff-size guidance no gate can decide.

```
enforced_when_installed(block-destructive-commands): force_push|reset_hard|rm_-rf; enforced_when_installed(block-no-verify): --no-verify|skip_hooks; enforced_when_installed(protect-main-branch): direct_commit|push(main|master)
advisory: avoid(branch_-D) without_approval; prefer(feature_branch|atomic_commits); ask_if(diff > 500_lines)
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
