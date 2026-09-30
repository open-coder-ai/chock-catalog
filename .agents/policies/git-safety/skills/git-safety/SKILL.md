---
name: git-safety
description: "trigger: force push, hard reset, destructive branch delete, hook bypass, direct main commits. avoid: rewriting remote history, discarding uncommitted work, skipping pre-commit checks. Enforced counterparts: block-destructive-commands (command guard plus pre-push hook), block-no-verify (command guard), protect-main-branch (commit and push gate), limit-diff-size (asks at commit). This rule is the advisory layer over them plus atomic-commit guidance no gate can decide."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Git Safety Rule

trigger: force push, hard reset, destructive branch delete, hook bypass, direct main commits. avoid: rewriting remote history, discarding uncommitted work, skipping pre-commit checks. Enforced counterparts: block-destructive-commands (command guard plus pre-push hook), block-no-verify (command guard), protect-main-branch (commit and push gate), limit-diff-size (asks at commit). This rule is the advisory layer over them plus atomic-commit guidance no gate can decide.

```
see(block-destructive-commands): force_push|reset_hard|rm_-rf|non_ff_push(pre_push); see(block-no-verify): --no-verify|skip_hooks; see(protect-main-branch): direct_commit|push(main|master)
advisory: avoid(branch_-D) without_approval; prefer(feature_branch|atomic_commits); enforced: see(limit-diff-size) asks at commit if diff > 500_lines (CHOCK_DIFF_LIMIT), person_only_override
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
