<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/git-safety/) -->
```
see(block-destructive-commands): force_push|reset_hard|rm_-rf|non_ff_push(pre_push); see(block-no-verify): --no-verify|skip_hooks; see(protect-main-branch): direct_commit|push(main|master)
advisory: avoid(branch_-D) without_approval; prefer(feature_branch|atomic_commits); enforced: see(limit-diff-size) asks at commit if diff > 500_lines (CHOCK_DIFF_LIMIT), person_only_override
```
<!-- chock:hooks:end -->
