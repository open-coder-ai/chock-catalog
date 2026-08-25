<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/git-safety/) -->
```
enforced_when_installed(block-destructive-commands): force_push|reset_hard|rm_-rf; enforced_when_installed(block-no-verify): --no-verify|skip_hooks; enforced_when_installed(protect-main-branch): direct_commit|push(main|master)
advisory: avoid(branch_-D) without_approval; prefer(feature_branch|atomic_commits); ask_if(diff > 500_lines)
```
<!-- chock:hooks:end -->
