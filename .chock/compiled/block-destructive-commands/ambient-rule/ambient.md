<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/block-destructive-commands/) -->
```
block(destructive_command @position-aware): rm_-rf(/|~|$HOME|.)|Remove-Item_-Recurse, git_push_--force, git_reset_--hard, git_checkout_., git_clean_-f, kubectl_delete, terraform_destroy, aws_s3(rm_--recursive|rb_--force), dropdb, helm(uninstall|delete), docker_volume(rm|prune)|system_prune, gcloud_delete
require_approval: reset_hard|rm_-rf|branch_-D; prefer: stash|soft_reset|force-with-lease|dry-run
```
<!-- chock:hooks:end -->
