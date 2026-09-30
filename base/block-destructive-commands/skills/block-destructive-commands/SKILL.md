---
name: block-destructive-commands
description: "Best-effort, on parsed commands (echo ignored). Blocks rm -rf on absolute, ~, $HOME, . or .. paths; recursive Remove-Item/rd/del on drive paths; git push --force or +refspec, reset --hard, clean -f, checkout .; kubectl delete; terraform destroy; aws s3 rm --recursive/rb --force; dropdb; helm uninstall; docker volume rm/prune, system prune; find -delete/-exec rm; shred; truncate; wipefs -a/-o; gcloud with any `delete` operand. branch -D asks. Pre-push hook refuses non-fast-forward pushes."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Destructive Commands

Best-effort, on parsed commands (echo ignored). Blocks rm -rf on absolute, ~, $HOME, . or .. paths; recursive Remove-Item/rd/del on drive paths; git push --force or +refspec, reset --hard, clean -f, checkout .; kubectl delete; terraform destroy; aws s3 rm --recursive/rb --force; dropdb; helm uninstall; docker volume rm/prune, system prune; find -delete/-exec rm; shred; truncate; wipefs -a/-o; gcloud with any `delete` operand. branch -D asks. Pre-push hook refuses non-fast-forward pushes.

```
block(destructive_command @position-aware): rm_-rf(abs|~|$HOME|.|..)|Remove-Item|rd|del_-Recurse, git_push_--force, git_reset_--hard, git_checkout_., git_clean_-f, kubectl_delete, terraform_destroy, aws_s3(rm_--recursive|rb_--force), dropdb, helm(uninstall|delete), docker_volume(rm|prune)|system_prune, gcloud_delete(any_operand), find(-delete|-exec_rm)|shred|truncate @dangerous_target, wipefs(-a|-o)
require_approval: branch_-D; prefer: stash|soft_reset|dry-run; push: refuse_non_ff
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs and a change at push. See https://github.com/open-coder-ai/chock
