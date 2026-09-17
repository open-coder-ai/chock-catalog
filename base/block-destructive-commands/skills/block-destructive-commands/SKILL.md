---
name: block-destructive-commands
description: "Best-effort guard against destructive commands: rm -rf targeting absolute, home ($HOME/~) or root-adjacent paths (and the PowerShell Remove-Item -Recurse equivalent); git push --force (not --force-with-lease); git reset --hard; git clean -f; kubectl delete; terraform destroy; aws s3 rm --recursive / rb --force; dropdb; helm uninstall/delete; docker volume rm/prune and system prune; gcloud ... delete; find -delete / -exec rm; shred; truncate; wipefs -a. Destructive verbs are matched position-aware, so a bucket, path or object NAMED like a verb (helm list delete) is allowed, and find/shred/truncate apply the same target test as rm, so a relative path in the working tree stays allowed. sudo, doas and pkexec are transparent wrappers: the program they run is graded, escalation itself is not refused. Known bypasses: aliases, quoted arguments, non-standard clients, an unusual value-flag outside the curated set, and indirect invocation via a script or interpreter. This is friction, not a security boundary."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Destructive Commands

Best-effort guard against destructive commands: rm -rf targeting absolute, home ($HOME/~) or root-adjacent paths (and the PowerShell Remove-Item -Recurse equivalent); git push --force (not --force-with-lease); git reset --hard; git clean -f; kubectl delete; terraform destroy; aws s3 rm --recursive / rb --force; dropdb; helm uninstall/delete; docker volume rm/prune and system prune; gcloud ... delete; find -delete / -exec rm; shred; truncate; wipefs -a. Destructive verbs are matched position-aware, so a bucket, path or object NAMED like a verb (helm list delete) is allowed, and find/shred/truncate apply the same target test as rm, so a relative path in the working tree stays allowed. sudo, doas and pkexec are transparent wrappers: the program they run is graded, escalation itself is not refused. Known bypasses: aliases, quoted arguments, non-standard clients, an unusual value-flag outside the curated set, and indirect invocation via a script or interpreter. This is friction, not a security boundary.

```
block(destructive_command @position-aware): rm_-rf(/|~|$HOME|.)|Remove-Item_-Recurse, git_push_--force, git_reset_--hard, git_checkout_., git_clean_-f, kubectl_delete, terraform_destroy, aws_s3(rm_--recursive|rb_--force), dropdb, helm(uninstall|delete), docker_volume(rm|prune)|system_prune, gcloud_delete, find(-delete|-exec_rm)|shred|truncate @dangerous_target, wipefs(-a|-o)
require_approval: reset_hard|rm_-rf|branch_-D; prefer: stash|soft_reset|force-with-lease|dry-run
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
