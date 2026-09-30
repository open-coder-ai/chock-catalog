---
name: rtk-dangerous-actions-blocker
description: "rtk#1007. Blocks: rm -rf on /, ~, ., .. or abs paths; PowerShell/cmd drive removal; git push --force/+refspec; credential-file reads (.env, keys, ~/.ssh); echo/inline *_API_KEY/_SECRET/_TOKEN; SQL DROP/TRUNCATE/unscoped DELETE/FLUSHALL; dropdb; kubectl delete, terraform destroy, aws s3 rm --recursive/rb --force, helm uninstall, gcloud delete, docker volume rm. Asks: relative rm -rf off safe list, git reset --hard/clean -f/checkout ./branch -D, docker prune. Skips rm/file/echo in container exec."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# rtk Dangerous Actions Blocker

rtk#1007. Blocks: rm -rf on /, ~, ., .. or abs paths; PowerShell/cmd drive removal; git push --force/+refspec; credential-file reads (.env, keys, ~/.ssh); echo/inline *_API_KEY/_SECRET/_TOKEN; SQL DROP/TRUNCATE/unscoped DELETE/FLUSHALL; dropdb; kubectl delete, terraform destroy, aws s3 rm --recursive/rb --force, helm uninstall, gcloud delete, docker volume rm. Asks: relative rm -rf off safe list, git reset --hard/clean -f/checkout ./branch -D, docker prune. Skips rm/file/echo in container exec.

```
block: rm_-rf(/|~|.|..|abs), git_push(--force|+ref), read(.env|*.pem|*.key|id_rsa|~/.ssh|~/.aws), echo|inline($*_API_KEY|$*_SECRET|$*_TOKEN), sql(DROP|TRUNCATE|DELETE_no_WHERE)|dropdb|FLUSHALL, kubectl_delete|terraform_destroy|aws_s3(rm_--recursive|rb_--force)|helm_uninstall|gcloud_delete|docker_volume_rm
ask: rm_-rf(relative, off safe_list), git(reset_--hard|clean_-f|checkout_.|branch_-D), docker_*_prune|docker_rm_-f_$(..); skip_inside: docker|kubectl_exec; prefix: rtk; prefer: stash|dry-run
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
