---
name: rtk-dangerous-actions-blocker
description: "rtk#1007. Destructive verdicts come from the chock_destructive table shared with block- destructive-commands: the same blocks (root/home deletes, force/delete/mirror pushes, reset --hard, clean -f, IaC destroy, cloud deletes, DB drops, lockouts) and asks (rm -rf off rtk's safe list, bare lease, stash drop, prunes, -auto-approve). Own rows block credential-file reads (.env, keys, ~/.ssh) and echo or inline *_API_KEY/_SECRET/_TOKEN. Skips file rows in container exec."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# rtk Dangerous Actions Blocker

rtk#1007. Destructive verdicts come from the chock_destructive table shared with block- destructive-commands: the same blocks (root/home deletes, force/delete/mirror pushes, reset --hard, clean -f, IaC destroy, cloud deletes, DB drops, lockouts) and asks (rm -rf off rtk's safe list, bare lease, stash drop, prunes, -auto-approve). Own rows block credential-file reads (.env, keys, ~/.ssh) and echo or inline *_API_KEY/_SECRET/_TOKEN. Skips file rows in container exec.

```
block: chock_destructive table (= block-destructive-commands: rm_-rf(/|~|.|abs), push(-f|+ref|:ref|--mirror), reset_--hard|clean_-f|checkout_., destroy|cloud_delete, sql_drop|dropdb), read(.env|*.pem|*.key|id_rsa|~/.ssh|~/.aws), echo|inline($*_API_KEY|$*_SECRET|$*_TOKEN)
ask: rm_-rf(relative, off safe_list), lease_bare, stash_drop, branch_-D, docker_*_prune, -auto-approve; skip_inside: docker|kubectl_exec(file rows); prefix: rtk; prefer: stash|dry-run
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs. See https://github.com/open-coder-ai/chock
