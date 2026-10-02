---
name: block-destructive-commands
description: "Best-effort, on parsed commands (echo ignored); verdicts come from the chock_destructive table shared with rtk-dangerous-actions-blocker. Blocks recursive deletes of root, home or abs paths; mv/chmod/chown -R of system dirs; dd to devices, mkfs; account lockouts; force, delete and mirror pushes; history rewrites; IaC destroy; listed cloud and platform deletes; DB drops. Asks: rm -rf off a safe list, bare lease, stash drop, -auto-approve, drain, prunes, API deletes. Pre-push: no non-ff."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Destructive Commands

Best-effort, on parsed commands (echo ignored); verdicts come from the chock_destructive table shared with rtk-dangerous-actions-blocker. Blocks recursive deletes of root, home or abs paths; mv/chmod/chown -R of system dirs; dd to devices, mkfs; account lockouts; force, delete and mirror pushes; history rewrites; IaC destroy; listed cloud and platform deletes; DB drops. Asks: rm -rf off a safe list, bare lease, stash drop, -auto-approve, drain, prunes, API deletes. Pre-push: no non-ff.

```
block(shared table): rm|rmdir|mv|chmod|chown_-R(root|home|/etc..), rm_-rf(abs|.|$PWD), dd_of=/dev|mkfs|wipefs|shred, lock(authorized_keys|usermod_-L|passwd_-l|chattr_+i|kill_-1|crontab_-r), git(push_-f|+ref|-d|:ref|--mirror, reset_--hard, clean_-f, checkout|restore_., reflog|gc|filter), iac_destroy, cloud|k8s|helm|paas_delete, sql_drop|dropdb
ask: rm_-rf(off safe_list), lease_bare, stash_drop, branch_-D, -auto-approve, drain, prune, pkill_-f, systemctl_disable, api_DELETE; push: refuse_non_ff
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs and a change at push. See https://github.com/open-coder-ai/chock
