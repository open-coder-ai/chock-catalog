<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/block-destructive-commands/) -->
```
block: rm|mv|chmod|chown_-R(root|home|sys),rm_-rf(abs|.|$PWD|.git),dd_of=/dev|mkfs|wipefs|shred,lockout(authkeys|usermod|passwd|chattr_+i|kill_-1|crontab),git(push_-f|+ref|-d|:ref|--mirror,reset_--hard,clean_-f,checkout|restore_.|switch_--discard,reflog|gc|filter),iac_destroy,cloud|k8s|helm_delete,sql_drop
ask: rm_-rf(off safe_list),kubectl_delete(1_named),lease_bare,stash_drop,branch_-D,-auto-approve,drain,prune,pkill_-f,systemctl_disable,api_DELETE;allow: tool_dry_run;push: refuse_non_ff
```
<!-- chock:hooks:end -->
