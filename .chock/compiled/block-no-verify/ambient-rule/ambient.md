<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/block-no-verify/) -->
```
never(commit|merge|am|rebase|push): --no-verify|-n(commit|am); never(set): core.hooksPath; never(agent_set|unset): CHOCK_ALLOW*|CHOCK_AGENT_COMMIT|CHOCK_DIFF_LIMIT|CLAUDECODE|AI_AGENT
if(hook_fails|override_needed): fix_issue|ask_person; never(skip_hook)
```
<!-- chock:hooks:end -->
