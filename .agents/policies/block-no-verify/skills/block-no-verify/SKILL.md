---
name: block-no-verify
description: "Best-effort guard against skipping git hooks: --no-verify on commit, push, merge, am and rebase, -n on commit and am (on push -n is --dry-run, allowed), and core.hooksPath set by -c, --config-env, `git config` or GIT_CONFIG_*. Read as parsed commands: wrappers are seen, message text is not. Also refuses an agent setting a person-only variable (CHOCK_ALLOW*, CHOCK_AGENT_COMMIT, CHOCK_DIFF_LIMIT) or hiding CLAUDECODE/AI_AGENT/CHOCK_AGENT_COMMIT; it says ask the person. Bypasses: aliases, scripts."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block No-Verify

Best-effort guard against skipping git hooks: --no-verify on commit, push, merge, am and rebase, -n on commit and am (on push -n is --dry-run, allowed), and core.hooksPath set by -c, --config-env, `git config` or GIT_CONFIG_*. Read as parsed commands: wrappers are seen, message text is not. Also refuses an agent setting a person-only variable (CHOCK_ALLOW*, CHOCK_AGENT_COMMIT, CHOCK_DIFF_LIMIT) or hiding CLAUDECODE/AI_AGENT/CHOCK_AGENT_COMMIT; it says ask the person. Bypasses: aliases, scripts.

```
never(commit|merge|am|rebase|push): --no-verify|-n(commit|am); never(set): core.hooksPath; never(agent_set|unset): CHOCK_ALLOW*|CHOCK_AGENT_COMMIT|CHOCK_DIFF_LIMIT|CLAUDECODE|AI_AGENT
if(hook_fails|override_needed): fix_issue|ask_person; never(skip_hook)
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs. See https://github.com/open-coder-ai/chock
