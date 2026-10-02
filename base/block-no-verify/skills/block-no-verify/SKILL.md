---
name: block-no-verify
description: "Friction, not a security boundary: refuses agent commands that skip git hooks. --no-verify on commit/push/merge/am/rebase/pull/cherry-pick/revert, -n on commit/am; core.hooksPath set by -c, git config or GIT_CONFIG_*; HUSKY=0, SKIP=, LEFTHOOK=0 and kin; pre-commit/lefthook/husky uninstall; aliases and rebase --exec it sees defined. Asks on commit-tree/update-ref, GIT_DIR and config files. Refuses person-only CHOCK_*/marker changes. Misses: older aliases, scripts."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block No-Verify

Friction, not a security boundary: refuses agent commands that skip git hooks. --no-verify on commit/push/merge/am/rebase/pull/cherry-pick/revert, -n on commit/am; core.hooksPath set by -c, git config or GIT_CONFIG_*; HUSKY=0, SKIP=, LEFTHOOK=0 and kin; pre-commit/lefthook/husky uninstall; aliases and rebase --exec it sees defined. Asks on commit-tree/update-ref, GIT_DIR and config files. Refuses person-only CHOCK_*/marker changes. Misses: older aliases, scripts.

```
never(commit|push|merge|am|rebase|pull|cherry-pick|revert): --no-verify|-n(commit|am); never(set): core.hooksPath|HUSKY=0|SKIP=|LEFTHOOK=0|kin; never: pre-commit|lefthook|husky uninstall; ask: commit-tree|update-ref|GIT_DIR|config files
never(agent_set|unset): CHOCK_ALLOW*|CHOCK_AGENT_COMMIT|CHOCK_DIFF_LIMIT|CLAUDECODE|AI_AGENT; if(hook_fails|override_needed): fix_issue|ask_person
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs. See https://github.com/open-coder-ai/chock
