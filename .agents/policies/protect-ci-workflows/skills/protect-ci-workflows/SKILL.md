---
name: protect-ci-workflows
description: "Guard against an agent weakening the automated checks that review its own work. CI/CD workflow files (.github/workflows/), the composite actions they call (.github/actions/) and the dependency-update automation (.github/dependabot.yml) define what must pass before a change lands -- so a shell command that rewrites or deletes them is the agent removing the gate that would catch it. The guard refuses shell write-commands targeting those paths; reads pass, and tool-driven regeneration (chock sync) passes because it writes through the tool, not shell editing. Best-effort and deliberately coarse: a compound command that both reads a protected file and writes elsewhere may be refused -- rewrite it in two steps. The 'chock: approved-config-change' escape marker is friction plus an audit trail, not authentication -- the agent can write it too; the check an agent cannot self-approve is branch protection and required-status-checks enforced server-side."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Protect CI Workflows

Guard against an agent weakening the automated checks that review its own work. CI/CD workflow files (.github/workflows/), the composite actions they call (.github/actions/) and the dependency-update automation (.github/dependabot.yml) define what must pass before a change lands -- so a shell command that rewrites or deletes them is the agent removing the gate that would catch it. The guard refuses shell write-commands targeting those paths; reads pass, and tool-driven regeneration (chock sync) passes because it writes through the tool, not shell editing. Best-effort and deliberately coarse: a compound command that both reads a protected file and writes elsewhere may be refused -- rewrite it in two steps. The 'chock: approved-config-change' escape marker is friction plus an audit trail, not authentication -- the agent can write it too; the check an agent cannot self-approve is branch protection and required-status-checks enforced server-side.

```
ci_config(.github/workflows|.github/actions|.github/dependabot.yml): never(shell_edit|delete); propose_to_human
if(ci_change_needed): open PR; await(review)  # an agent must not disarm the checks on its own work
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
