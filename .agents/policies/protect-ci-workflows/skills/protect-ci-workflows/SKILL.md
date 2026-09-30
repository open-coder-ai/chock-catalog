---
name: protect-ci-workflows
description: "Stops an agent weakening the checks that review its work. Shell guard refuses writes to .github/workflows/, .github/actions/ and .github/dependabot.yml|yaml: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, Set-Content/Add-Content/Out-File. Reads and `chock sync` pass. Best-effort, coarse. No marker bypass: a person edits from their own shell. Shell only: Edit/Write to these paths is not checked (no gate). Backstop: server-side branch protection."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Protect CI Workflows

Stops an agent weakening the checks that review its work. Shell guard refuses writes to .github/workflows/, .github/actions/ and .github/dependabot.yml|yaml: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, Set-Content/Add-Content/Out-File. Reads and `chock sync` pass. Best-effort, coarse. No marker bypass: a person edits from their own shell. Shell only: Edit/Write to these paths is not checked (no gate). Backstop: server-side branch protection.

```
ci_config(.github/workflows|.github/actions|.github/dependabot.yml|yaml): never(shell_edit|delete); ask_person
if(ci_change_needed): ask_person; person edits from own shell; no agent-typed marker passes  # an agent must not disarm the checks on its own work
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs. See https://github.com/open-coder-ai/chock
