---
name: protect-ci-workflows
description: "Stops an agent weakening the checks that review its work. Shell guard refuses writes to .github/workflows/, .github/actions/, .github/dependabot.y*ml (redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, cmdlets); reads and `chock sync` pass. Edit/Write: tool_use gate asks a person before a write to CI, hook or bot config (GitLab, Jenkins, CircleCI, Azure, Buildkite, CODEOWNERS, husky, pre-commit, more). Not yet: shell writes to non-GitHub CI paths; plugin installs ship no gate."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Protect CI Workflows

Stops an agent weakening the checks that review its work. Shell guard refuses writes to .github/workflows/, .github/actions/, .github/dependabot.y*ml (redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, cmdlets); reads and `chock sync` pass. Edit/Write: tool_use gate asks a person before a write to CI, hook or bot config (GitLab, Jenkins, CircleCI, Azure, Buildkite, CODEOWNERS, husky, pre-commit, more). Not yet: shell writes to non-GitHub CI paths; plugin installs ship no gate.

```
ci_config(.github/{workflows,actions,dependabot.y*ml}): never(shell_edit|delete); edit_or_write(those|CODEOWNERS|.gitlab-ci.yml|.gitlab/|Jenkinsfile*|.circleci/|azure-pipelines*|bitbucket-pipelines.yml|.buildkite/|.drone.yml|cloudbuild*|renovate|.pre-commit-config.yaml|.husky/|lefthook|.githooks/|.travis.yml|action.yml|more): ask_person
if(ci_change_needed): ask_person; person edits from own shell; no agent-typed marker passes  # an agent must not disarm the checks on its own work
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs; asks on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
