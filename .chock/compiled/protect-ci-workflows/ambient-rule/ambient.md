<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/protect-ci-workflows/) -->
```
ci_config(.github/{workflows,actions,dependabot.y*ml}): never(shell_edit|delete); edit_or_write(those|CODEOWNERS|.gitlab-ci.yml|.gitlab/|Jenkinsfile*|.circleci/|azure-pipelines*|bitbucket-pipelines.yml|.buildkite/|.drone.yml|cloudbuild*|renovate|.pre-commit-config.yaml|.husky/|lefthook|.githooks/|.travis.yml|action.yml|more): ask_person
if(ci_change_needed): ask_person; person edits from own shell; no agent-typed marker passes  # an agent must not disarm the checks on its own work
```
<!-- chock:hooks:end -->
