<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/protect-ci-workflows/) -->
```
ci_config(.github/workflows|.github/actions|.github/dependabot.yml|yaml): never(shell_edit|delete); ask_person
if(ci_change_needed): ask_person; person edits from own shell; no agent-typed marker passes  # an agent must not disarm the checks on its own work
```
<!-- chock:hooks:end -->
