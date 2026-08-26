<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/protect-ci-workflows/) -->
```
ci_config(.github/workflows|.github/actions|.github/dependabot.yml): never(shell_edit|delete); propose_to_human
if(ci_change_needed): open PR; await(review)  # an agent must not disarm the checks on its own work
```
<!-- chock:hooks:end -->
