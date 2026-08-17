---
name: context-hygiene
description: "trigger: context bloat, stale observations, resolved content inlined, noisy exploration. avoid: context rot and lost-in-the-middle failures."
metadata:
  chock:
    artifact: rule
    enforcement: advise
    coverage_without_chock: advisory
---

# Context Hygiene Rule

trigger: context bloat, stale observations, resolved content inlined, noisy exploration. avoid: context rot and lost-in-the-middle failures.

```
replace(resolved_content): path_ref_only; delegate(noisy_exploration): subagent; prune(stale > 3_turns)
on_context_growth: summarize(old_observations); keep(decisions+outcomes); discard(superseded_content)
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
