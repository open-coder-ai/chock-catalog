---
name: memory-discipline
description: "trigger: repeated mistakes, rediscovered patterns, preferences, non-derivable facts. avoid: persisting file contents, git history, or task intermediates as memory."
metadata:
  chock:
    artifact: rule
    enforcement: advise
    coverage_without_chock: advisory
---

# Memory Discipline Rule

trigger: repeated mistakes, rediscovered patterns, preferences, non-derivable facts. avoid: persisting file contents, git history, or task intermediates as memory.

```
persist: decisions|preferences|non_derivable_facts; never_persist: file_contents|git_history|task_intermediates
extract(atomic_facts); consolidate(similar > 0.85); decay(stale); verify(memory) before_recommend
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
