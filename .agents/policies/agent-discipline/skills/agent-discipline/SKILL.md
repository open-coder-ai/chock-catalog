---
name: agent-discipline
description: "trigger: edits without reading, unverified completion claims, weakened tests, dead code. avoid: skipping verification, deleting assertions, leaving unused code."
metadata:
  chock:
    artifact: rule
    enforcement: advise
    coverage_without_chock: advisory
---

# Agent Discipline Rule

trigger: edits without reading, unverified completion claims, weakened tests, dead code. avoid: skipping verification, deleting assertions, leaving unused code.

```
before(edit): read(file); before(done): verify(flow) + tests_pass + lint_clean
never(fix_test_by): delete_assertion|weaken_check|skip; on_find(dead_code|unused): delete
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
