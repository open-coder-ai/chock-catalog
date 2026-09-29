---
name: limit-diff-size
description: "trigger: staging a large change, committing more than a reviewer can read at once. avoid: one commit carrying hundreds of hand-written lines; lockfile and generated churn is not counted."
metadata:
  chock.artifact: rule
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Limit Diff Size Rule

trigger: staging a large change, committing more than a reviewer can read at once. avoid: one commit carrying hundreds of hand-written lines; lockfile and generated churn is not counted.

```
at(commit): refuse if sum(added+removed, staged) > CHOCK_DIFF_LIMIT (default 500); excluded: lockfiles|vendor/|node_modules/|dist/|build/|*.min.js|*.min.css|*.snap|.chock/|binary
on(refused): split into atomic commits (git add -p); override: CHOCK_ALLOW_LARGE_DIFF=1 set by a human only; agent: never(set_override), ask(human)
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
