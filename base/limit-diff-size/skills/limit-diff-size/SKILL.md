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
at(commit): ask if sum(added+removed, staged) > CHOCK_DIFF_LIMIT (default 500); excluded: lockfiles|vendor/|node_modules/|dist/|build/|*.min.js|*.min.css|*.snap|.chock/|binary; git_diff_fails: block
on(asked): split into atomic commits (git add -p); answer: CHOCK_ALLOW=limit-diff-size|CHOCK_ALLOW_LARGE_DIFF=1|CHOCK_DIFF_LIMIT set by a human only; agent: never(set), ask(human)
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse a change at commit. See https://github.com/open-coder-ai/chock
