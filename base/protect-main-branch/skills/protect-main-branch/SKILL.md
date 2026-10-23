---
name: protect-main-branch
description: "Keeps agents off main and master: a git hook reads the current branch at commit time and parses the refs being pushed at push time. The hook refuses a violation only where it is installed. As skill text alone this is advice, and nothing stops one."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Protect Main Branch

Keeps agents off main and master: a git hook reads the current branch at commit time and parses the refs being pushed at push time. The hook refuses a violation only where it is installed. As skill text alone this is advice, and nothing stops one.

```
on(commit|push): block(forbidden_ref) refs=main|master
Direct commits/pushes to a protected branch (main|master) are blocked. Create a feature branch and open a pull request.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit and at push. See https://github.com/open-coder-ai/chock
