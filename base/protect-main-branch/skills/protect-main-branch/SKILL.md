---
name: protect-main-branch
description: "Refuses direct commits and pushes to main or master in a git hook: at commit time it reads the current branch, at push time it parses the refs being pushed. Where an agent loads this as skill text only, it is advice, and nothing stops a violation."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Protect Main Branch

Refuses direct commits and pushes to main or master in a git hook: at commit time it reads the current branch, at push time it parses the refs being pushed. Where an agent loads this as skill text only, it is advice, and nothing stops a violation.

```
on(commit|push): block(forbidden_ref) refs=main|master
Direct commits/pushes to a protected branch (main|master) are blocked. Create a feature branch and open a pull request.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit and at push. See https://github.com/open-coder-ai/chock
