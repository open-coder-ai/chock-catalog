---
name: code-safety
description: "trigger: secrets, eval/exec, unsanitized SQL, hallucinated dependencies. avoid: committing credentials, adding unverified packages, executing dynamic code. Install scan-secrets and verify-dependency-exists to enforce the secret and dependency slices deterministically; the eval/exec and unsanitized-SQL guidance stays advisory (no diff-time gate can decide whether dynamic execution or a query string is unsafe)."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Code Safety Rule

trigger: secrets, eval/exec, unsanitized SQL, hallucinated dependencies. avoid: committing credentials, adding unverified packages, executing dynamic code. Install scan-secrets and verify-dependency-exists to enforce the secret and dependency slices deterministically; the eval/exec and unsanitized-SQL guidance stays advisory (no diff-time gate can decide whether dynamic execution or a query string is unsafe).

```
enforced_when_installed(scan-secrets): commit(secrets|keys|tokens|passwords|.env); enforced_when_installed(verify-dependency-exists): add(unlisted_dependency)
advisory: avoid(eval|exec|unsanitized_sql); on_find(secret|hallucinated_pkg): propose_removal_to_human
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
