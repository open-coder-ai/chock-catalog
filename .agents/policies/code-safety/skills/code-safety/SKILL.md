---
name: code-safety
description: "trigger: secrets, eval/exec, unsanitized SQL, hallucinated dependencies. avoid: committing credentials, adding unverified packages, executing dynamic code. Install scan-secrets for the enforced counterpart of the secret slice (a commit-time gate), and verify-dependency-exists for the dependency slice (opt-in: disabled by default, needs a curated allowlist); the eval/exec and unsanitized-SQL guidance stays advisory (no diff-time gate can decide whether dynamic execution or a query string is unsafe)."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Code Safety Rule

trigger: secrets, eval/exec, unsanitized SQL, hallucinated dependencies. avoid: committing credentials, adding unverified packages, executing dynamic code. Install scan-secrets for the enforced counterpart of the secret slice (a commit-time gate), and verify-dependency-exists for the dependency slice (opt-in: disabled by default, needs a curated allowlist); the eval/exec and unsanitized-SQL guidance stays advisory (no diff-time gate can decide whether dynamic execution or a query string is unsafe).

```
see(scan-secrets): commit(secrets|keys|tokens|passwords|.env); see(verify-dependency-exists, opt_in): add(unlisted_dependency)
advisory: avoid(eval|exec|unsanitized_sql); on_find(secret|hallucinated_pkg): propose_removal_to_human
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
