---
name: code-safety
description: "trigger: secrets, eval/exec, unsanitized SQL, hallucinated dependencies. avoid: committing credentials, adding unverified packages, executing dynamic code."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Code Safety Rule

trigger: secrets, eval/exec, unsanitized SQL, hallucinated dependencies. avoid: committing credentials, adding unverified packages, executing dynamic code.

```
never(commit): secrets|keys|tokens|passwords|.env; never(add): eval|exec|unsanitized_sql
before(dependency): verify(exists_in_registry); on_find(secret|hallucinated_pkg): block + remove
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
