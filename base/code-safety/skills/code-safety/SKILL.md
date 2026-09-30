---
name: code-safety
description: "trigger: secrets, eval/exec, unsanitized SQL, hallucinated dependencies. avoid: committing credentials, adding unverified packages, executing dynamic code. Install scan-secrets (commit, agent write) for secrets and verify-dependency-exists (opt-in; needs an allowlist) for dependencies. Advisory: eval/exec and SQL guidance; a gate decides only the non-literal slice (agentic-code-security code pack: Python eval/exec, SQL built from strings in Python and JS)."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Code Safety Rule

trigger: secrets, eval/exec, unsanitized SQL, hallucinated dependencies. avoid: committing credentials, adding unverified packages, executing dynamic code. Install scan-secrets (commit, agent write) for secrets and verify-dependency-exists (opt-in; needs an allowlist) for dependencies. Advisory: eval/exec and SQL guidance; a gate decides only the non-literal slice (agentic-code-security code pack: Python eval/exec, SQL built from strings in Python and JS).

```
see(scan-secrets): commit|agent_write(secrets|keys|tokens|passwords|.env); see(verify-dependency-exists, opt_in): add(unlisted_dependency)
see(agentic-code-security pack code): refuses Python eval|exec of non-literal text and SQL built from strings (Python|JS); advisory: avoid(eval|exec|unsanitized_sql); on_find(secret|hallucinated_pkg): propose_removal_to_human
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
