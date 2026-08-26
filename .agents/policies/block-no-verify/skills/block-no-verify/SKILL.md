---
name: block-no-verify
description: "Best-effort guard against bypassing git hooks via git commit/push --no-verify, commit's short -n form, or -c core.hooksPath overrides. On git push, -n means --dry-run and stays allowed. Known bypass classes include aliases, wrapper scripts, and non-standard clients. Fix the underlying hook failure instead of skipping validation."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block No-Verify

Best-effort guard against bypassing git hooks via git commit/push --no-verify, commit's short -n form, or -c core.hooksPath overrides. On git push, -n means --dry-run and stays allowed. Known bypass classes include aliases, wrapper scripts, and non-standard clients. Fix the underlying hook failure instead of skipping validation.

```
never(commit): --no-verify|-n; never(push): --no-verify
if(hook_fails): fix_issue; never(skip_hook)
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
