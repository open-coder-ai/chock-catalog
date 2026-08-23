---
name: verify-catalog-conformance
description: "Repo-local policy (this repo only, never published): run the fast deterministic catalog checks at commit time -- registry labels, README counts, quoted console output, workflow-trigger safety -- so a mismatch fails in seconds under the committer's hands instead of minutes later in CI. Each of these caught a real error from CI on 2026-08-16. CI remains the authority: it re-runs the same tools on the pinned engine plus everything too slow for a hook (evals, transcripts, the staged adopter). Skips with a warning when python is absent, because the backstop is what makes that honest."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Verify Catalog Conformance

Repo-local policy (this repo only, never published): run the fast deterministic catalog checks at commit time -- registry labels, README counts, quoted console output, workflow-trigger safety -- so a mismatch fails in seconds under the committer's hands instead of minutes later in CI. Each of these caught a real error from CI on 2026-08-16. CI remains the authority: it re-runs the same tools on the pinned engine plus everything too slow for a hook (evals, transcripts, the staged adopter). Skips with a warning when python is absent, because the backstop is what makes that honest.

```
before(commit): pass(check_registry, check_readme, check_console, check_workflows)  # enforced by the installed pre-commit implementation
if(check_fails): fix_the_source; never(edit_the_check_to_pass)
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
