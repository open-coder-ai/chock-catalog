---
name: verify-dependency-exists
description: "Block hallucinated or unknown dependencies before they enter the repo. Watches requirements.txt, pyproject.toml, package.json, and go.mod, and blocks any newly added dependency not present in the allowlist file. Opt-in: disabled by default because it requires a curated allowlist. Enable with `chock enable verify-dependency-exists` after populating .chock/dependency-allowlist.txt."
metadata:
  chock:
    artifact: hook
    enforcement: block
    coverage_without_chock: advisory
---

# Verify Dependency Exists

Block hallucinated or unknown dependencies before they enter the repo. Watches requirements.txt, pyproject.toml, package.json, and go.mod, and blocks any newly added dependency not present in the allowlist file. Opt-in: disabled by default because it requires a curated allowlist. Enable with `chock enable verify-dependency-exists` after populating .chock/dependency-allowlist.txt.

```
on(commit): block(dependency_allowlist) manifests=requirements.txt|pyproject.toml|package.json|... allowlist_file=.chock/dependency-allowlist.txt
Unknown dependency blocked. Verify the package exists in the official registry, then add it to .chock/dependency-allowlist.txt to allow it.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
