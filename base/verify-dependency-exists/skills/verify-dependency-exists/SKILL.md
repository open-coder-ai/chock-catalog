---
name: verify-dependency-exists
description: "Allowlist gate for new dependencies; no registry lookup is made. Watches requirements.txt, pyproject.toml ([project] and poetry dependencies), package.json, go.mod; blocks an added name missing from .chock/dependency-allowlist.txt. Not read: -r/-e lines, requirements-dev.txt, poetry groups, [dependency-groups]. Opt-in: fill the allowlist, then `chock enable verify-dependency-exists`. Runs: commit, agent write (vs disk), turn's end (vs HEAD)."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Dependency Allowlist

Allowlist gate for new dependencies; no registry lookup is made. Watches requirements.txt, pyproject.toml ([project] and poetry dependencies), package.json, go.mod; blocks an added name missing from .chock/dependency-allowlist.txt. Not read: -r/-e lines, requirements-dev.txt, poetry groups, [dependency-groups]. Opt-in: fill the allowlist, then `chock enable verify-dependency-exists`. Runs: commit, agent write (vs disk), turn's end (vs HEAD).

```
on(commit|tool_use): block(dependency_allowlist) manifests=requirements.txt|pyproject.toml|package.json|... allowlist_file=.chock/dependency-allowlist.txt
Unknown dependency blocked: it is not in .chock/dependency-allowlist.txt. This gate checks the allowlist only and makes no registry lookup, so confirm the package exists in the official registry first. If you are an agent, ask a person to add the name; do not edit that file yourself (protect-agent-config). If you are a person, add the name to the file.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
