---
name: block-hook-bypass-in-files
description: "Friction, not a security boundary: flags lines added to hook launchers and scripts that switch git hooks off -- the hook-skip option on a git commit/push/merge/am/rebase/pull, core.hooksPath set, the husky, lefthook and pre-commit off-switch variables (HUSKY or LEFTHOOK zero, SKIP and the like), an uninstall by pre-commit, lefthook or husky -- in .husky/, .githooks/, lefthook, package.json, Makefile, justfile, *.sh. Warns only (observe). Misses: split lines, -n, other files."
metadata:
  chock.artifact: hook
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Hook Bypass In Files

Friction, not a security boundary: flags lines added to hook launchers and scripts that switch git hooks off -- the hook-skip option on a git commit/push/merge/am/rebase/pull, core.hooksPath set, the husky, lefthook and pre-commit off-switch variables (HUSKY or LEFTHOOK zero, SKIP and the like), an uninstall by pre-commit, lefthook or husky -- in .husky/, .githooks/, lefthook, package.json, Makefile, justfile, *.sh. Warns only (observe). Misses: split lines, -n, other files.

```
on(commit|tool_use): warn(content_regex) paths=.husky/*|*/.husky/*|.githooks/*|*/.githooks/*|lefthook*.y*ml|*/lefthook*.y*ml|.lefthook*.y*ml|*/.lefthook*.y*ml|package.json|*/package.json|Makefile|*/Makefile|makefile|*/makefile|GNUmakefile|*/GNUmakefile|*.mk|justfile|*/justfile|Justfile|*/Justfile|.justfile|*/.justfile|*.sh|*.bash|*.zsh scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+hook-bypass content_pattern(regex)
This line switches git hooks off for everyone who runs this file (a hook-skip option on a git command, a new hooks path (core.hooksPath), a hook manager's off-switch variable such as HUSKY set to zero, or an uninstall). Fix the failing hook instead. A person who has reviewed it may keep it with 'pragma: allowlist hook-bypass' on the same line (a person's commit honours it; in the agent only a line already in HEAD counts). An agent asks a person; it never writes the pragma.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` warns at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
