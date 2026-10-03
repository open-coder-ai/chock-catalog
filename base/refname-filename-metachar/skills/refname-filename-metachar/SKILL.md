---
name: refname-filename-metachar
description: "Refuses names a shell, CI step or git can misread. Paths a change adds or renames into (commit, agent writes), and branches and tags pushed (pre-push), with command substitution, an IFS expansion, a backtick, ; & | < >, a control or bidi character, a base64-decode shape, a leading dash or trailing space or dot in a segment, or a '..' segment; a ref also with a full commit id's shape. A guard refuses git and file commands creating such names. No waiver. Friction, not a boundary."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Refname Filename Metachar

Refuses names a shell, CI step or git can misread. Paths a change adds or renames into (commit, agent writes), and branches and tags pushed (pre-push), with command substitution, an IFS expansion, a backtick, ; & | < >, a control or bidi character, a base64-decode shape, a leading dash or trailing space or dot in a segment, or a '..' segment; a ref also with a full commit id's shape. A guard refuses git and file commands creating such names. No waiver. Friction, not a boundary.

```
on(commit|tool_use): block(script) script=refname-filename-metachar-gate.py
A path this change adds or renames into has a name a shell, a CI step or git can misread: command substitution, an IFS expansion, a backtick, a shell operator, a control or bidi character, a base64-decode shape, a segment starting with '-' or ending in a space or '.', or a '..' segment. Rename it with letters, digits, spaces inside, '.', '_', '-' and '/'. No waiver: if the name is truly required, a person creates it from their own shell.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs and a change at push; blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
