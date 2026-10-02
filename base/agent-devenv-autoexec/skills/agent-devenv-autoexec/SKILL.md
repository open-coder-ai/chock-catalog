---
name: agent-devenv-autoexec
description: "Warns only (observe): flags files that make a dev tool run code on open, clone or shell entry -- agent hooks, helpers, env/BASE_URL overrides, auto-approve; VS Code folderOpen tasks, trust off, repo executables; devcontainer initializeCommand; .envrc, mise, husky, lefthook, pre-commit; gitconfig exec keys, gitattributes drivers, unsafe .gitmodules. Commit, agent write, turn's end; additions only; unreadable configs refused. Friction: misses interpreted code and unlisted files."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Agent Devenv Autoexec

Warns only (observe): flags files that make a dev tool run code on open, clone or shell entry -- agent hooks, helpers, env/BASE_URL overrides, auto-approve; VS Code folderOpen tasks, trust off, repo executables; devcontainer initializeCommand; .envrc, mise, husky, lefthook, pre-commit; gitconfig exec keys, gitattributes drivers, unsafe .gitmodules. Commit, agent write, turn's end; additions only; unreadable configs refused. Friction: misses interpreted code and unlisted files.

```
devenv_autoexec(agent hooks|helpers|env overrides|auto-approve|folderOpen tasks|trust off|devcontainer lifecycle|.envrc|mise|git hooks|gitconfig exec|gitattributes drivers|.gitmodules): changed by people only
never(add): hook|task|helper|env override|auto-approval; observe: warns at commit+tool_use, enforce later
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` warns at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
