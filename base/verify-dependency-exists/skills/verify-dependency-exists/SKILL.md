---
name: verify-dependency-exists
description: "Allowlist gate for new dependencies; no registry lookup is made. Reads Python, Node, Rust, Ruby, PHP, JVM, .NET, Go, Elixir, Dart and Swift manifests (parsed, never run); blocks an added name missing from .chock/dependency-allowlist.txt and asks on a lockfile-only addition. Not read: computed lists, sources, versions. Opt-in: seed the allowlist, run in rollout observe, then `chock enable verify-dependency-exists`. Runs: commit, agent write, turn's end."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Dependency Allowlist

Allowlist gate for new dependencies; no registry lookup is made. Reads Python, Node, Rust, Ruby, PHP, JVM, .NET, Go, Elixir, Dart and Swift manifests (parsed, never run); blocks an added name missing from .chock/dependency-allowlist.txt and asks on a lockfile-only addition. Not read: computed lists, sources, versions. Opt-in: seed the allowlist, run in rollout observe, then `chock enable verify-dependency-exists`. Runs: commit, agent write, turn's end.

```
on(commit|tool_use): block(script) script=dependency-manifests.py
Unknown dependency blocked: it is not in .chock/dependency-allowlist.txt. This gate checks the allowlist only and makes no registry lookup, so confirm the package exists in its official registry and is the intended one first. If you are an agent, ask a person to add the name; do not edit that file yourself (protect-agent-config). If you are a person, add the name to the file.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
