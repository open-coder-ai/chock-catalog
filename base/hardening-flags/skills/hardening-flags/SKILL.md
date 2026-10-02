---
name: hardening-flags
description: "Blocks added settings that weaken compiler, linker, Rust or kernel hardening, in CMake, Make, meson, configure.ac, Cargo, build.rs, Go release scripts, Dockerfiles and kernel config: no stack protector, FORTIFY_SOURCE off, non-PIE, execstack, norelro, CET off, kernel KASLR/RWX off. Asks on Rust release overflow-checks off, /dev/mem. Misses flags set by environment, generated files, toolchain defaults. Runs: commit, agent write, turn's end, CI. Waiver: 'pragma: allowlist hardening-flag'."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Hardening Flags

Blocks added settings that weaken compiler, linker, Rust or kernel hardening, in CMake, Make, meson, configure.ac, Cargo, build.rs, Go release scripts, Dockerfiles and kernel config: no stack protector, FORTIFY_SOURCE off, non-PIE, execstack, norelro, CET off, kernel KASLR/RWX off. Asks on Rust release overflow-checks off, /dev/mem. Misses flags set by environment, generated files, toolchain defaults. Runs: commit, agent write, turn's end, CI. Waiver: 'pragma: allowlist hardening-flag'.

```
on(commit|tool_use): block(script) script=hardening-flags-gate.py
A build or kernel setting that weakens a hardening default was added (stack protector, FORTIFY_SOURCE, PIE, RELRO, non-executable stack, CET, kernel KASLR or RWX). Keep the default or enable the protection. A person may waive a reviewed setting with 'pragma: allowlist hardening-flag' in a comment on the same line and commit from their own shell; in the agent a waiver counts only for a line already committed in HEAD, so an agent asks the person rather than writing the pragma itself.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
