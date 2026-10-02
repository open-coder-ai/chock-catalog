---
name: block-test-skips
description: "Blocks newly added test skips, focus markers and runner options that hide tests: pytest/unittest skips, non-strict xfail, importorskip; JS skip/only/todo/fixme, x/f prefixes; JUnit Disabled/Assume; Go Skip, Short(); Rust ignore; RSpec, PHPUnit, C#, Swift skips; --deselect/-k not, collect_ignore, jest testPathIgnorePatterns. Runs: commit, agent write, turn's end; only additions judged. Friction: computed names evade it. Waiver: 'chock: allow test-skip' same line; agent: only if in HEAD."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Test Skips

Blocks newly added test skips, focus markers and runner options that hide tests: pytest/unittest skips, non-strict xfail, importorskip; JS skip/only/todo/fixme, x/f prefixes; JUnit Disabled/Assume; Go Skip, Short(); Rust ignore; RSpec, PHPUnit, C#, Swift skips; --deselect/-k not, collect_ignore, jest testPathIgnorePatterns. Runs: commit, agent write, turn's end; only additions judged. Friction: computed names evade it. Waiver: 'chock: allow test-skip' same line; agent: only if in HEAD.

```
on(commit|tool_use): block(script) script=block-test-skips-gate.py
Test skip, focus marker (.only) or test-hiding runner option added. Fix the test or the code instead of skipping, focusing or deselecting it. A person may waive a reviewed skip with 'chock: allow test-skip' on the line and commit from their own shell; in the agent a waiver counts only for a line already committed in HEAD, so an agent asks the person rather than writing the pragma itself.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
