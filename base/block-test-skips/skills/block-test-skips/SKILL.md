---
name: block-test-skips
description: "Blocks newly added test skips and focus markers (@pytest.mark.skip/skipif, @unittest.skip, it/describe/test.skip or .only, xit/xdescribe, JUnit @Disabled/@Ignore, Go t.Skip) in test files. Runs: commit, agent write, turn's end. Only what the change adds is judged. Waiver: 'chock: allow test-skip' same line. Person's commit: honoured. Agent (write, turn's end, an agent's commit: CHOCK_AGENT_COMMIT, CLAUDECODE=1, AI_AGENT or agent_commit_env): only if already in HEAD; it asks a person."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Test Skips

Blocks newly added test skips and focus markers (@pytest.mark.skip/skipif, @unittest.skip, it/describe/test.skip or .only, xit/xdescribe, JUnit @Disabled/@Ignore, Go t.Skip) in test files. Runs: commit, agent write, turn's end. Only what the change adds is judged. Waiver: 'chock: allow test-skip' same line. Person's commit: honoured. Agent (write, turn's end, an agent's commit: CHOCK_AGENT_COMMIT, CLAUDECODE=1, AI_AGENT or agent_commit_env): only if already in HEAD; it asks a person.

```
on(commit|tool_use): block(script) script=block-test-skips-gate.py
Test skip or focus marker (.only) added. Fix the test or the code instead of skipping it. A person may waive a reviewed skip with 'chock: allow test-skip' on the line and commit from their own shell; in the agent a waiver counts only for a line already committed in HEAD, so an agent asks the person rather than writing the pragma itself.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
