---
name: block-test-skips
description: "Blocks newly added test skips and focus markers -- @pytest.mark.skip/skipif, @unittest.skip, it/describe/test.skip, xit/xdescribe, it/describe/test.only, JUnit @Disabled/@Ignore and Go t.Skip -- in test files, at commit and at agent tool-use. Only lines the change adds are judged (against HEAD), so a skip already committed never blocks an unrelated edit. Companion of protect-test-integrity, which cannot see skips. Waivers: 'chock: allow test-skip' on the line is honoured only at commit in chock 0.13.0, never in the agent, and never when CHOCK_AGENT_COMMIT is set; an agent that needs a skip must ask a person."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Test Skips

Blocks newly added test skips and focus markers -- @pytest.mark.skip/skipif, @unittest.skip, it/describe/test.skip, xit/xdescribe, it/describe/test.only, JUnit @Disabled/@Ignore and Go t.Skip -- in test files, at commit and at agent tool-use. Only lines the change adds are judged (against HEAD), so a skip already committed never blocks an unrelated edit. Companion of protect-test-integrity, which cannot see skips. Waivers: 'chock: allow test-skip' on the line is honoured only at commit in chock 0.13.0, never in the agent, and never when CHOCK_AGENT_COMMIT is set; an agent that needs a skip must ask a person.

```
on(commit|tool_use): block(script) script=block-test-skips-gate.py
Test skip added. Fix the test or the code instead of skipping it. A person may waive a reviewed skip with 'chock: allow test-skip' on the line and commit from their own shell; in chock 0.13.0 the waiver is honoured only at commit, not in the agent, so an agent asks the person rather than writing the pragma itself.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
