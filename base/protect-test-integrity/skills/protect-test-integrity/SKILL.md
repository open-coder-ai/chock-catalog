---
name: protect-test-integrity
description: "Blocks weakening tests to turn them green: a deleted test file (commit only), a net loss of assertions, or an added vacuous assertion (assert True, expect(true).toBe(true)). Added skips are block-test-skips. Runs: commit (incl. an agent's commit: CHOCK_AGENT_COMMIT, CLAUDECODE=1, AI_AGENT or agent_commit_env), agent write (vs disk), turn's end (vs HEAD). Waiver: 'chock: allow test-integrity' on an added line. Person's commit: honoured. Agent: only if already in HEAD; it asks a person."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Protect Test Integrity

Blocks weakening tests to turn them green: a deleted test file (commit only), a net loss of assertions, or an added vacuous assertion (assert True, expect(true).toBe(true)). Added skips are block-test-skips. Runs: commit (incl. an agent's commit: CHOCK_AGENT_COMMIT, CLAUDECODE=1, AI_AGENT or agent_commit_env), agent write (vs disk), turn's end (vs HEAD). Waiver: 'chock: allow test-integrity' on an added line. Person's commit: honoured. Agent: only if already in HEAD; it asks a person.

```
on(commit|tool_use): block(test_integrity) test_path_regex(regex) assertion_pattern(regex) dummy_assertion_pattern(regex) ...
Test integrity: this change deletes a test file, removes more assertions than it adds, or adds a vacuous assertion. Fix the code under test, not the test. If the removal is deliberate (obsolete behaviour, a test moved elsewhere), a person adds 'chock: allow test-integrity' on an added line of that test file and commits from their own shell. In the agent (tool use, the turn's end, an agent's commit) only a waiver already committed in HEAD counts, so an agent asks a person.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
