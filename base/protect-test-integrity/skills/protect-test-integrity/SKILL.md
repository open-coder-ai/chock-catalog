---
name: protect-test-integrity
description: "Blocks a commit that turns tests green by weakening them instead of fixing the code: a deleted test file, a net loss of assertions across the change, or a vacuous assertion (assert True, expect(true).toBe(true)) added in place of a real one. Covers Python, JS/TS, Go and Java test layouts. Mechanised slice of agent-discipline's never(fix_test_by) rule; added skips are block-test-skips. Enforced at commit and at agent tool-use (an edit that weakens a test is judged against the file on disk, the turn's end against HEAD; Edit and Write cannot delete a file). A reviewed exception carries 'chock: allow test-integrity' on an added line of the test file; a waiver is honoured at commit only, never in the agent."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Protect Test Integrity

Blocks a commit that turns tests green by weakening them instead of fixing the code: a deleted test file, a net loss of assertions across the change, or a vacuous assertion (assert True, expect(true).toBe(true)) added in place of a real one. Covers Python, JS/TS, Go and Java test layouts. Mechanised slice of agent-discipline's never(fix_test_by) rule; added skips are block-test-skips. Enforced at commit and at agent tool-use (an edit that weakens a test is judged against the file on disk, the turn's end against HEAD; Edit and Write cannot delete a file). A reviewed exception carries 'chock: allow test-integrity' on an added line of the test file; a waiver is honoured at commit only, never in the agent.

```
on(commit|tool_use): block(test_integrity) test_path_regex=(^|/)(tests?/|__tests__/|test_[^/]*\.py$|[^/]... ...
Test integrity: this change deletes a test file, removes more assertions than it adds, or adds a vacuous assertion. Fix the code under test, not the test. If the removal is deliberate (obsolete behaviour, a test moved elsewhere), a person adds 'chock: allow test-integrity' on an added line of that test file and commits from their own shell; the waiver is honoured at commit only, never in the agent (tool use, the turn's end, or a commit with CHOCK_AGENT_COMMIT set), so an agent asks a person.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
