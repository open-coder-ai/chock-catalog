# Protect Test Integrity

`protect-test-integrity` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | test_integrity gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 19 total, 17 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Blocks weakening tests to turn them green: a deleted test file (commit only), a net loss of assertions, or an added vacuous assertion (assert True, expect(true).toBe(true)). Added skips are block-test-skips. Runs: commit (incl. an agent's commit: CHOCK_AGENT_COMMIT, CLAUDECODE=1, AI_AGENT or agent_commit_env), agent write (vs disk), turn's end (vs HEAD). Waiver: 'chock: allow test-integrity' on an added line. Person's commit: honoured. Agent: only if already in HEAD; it asks a person.

## What it solves

An agent asked to make a red suite green can do it by weakening the suite: deleting the failing test, cutting assertions, or replacing one with `assert True`. CI then goes green over a bug. This gate refuses those three shapes at commit, where the diff is visible, and points the agent back at the code under test.

## How it works

A declarative `test_integrity` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `allowlist_pragma`
- `assertion_pattern`
- `dummy_assertion_pattern`
- `test_path_regex`

On a match it prints:

> Test integrity: this change deletes a test file, removes more assertions than it adds, or adds a vacuous assertion. Fix the code under test, not the test. If the removal is deliberate (obsolete behaviour, a test moved elsewhere), a person adds 'chock: allow test-integrity' on an added line of that test file and commits from their own shell. In the agent (tool use, the turn's end, an agent's commit) only a waiver already committed in HEAD counts, so an agent asks a person.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/protect-test-integrity/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add protect-test-integrity
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/protect-test-integrity  <your-repo>/.agents/policies/protect-test-integrity
cd <your-repo> && chock sync --repo .
```

## Customising it

Edit `test_path_regex` for a test layout it does not know, and `assertion_pattern` for a framework whose assertions it does not recognise. `dummy_assertion_pattern` lists the vacuous forms. A deliberate removal is waived by a person with `chock: allow test-integrity` on an added line of the test file; the waiver is not honoured for an agent's commit (`CHOCK_AGENT_COMMIT` set).

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals protect-test-integrity
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/protect-test-integrity/`](../../base/protect-test-integrity/) · [all policies](../README.md)
