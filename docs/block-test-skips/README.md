# Block Test Skips

`block-test-skips` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 82 total, 81 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Blocks newly added test skips, focus markers and runner options that hide tests: pytest/unittest skips, non-strict xfail, importorskip; JS skip/only/todo/fixme, x/f prefixes; JUnit Disabled/Assume; Go Skip, Short(); Rust ignore; RSpec, PHPUnit, C#, Swift skips; --deselect/-k not, collect_ignore, jest testPathIgnorePatterns. Runs: commit, agent write, turn's end; only additions judged. Friction: computed names evade it. Waiver: 'chock: allow test-skip' same line; agent: only if in HEAD.

## What it solves

A quieter way to green a suite than deleting a test is to skip it, or to focus one test with `.only` so the rest never run. protect-test-integrity counts assertions and cannot see that. This gate refuses a newly added skip or focus marker in a test file, at commit and while the agent writes, and ignores skips already committed.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> Test skip, focus marker (.only) or test-hiding runner option added. Fix the test or the code instead of skipping, focusing or deselecting it. A person may waive a reviewed skip with 'chock: allow test-skip' on the line and commit from their own shell; in the agent a waiver counts only for a line already committed in HEAD, so an agent asks the person rather than writing the pragma itself.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/block-test-skips/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add block-test-skips
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/block-test-skips  <your-repo>/.agents/policies/block-test-skips
cd <your-repo> && chock sync --repo .
```

## Customising it

The skip markers and the test-path regex are constants at the top of `implementations/block-test-skips-gate.py`; add a framework's marker there. A reviewed skip is waived by a person with `chock: allow test-skip` on the line, honoured at commit only in chock 0.13.0, never in the agent.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-test-skips
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/block-test-skips/`](../../base/block-test-skips/) · [all policies](../README.md)
