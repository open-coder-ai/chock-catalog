# Agent Discipline Rule

`agent-discipline` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 3 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: edits without reading, unverified completion claims, weakened tests, dead code. avoid: skipping verification, deleting assertions, leaving unused code.

## What it solves

Agents that edit a file they never read, declare work finished without running it, and "fix" a failing test by deleting the assertion that caught the bug. Each is individually small and each destroys the evidence that would have revealed it.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
before(edit): read(file); before(done): verify(flow) + tests_pass + lint_clean
never(fix_test_by): delete_assertion|weaken_check|skip; on_find(dead_code|unused): delete
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/agent-discipline/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add agent-discipline
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/agent-discipline  <your-repo>/.agents/policies/agent-discipline
cd <your-repo> && chock sync --repo .
```

## Customising it

The verification bar is the part worth tuning. If your project has no lint step, drop `lint_clean` rather than leaving a rule that cannot be satisfied -- a rule an agent routinely cannot meet teaches it that rules are advisory in general.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals agent-discipline
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/agent-discipline/`](../../base/agent-discipline/) · [all policies](../README.md)
