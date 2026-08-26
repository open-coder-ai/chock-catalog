# Context Hygiene Rule

`context-hygiene` · rule · advises

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

trigger: context bloat, stale observations, resolved content inlined, noisy exploration. avoid: context rot and lost-in-the-middle failures.

## What it solves

Long sessions that get worse rather than better. Resolved content stays inlined, stale observations accumulate, and the instruction that mattered ends up in the middle of a window where models attend to it least.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
replace(resolved_content): path_ref_only; delegate(noisy_exploration): subagent; prune(stale > 3_turns)
on_context_growth: summarize(old_observations); keep(decisions+outcomes); discard(superseded_content)
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/context-hygiene/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add context-hygiene
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/context-hygiene  <your-repo>/.agents/policies/context-hygiene
cd <your-repo> && chock sync --repo .
```

## Customising it

The `> 3_turns` pruning threshold is a guess, not a measurement. Raise it for work that revisits the same files and lower it for broad exploration.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals context-hygiene
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/context-hygiene/`](../../base/context-hygiene/) · [all policies](../README.md)
