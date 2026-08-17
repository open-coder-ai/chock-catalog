# Token Efficiency Rule

`token-efficiency` · rule · advises

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

trigger: large command output, broad searches, re-reading unchanged files, front-loading references. avoid: wasting context window on low-signal content.

## What it solves

Context spent on output nobody reads: full command dumps, broad searches, re-reading files that have not changed, reference material loaded before it is needed.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```
cap(tool_output): 4000_bytes; cap(search_results): top_3; cap(retry_loops): max_3_iterations
prefer: targeted_reads|structured_output|on_demand_refs; never: re-read(unchanged_file)|load_all_upfront
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/token-efficiency/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add token-efficiency
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/token-efficiency  <your-repo>/.agents/policies/token-efficiency
cd <your-repo> && chock sync --repo .
```

## Customising it

Every number here is a budget, not a finding. Raise the output cap for work with large legitimate output; lower it when context pressure is the binding constraint.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals token-efficiency
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/token-efficiency/`](../../base/token-efficiency/) · [all policies](../README.md)
