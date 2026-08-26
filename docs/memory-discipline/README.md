# Memory Discipline Rule

`memory-discipline` · rule · advises

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

trigger: repeated mistakes, rediscovered patterns, preferences, non-derivable facts. avoid: persisting file contents, git history, or task intermediates as memory.

## What it solves

Memory that fills with things the repo already records -- file contents, git history, task scratch -- until the genuinely non-derivable facts are buried in it.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
persist: decisions|preferences|non_derivable_facts; never_persist: file_contents|git_history|task_intermediates
extract(atomic_facts); consolidate(near_duplicate_facts); decay(stale); verify(memory) before_recommend
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/memory-discipline/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add memory-discipline
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/memory-discipline  <your-repo>/.agents/policies/memory-discipline
cd <your-repo> && chock sync --repo .
```

## Customising it

Consolidation of near-duplicate facts and the decay policy are the tunable parts. What should not move is `verify(memory) before_recommend`: a memory that names a file or flag is a claim about a repo that has changed since.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals memory-discipline
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/memory-discipline/`](../../base/memory-discipline/) · [all policies](../README.md)
