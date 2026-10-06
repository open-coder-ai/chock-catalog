# Token Efficiency Rule

`token-efficiency` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | advisory — advisory only: skill text, nothing stops a violation |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | guard script `token-efficiency-gate.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 7 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: large command output, broad searches, re-reading unchanged files, front-loading references. avoid: wasting context window on low-signal content.

## What it solves

Context spent on output nobody reads: full command dumps, broad searches, re-reading files that have not changed, reference material loaded before it is needed.

## How it works

A guard script, `implementations/token-efficiency-gate.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
cap(tool_output): 4000_bytes; cap(search_results): top_3; cap(retry_loops): max_3_iterations
prefer: targeted_reads|structured_output|on_demand_refs; never: re-read(unchanged_file)|load_all_upfront
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/token-efficiency/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add token-efficiency
chock sync .
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
