# Limit Diff Size Rule

`limit-diff-size` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: block`) |
| **Mechanism** | commit-time guard script `limit-diff-size-pre-commit.py` |
| **Reaches** | `enforced-at-commit` — the script exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ambient-rule` |
| **Eval cases** | 8 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: staging a large change, committing more than a reviewer can read at once. avoid: one commit carrying hundreds of hand-written lines; lockfile and generated churn is not counted.

## What it solves

A commit of thousands of hand-written lines cannot be reviewed, and an agent will produce one unless something stops it. git-safety only advised asking. This script counts the staged added plus removed lines, leaves out lockfiles, vendored and generated paths and binaries, and refuses above the limit with the largest files named.

## How it works

A guard script, `implementations/limit-diff-size-pre-commit.py`, run by the git hook at every commit with no arguments. It reads the staged revision of each file from git and exits non-zero to refuse the commit.

The rule text ships alongside, so an agent reading its context knows the constraint before it stages the change rather than only after being refused:

```text
at(commit): refuse if sum(added+removed, staged) > CHOCK_DIFF_LIMIT (default 500); excluded: lockfiles|vendor/|node_modules/|dist/|build/|*.min.js|*.min.css|*.snap|.chock/|binary
on(refused): split into atomic commits (git add -p); override: CHOCK_ALLOW_LARGE_DIFF=1 set by a human only; agent: never(set_override), ask(human)
```

## Which primitive it becomes

A **commit-time guard script**. `recompile` registers `implementations/limit-diff-size-pre-commit.py` under `.git/hooks/pre-commit.d/`, and the hook runs it at every commit (a commit-msg script gets git's message file as its one argument, any other none). The script reads the change from git itself and exits non-zero to refuse; the rule text compiles to `ambient-rule` beside it, so the agent knows the constraint before the commit is refused.

## Installing it

```bash
chock add limit-diff-size
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/limit-diff-size  <your-repo>/.agents/policies/limit-diff-size
cd <your-repo> && chock sync --repo .
```

## Customising it

Set `CHOCK_DIFF_LIMIT` to change the 500-line default. The exclusion lists are constants in `implementations/limit-diff-size-pre-commit.py`. A person may set `CHOCK_ALLOW_LARGE_DIFF=1` for one commit; it is ignored when `CHOCK_AGENT_COMMIT` is set, and an agent asks rather than setting it.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals limit-diff-size
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/limit-diff-size/`](../../base/limit-diff-size/) · [all policies](../README.md)
