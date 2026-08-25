# Git Safety Rule

`git-safety` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 4 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: force push, hard reset, destructive branch delete, hook bypass, direct main commits. avoid: rewriting remote history, discarding uncommitted work, skipping pre-commit checks. Install block-destructive-commands, block-no-verify and protect-main-branch to enforce the hard controls deterministically; this rule is the advisory layer over them plus atomic-commit and diff-size guidance no gate can decide.

## What it solves

Git operations that lose work rather than record it: force pushes over shared history, hard resets across uncommitted changes, branch deletions, commits landing straight on the default branch.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```
enforced_when_installed(block-destructive-commands): force_push|reset_hard|rm_-rf; enforced_when_installed(block-no-verify): --no-verify|skip_hooks; enforced_when_installed(protect-main-branch): direct_commit|push(main|master)
advisory: avoid(branch_-D) without_approval; prefer(feature_branch|atomic_commits); ask_if(diff > 500_lines)
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/git-safety/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add git-safety
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/git-safety  <your-repo>/.agents/policies/git-safety
cd <your-repo> && chock sync --repo .
```

## Customising it

The `diff > 500_lines` threshold and the protected branch names are the two knobs that matter. Both are conventions, not findings, so set them to your team's.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals git-safety
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/git-safety/`](../../base/git-safety/) · [all policies](../README.md)
