# Block Hook Bypass In Files

`block-hook-bypass-in-files` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: advise`) |
| **Mechanism** | warn-only `content_regex` gate |
| **Reaches** | `advisory` — the gate runs and prints its findings; it never refuses |
| **Compiles to** | `git-hook`, `ci-gate`, `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 28 total, 28 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Friction, not a security boundary: flags lines added to hook launchers and scripts that switch git hooks off -- the hook-skip option on a git commit/push/merge/am/rebase/pull, core.hooksPath set by git config or GIT_CONFIG_*, the husky, lefthook and pre-commit off-switch variables, a pre-commit, lefthook or husky (v8 and older) uninstall -- in .husky/, .githooks/, lefthook, package.json, Makefile, justfile, .envrc, *.sh. Warns only (observe). Misses: split lines, -n.

## What it solves

block-no-verify refuses an agent's command that skips git hooks, but not the same skip written into a file that runs later. A hook-skip option in a release script, core.hooksPath set by a package.json prepare script, HUSKY=0 or SKIP= in a Makefile, or an uninstall in a setup script switches the hooks off for everyone who runs it. This gate reads the lines a change adds to hook launchers, scripts and build files, and flags each such line. It warns while its false-positive rate is measured, then blocks.

## How it works

A `content_regex` gate runs on `commit` and `tool_use` and only warns: its action is `warn`, so it prints its findings and never refuses. It does not enforce anything, so the policy counts as advisory.

On a finding it prints:

> This line switches git hooks off for everyone who runs this file (a hook-skip option on a git command, a new hooks path (core.hooksPath), a hook manager's off-switch variable such as HUSKY set to zero, or an uninstall). Fix the failing hook instead. A person who has reviewed it may keep it with 'pragma: allowlist hook-bypass' on the same line (a person's commit honours it; in the agent only a line already in HEAD counts). An agent asks a person; it never writes the pragma.

## Which primitive it becomes

A **warn-only gate**. `recompile` writes it under `.chock/compiled/block-hook-bypass-in-files/` for each surface its `on` names (the git hook, CI, the agent's write path) beside the ambient rule. It runs and prints, but its exit never refuses a commit or a write.

## Installing it

```bash
chock add block-hook-bypass-in-files
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/block-hook-bypass-in-files  <your-repo>/.agents/policies/block-hook-bypass-in-files
cd <your-repo> && chock sync --repo .
```

## Customising it

The scoped files are `applies_to.paths` in the manifest and the pattern is `content_pattern`; widen either there. A reviewed bypass is kept by a person with `pragma: allowlist hook-bypass` on the line (a JSON file such as package.json cannot carry it). In the agent a waiver counts only for a line already in HEAD.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-hook-bypass-in-files
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/block-hook-bypass-in-files/`](../../base/block-hook-bypass-in-files/) · [all policies](../README.md)
