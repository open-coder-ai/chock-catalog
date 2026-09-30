# Guard Memory Writes

`guard-memory-writes` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 25 total, 24 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Refuses agent-memory writes holding what memory must never hold: pasted git history (diff, hunk, commit, index lines), a fenced code block over 20 lines, a duplicate line, or a secret (scan-secrets' pattern). Judges only memory files (MEMORY.md at any depth, CLAUDE.local.md, .claude/memory/**, memory/**/*.md; at agent tool-use also ~/.claude/projects/*/memory/**, ~/.claude/CLAUDE.md, /memories/**) and only what the change adds. No waiver. Structural checks only.

## What it solves

Agent memory rots when it fills with pasted diffs, whole code listings, repeated lines and, worst, credentials that then travel with the repository. This script judges only memory files and only what a change adds, and refuses those four things with a path and line for each.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> Memory write refused: it pastes git history, a code block over 20 lines, a duplicate line, or a secret. Store the non-derivable fact in one short line; link to the commit or file instead of pasting it. Rotate any secret that was written.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/guard-memory-writes/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add guard-memory-writes
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/guard-memory-writes  <your-repo>/.agents/policies/guard-memory-writes
cd <your-repo> && chock sync --repo .
```

## Customising it

The memory paths, the fenced-block limit and the git-history patterns are constants in `implementations/guard-memory-writes-gate.py`; the secret pattern is scan-secrets' verbatim, so update both together. There is no waiver.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals guard-memory-writes
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/guard-memory-writes/`](../../base/guard-memory-writes/) · [all policies](../README.md)
