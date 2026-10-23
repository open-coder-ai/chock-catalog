# Protect Main Branch

`protect-main-branch` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` |
| **On Claude Code** | advisory — text only in a plugin. Nothing in the plugin stops a violation. The plugin does not carry the enforcement the manifest declares |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | forbidden_ref gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 4 total, 4 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Keeps agents off main and master: a git hook reads the current branch at commit time and parses the refs being pushed at push time. The hook refuses a violation only where it is installed. As skill text alone this is advice, and nothing stops one.

## What it solves

Work landing on the default branch without review. Not because the commit is wrong, but because nobody saw it -- and once it is pushed, the fix costs more than the review would have.

## How it works

A declarative `forbidden_ref` gate, evaluated on `commit` and `push`, action `block`.

Parameters, from `manifest.yaml`:

- `config_key`
- `refs`

On a match it prints:

> Direct commits/pushes to a protected branch ({refs}) are blocked. Create a feature branch and open a pull request.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/protect-main-branch/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add protect-main-branch
chock sync .
```

Or [Open in the chock.sh builder](https://chock.sh/coding/builder/#s=eyJzY2hlbWEiOjIsImNsaWVudCI6ImNsYXVkZS1jb2RlIiwiYnVuZGxlIjp7InZlcnNpb24iOiIxLjAuMCJ9LCJjYXRhbG9nIjp7InNvdXJjZSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9vcGVuLWNvZGVyLWFpL2Nob2NrLWNhdGFsb2ciLCJyZWYiOiJlOGQwZmQxZDVjN2M4NGY1MDczNWFmNGE5Yjk3MzBjZDJmYjdmYWExIn0sInBvbGljaWVzIjpbeyJmcm9tIjoiY2F0YWxvZyIsImlkIjoicHJvdGVjdC1tYWluLWJyYW5jaCIsInZlcnNpb24iOiIwLjAuNCIsInNoYTI1NiI6IjY2MTNiNDRlYTA2YWZmYWUwMTgyNTA2NjAzMzFiMGZiMjU0NzEwZGM5ZjllNzJjZDVlODE4MjZlMDdjZTVhMDUifV19): this policy preselected for Claude Code, one merged plugin, installed with `chock install --selection '<code>' --apply`.

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/protect-main-branch  <your-repo>/.agents/policies/protect-main-branch
cd <your-repo> && chock sync --repo .
```

## Customising it

`params.refs` is the branch list and takes fnmatch patterns, so `release/*` works alongside `main`. `params.config_key` names the git config key an adopter can set to override the list per clone.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals protect-main-branch
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/protect-main-branch/`](../../base/protect-main-branch/) · [all policies](../README.md)
