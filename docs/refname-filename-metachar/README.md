# Refname Filename Metachar

`refname-filename-metachar` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 40 total, 40 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Refuses names a shell, CI step or git can misread. Paths a change adds or renames into (commit, agent writes), and branches and tags pushed (pre-push), with command substitution, an IFS expansion, a backtick, ; & | < >, a control or bidi character, a base64-decode shape, a leading dash or trailing space or dot in a segment, or a '..' segment; a ref also with a full commit id's shape. A guard refuses git and file commands creating such names. No waiver. Friction, not a boundary.

## What it solves

Names a shell, CI step or git can misread. Paths a change adds or renames into, and branches and tags pushed, can carry command substitution, an IFS expansion, a backtick, a shell operator, a control or bidi character, a base64-decode shape, a leading dash or a trailing space or dot in a segment, or a '..' segment; a ref can also have a full commit id's shape.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> A path this change adds or renames into has a name a shell, a CI step or git can misread: command substitution, an IFS expansion, a backtick, a shell operator, a control or bidi character, a base64-decode shape, a segment starting with '-' or ending in a space or '.', or a '..' segment. Rename it with letters, digits, spaces inside, '.', '_', '-' and '/'. No waiver: if the name is truly required, a person creates it from their own shell.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/refname-filename-metachar/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add refname-filename-metachar
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/refname-filename-metachar  <your-repo>/.agents/policies/refname-filename-metachar
cd <your-repo> && chock sync --repo .
```

## Customising it

No waiver: if a name is truly required, a person creates it from their own shell. This is friction, not a boundary.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals refname-filename-metachar
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/refname-filename-metachar/`](../../base/refname-filename-metachar/) · [all policies](../README.md)
