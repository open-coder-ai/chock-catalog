# Guard Deletion and Mitigation Removal

`guard-deletion` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 18 total, 17 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: a change that removes a check, auth decorator, middleware registration, sanitizer call or path check with none like it in the same hunk (ask), or removes or weakens a hardening flag, security header, cookie attribute, TLS verification, row-level security or file mode (block). Hunk-local, line-level; misses a guard moved to another hunk or file, a semantic replacement, a deletion-only commit, and tests, docs and vendored code (not judged).

## What it solves

A review catches the deleted check that nothing replaced -- the bound compare, the auth decorator, the escape call, the hardening flag -- because it reads the diff. A file-level scanner cannot: the line that mattered is gone, so there is nothing left to match. This gate reads the removed lines against the lines added beside them in the same hunk. A removed check with none of its kind beside it asks a person; a removed or weakened mitigation (hardening flag, security header, cookie attribute, TLS verification, row-level security, file mode) is refused. Several of those weakenings, written as added lines on their own, are other policies' business (agentic-code-security refuses TLS verification off in agent code, java-security the Java cookie and header forms); this one fires on the removal, so it adds the view they cannot have.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> guard-deletion: this change removes a check or a security mitigation (the refusal above names the file, line and family). Keep it, or move its replacement into the same hunk. A removed guard asks a person; a removed or weakened mitigation (hardening flag, security header, cookie attribute, TLS verification, row-level security, file mode) is refused. A person who has reviewed the removal waives one line with 'pragma: allowlist guard-removal' or 'pragma: allowlist mitigation-removal'; an agent's own pragma counts only once that exact line is committed.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/guard-deletion/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add guard-deletion
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/guard-deletion  <your-repo>/.agents/policies/guard-deletion
cd <your-repo> && chock sync --repo .
```

## Customising it

The check shapes and the mitigation families are regexes in `implementations/data/shapes.json`, and the judged paths in `implementations/data/scope.json` (EP12 tables, dated and schema-checked); add a family there with a bad and a good eval. A person waives a reviewed hunk with `pragma: allowlist guard-removal` or `pragma: allowlist mitigation-removal` on a line in it; an agent's pragma counts only on a removed line HEAD already holds. Hunk-local by design -- it does not follow a guard moved across hunks or files, and it does not read a commit that only deletes files.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals guard-deletion
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/guard-deletion/`](../../base/guard-deletion/) · [all policies](../README.md)
