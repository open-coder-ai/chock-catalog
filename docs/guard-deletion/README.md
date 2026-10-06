# Guard Deletion and Mitigation Removal

`guard-deletion` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` |
| **On Claude Code** | blocks — blocks on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 23 total, 22 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: a change that removes a check, auth decorator, middleware registration, sanitizer call or path check with none of its kind in the same hunk (ask), or removes a hardening flag, security header, cookie attribute, TLS check or row-level security, or swaps one of those or a narrow file mode for a weakened form (block). Hunk-local: misses a guard moved across hunks or files, one neutralised in place, added insecure settings, a deletion-only commit.

## What it solves

A review catches the deleted check that nothing replaced -- the bound compare, the auth decorator, the escape call, the hardening flag -- because it reads the diff. A file-level scanner cannot: the line that mattered is gone, so there is nothing left to match. This gate reads the removed lines against the lines added beside them in the same hunk. A removed check with none of its kind beside it asks a person; a removed or weakened mitigation (hardening flag, security header, cookie attribute, TLS verification, row-level security, file mode) is refused. Several of those weakenings, written as added lines on their own, are other policies' business (agentic-code-security refuses TLS verification off in agent code, java-security the Java cookie and header forms); this one fires on the removal, so it adds the view they cannot have.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> guard-deletion: this change removes a check or a security mitigation (the refusal above names the file, line and family). Keep it, or move its replacement into the same hunk. A removed guard asks a person; a removed or weakened mitigation (hardening flag, security header, cookie attribute, TLS verification, row-level security, file mode) is refused. A person who has reviewed the removal waives one line with 'pragma: allowlist guard-removal' or 'pragma: allowlist mitigation-removal'; an agent's own pragma is itself a finding, and counts only on a removed line that is already committed.

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

The check shapes and the mitigation families are regexes in `implementations/data/shapes.json`, and the judged paths in `implementations/data/scope.json` (EP12 tables, dated and schema-checked); add a family there with a bad and a good eval. A person waives a reviewed hunk with `pragma: allowlist guard-removal` or `pragma: allowlist mitigation-removal` on a line in it; an agent's pragma counts only on a removed line HEAD already holds, and one an agent adds to a guard or mitigation line is a finding. Known limits, each a miss rather than a refusal: it is hunk-local, so a guard moved across hunks or files is not followed; a guard neutralised in place (`assert True`, a swapped middleware) is not seen; an insecure setting added with nothing removed is left to other policies; a commit whose only change is deleted files never reaches a script gate; a strong-to-plain stack protector downgrade is not seen; authorization wired by dependency injection or a config chain (FastAPI `Depends`, Spring `authorizeRequests`) is not read; files over 4000 lines are compared by line counts, not hunks; CI without a base ref or a push event file reads only the tip commit; a replacement line that only names a guard or header in a string (a log message) counts as keeping it; a file mode is judged on a swap to a weaker one, so a bare removed `chmod` and `umask` are not seen; CR-only line endings read as one line; a binary file with an unlisted suffix is read as text and asks; the path scope skips root `test`, `fixtures`, `evals`, `docs` and any `tests`, `vendor`, `node_modules` directory, and an agent's move of a file into a judged path from outside it asks.

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
