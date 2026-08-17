# Verify Dependency Exists

`verify-dependency-exists` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | dependency_allowlist gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 5 total, 5 executable |
| **Enabled by default** | no — opt in |

<!-- generated:end -->

## What it is about

Block hallucinated or unknown dependencies before they enter the repo. Watches requirements.txt, pyproject.toml, package.json, and go.mod, and blocks any newly added dependency not present in the allowlist file. Opt-in: disabled by default because it requires a curated allowlist. Enable with `chock enable verify-dependency-exists` after populating .chock/dependency-allowlist.txt.

## What it solves

Package hallucination, and the supply-chain attack built on it. Agents confidently suggest packages that do not exist; an attacker who registers that name gets code execution in every repo that installs it.

## How it works

A declarative `dependency_allowlist` gate, evaluated on `commit`, action `block`.

Parameters, from `manifest.yaml`:

- `allowlist_file`
- `manifests`

On a match it prints:

> Unknown dependency blocked. Verify the package exists in the official registry, then add it to .chock/dependency-allowlist.txt to allow it.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/verify-dependency-exists/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add verify-dependency-exists
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/verify-dependency-exists  <your-repo>/.agents/policies/verify-dependency-exists
cd <your-repo> && chock sync --repo .
```

This one ships disabled. Enable it with `chock enable verify-dependency-exists` once its prerequisites are in place.

## Customising it

The allowlist is the policy. `params.manifests` sets which files are watched, and `params.allowlist_file` where the approved names live. This one ships disabled because an empty allowlist blocks every dependency -- populate it first, then enable.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals verify-dependency-exists
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/verify-dependency-exists/`](../../base/verify-dependency-exists/) · [all policies](../README.md)
