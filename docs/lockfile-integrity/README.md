# Lockfile Integrity

`lockfile-integrity` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` |
| **On Claude Code** | blocks — blocks on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 65 total, 65 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Script gate (commit, agent write, CI) over npm, yarn, pnpm, bun, poetry, uv, Pipfile, Cargo, go.sum, Gemfile, composer and NuGet locks. Blocks: source off the registry list or not https, missing hash, hash changed for a locked version, unpinned git source, unreadable lock. Asks: SHA-1-only hash, transitive install script, lock or manifest moved alone, go.sum lines removed, lock ignored or deleted. Judges what a change adds. Friction, not a security boundary.

## What it solves

A lockfile is thousands of generated lines nobody reads, which makes it the quiet place to point one package at another server, drop its hash or re-hash a version already locked. This gate reads the lockfile formats of twelve package managers and refuses those changes, at commit and while the agent writes, judging only what the change adds.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> A lockfile change points a package somewhere other than its registry, drops or replaces its hash, leaves a git source unpinned, or moves the lock without the manifest that explains it. Regenerate the lock with the package manager from the registry (npm install, yarn, pnpm install, poetry lock, uv lock, cargo update -p, go mod tidy, bundle lock, composer update) and commit it with the manifest change. A person who has reviewed a private registry host adds it to .chock/registry-allowlist.txt and commits that first; an agent asks the person and never edits that file or the lock by hand.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/lockfile-integrity/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add lockfile-integrity
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/lockfile-integrity  <your-repo>/.agents/policies/lockfile-integrity
cd <your-repo> && chock sync --repo .
```

## Customising it

A reviewed private registry or mirror host goes in `.chock/registry-allowlist.txt` (one host or `*.domain` per line), committed before the lock that uses it; only the committed file counts. The default registries per ecosystem are `DEFAULT_HOSTS` in `implementations/lockscan/sources.py`. Start with `rollout: observe` and read the gate log before enforcing.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals lockfile-integrity
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/lockfile-integrity/`](../../base/lockfile-integrity/) · [all policies](../README.md)
