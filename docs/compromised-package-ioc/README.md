# Compromised Package IOC

`compromised-package-ioc` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 43 total, 43 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Blocks adding a known-malicious package version (npm, PyPI, crates, Go, RubyGems, Packagist manifests and lockfiles), a re-pointed action ref, or an IOC file name, from a dated, sourced list (data/ioc.json, CI fails 120 days after as_of). Runs: commit, agent write, turn's end; only additions judged. Exact versions only: a range is not resolved. A snapshot, not a feed; friction, not a boundary. Adopt under rollout observe.

## What it solves

A dependency bump can pull a release that was published by a stolen token and is known to be malicious -- chalk and debug in September 2025, nx, axios 1.14.1, litellm 1.82.8, the keyv worm. A registry unpublishes it within hours, but a lockfile written in that window keeps it, and an agent copying a version from an issue or a stale lockfile writes it back. This gate refuses the listed package versions, re-pointed action refs and IOC file names as they are added.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> A known-malicious package version, compromised action ref or IOC file name was added. Use a release outside the list (the cited advisory names the fixed one) or drop the dependency, pin the action to a reviewed commit, or delete the file. The list changes only in a reviewed pull request to this policy's data/ioc.json; there is no in-line waiver.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/compromised-package-ioc/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add compromised-package-ioc
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/compromised-package-ioc  <your-repo>/.agents/policies/compromised-package-ioc
cd <your-repo> && chock sync --repo .
```

## Customising it

The list is `implementations/data/ioc.json`: each row names its ecosystem, package, exact versions (or `*`), incident, date and a cited source. A person refreshes it in a reviewed pull request from the weekly threat digest; CI fails 120 days after `as_of`. There is no in-line waiver. Adopt it under `rollout: observe` first.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals compromised-package-ioc
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/compromised-package-ioc/`](../../base/compromised-package-ioc/) · [all policies](../README.md)
