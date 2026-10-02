# Registry Config

`registry-config` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 54 total, 54 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Refuses package-manager config that redirects installs or weakens them: literal tokens, http or unlisted registry hosts (parsed, so lookalike and userinfo spellings fail), TLS or checksum checks off, install scripts on (npm, Yarn, pnpm, Bun, pip, uv, Poetry, conda, Go, Cargo, NuGet, Maven, Bundler, Composer, Hex, Dependabot); asks on extra indexes, replaces, no cooldown. Added only. Ship observe first. Friction, not a boundary.

## What it solves

One line in a package manager's config decides where every dependency comes from and how it is checked: a
registry or index URL, a source replacement, a TLS or checksum switch, a setting that lets dependencies run
install scripts, a token written into the file. An agent fixing an install error can change any of them, and
the change looks like configuration, not code. This gate reads those files for npm, Yarn, pnpm, Bun, pip, uv,
Poetry, PDM, pipenv, conda, Go, Cargo, NuGet, Maven, Bundler, Composer, Hex, CocoaPods, SwiftPM, Dependabot and
Renovate, and refuses what the change adds: clear-text or unlisted registry hosts (URLs are parsed and hosts
normalised, so a lookalike or userinfo spelling does not pass for an allowed host), verification turned off,
install scripts turned on and literal credentials. Extra indexes, replaces and redirects, and a missing release
cooldown ask a person instead. Settings already committed stay quiet.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> This change points a package manager at an unapproved or clear-text registry, writes a credential into its config, turns TLS or checksum verification off, lets dependencies run install scripts, or redirects where packages come from. Use https registries on the default hosts, read tokens from environment references and keep verification on. An internal mirror is added by a person to .chock/registry-hosts.txt in a reviewed commit. A finding that only asks (extra index, replace, missing cooldown) is kept by a person committing from their own shell with CHOCK_ALLOW=registry-config; an agent asks the person and never sets it.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/registry-config/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add registry-config
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/registry-config  <your-repo>/.agents/policies/registry-config
cd <your-repo> && chock sync --repo .
```

## Customising it

Ship it under `rollout: observe` in .chock/config.yaml first, read the gate log, and move to enforce once the
findings it records are the ones you want refused. An internal mirror is allowed by a person adding its host
(or `*.` and a domain) to `.chock/registry-hosts.txt` in a reviewed commit; the gate reads that file from HEAD
only, and a change to it asks. A finding that asks (an extra index, a replace, a missing cooldown) is kept by a
person committing from their own shell with CHOCK_ALLOW=registry-config for that one commit. To stop judging
the policy, list it under policies.disabled.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals registry-config
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/registry-config/`](../../base/registry-config/) · [all policies](../README.md)
