# Hardening Flags

`hardening-flags` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` |
| **On Claude Code** | blocks — blocks on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 36 total, 36 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Blocks added settings that weaken compiler, linker, Rust or kernel hardening, in CMake, Make, meson, configure.ac, Cargo, build.rs, Go release scripts, Dockerfiles and kernel config: no stack protector, FORTIFY_SOURCE off, non-PIE, execstack, norelro, CET off, kernel KASLR/RWX off. Asks on Rust release overflow-checks off, /dev/mem. Not MSVC, sysctl or container settings; misses environment flags, generated files. Runs: commit, agent write, turn's end, CI. Waiver: 'pragma: allowlist hardening-flag'.

## What it solves

A change that adds -fno-stack-protector, -D_FORTIFY_SOURCE=0, -no-pie, -z execstack, or a kernel config that turns KASLR or the stack protector off silently removes a mitigation a compiler or kernel gives by default, and no test notices. This gate refuses those added settings in CMake, Make, meson, configure.ac, Cargo, build.rs, Go release scripts, Dockerfiles and kernel config, and asks about Rust release overflow-checks off and /dev/mem. It judges only what a change adds and is advisory about everything it cannot see (environment-set flags, generated build files, toolchain defaults).

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> A build or kernel setting that weakens a hardening default was added (stack protector, FORTIFY_SOURCE, PIE, RELRO, non-executable stack, CET, kernel KASLR or RWX). Keep the default or enable the protection. A person may waive a reviewed setting with 'pragma: allowlist hardening-flag' in a comment on the same line and commit from their own shell; in the agent a waiver counts only for a line already committed in HEAD, so an agent asks the person rather than writing the pragma itself.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/hardening-flags/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add hardening-flags
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/hardening-flags  <your-repo>/.agents/policies/hardening-flags
cd <your-repo> && chock sync --repo .
```

## Customising it

The settings are rows in `implementations/data/flags.json` (id, tier block or ask, languages, regex, what it weakens); add a row and a case, bump `as_of`. A reviewed exception is waived by a person with `pragma: allowlist hardening-flag` in a comment on the same line (`#`, or `//` in build.rs), honoured at commit and CI, and in the agent only for a line already in HEAD. Ship it with rollout `observe` first.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals hardening-flags
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/hardening-flags/`](../../base/hardening-flags/) · [all policies](../README.md)
