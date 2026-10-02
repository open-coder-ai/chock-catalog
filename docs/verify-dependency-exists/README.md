# Dependency Allowlist

`verify-dependency-exists` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 52 total, 52 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Allowlist gate for new dependencies; no registry lookup is made. Reads Python, Node, Rust, Ruby, PHP, JVM, .NET, Go, Elixir, Dart and Swift manifests (read, never run); blocks an added name missing from .chock/dependency-allowlist.txt and asks on a lockfile-only addition. Not read: computed lists, sources, some pattern-read forms (see docs), versions. Opt-in: seed the allowlist, run in rollout observe, then `chock enable verify-dependency-exists`. Runs: commit, agent write, turn's end.

## What it solves

Package hallucination, and the supply-chain attack built on it. Agents confidently suggest packages that do not exist; an attacker who registers that name gets code execution in every repo that installs it.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> Unknown dependency blocked: it is not in .chock/dependency-allowlist.txt. This gate checks the allowlist only and makes no registry lookup, so confirm the package exists in its official registry and is the intended one first. If you are an agent, ask a person to add the name; do not edit that file yourself (protect-agent-config). If you are a person, add the name to the file.

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

## Customising it

The allowlist is the policy: `.chock/dependency-allowlist.txt`, one name per line, `#` for notes, matched after the ecosystem's own normalisation (`Foo_Bar` is `foo-bar`; a Cargo `-` is a `_`). It ships disabled because an empty allowlist blocks every dependency. Seed it from what the repository already depends on -- `python .agents/policies/verify-dependency-exists/implementations/dependency-manifests.py --seed > .chock/dependency-allowlist.txt` -- review it, then set `rollout: observe` in `.chock/config.yaml`, enable the policy and read what it would have refused before promoting it. A new name in a manifest blocks; a name that only a lockfile adds (a transitive dependency) asks. Reads Python, Node, Rust, Ruby, PHP, JVM, .NET, Go, Elixir, Dart and Swift manifests by parsing them (Ruby, Elixir, Gradle and Swift by pattern), never running them. Limits: the allowlist is one flat list, so a name listed for one ecosystem also passes in another, and Go module paths and Maven coordinates are compared as written, so their allowlist line must match the case; tomllib reads TOML 1.0, so a Cargo or pyproject file using TOML 1.1 syntax cannot be parsed and asks; forms not read include Gradle coordinates built from variables, Pipfile custom categories, pyproject tool tables beyond the ones named above (pixi, pdm overrides), NuGet Sdk attributes and dotnet tool manifests, and Maven annotation-processor paths; local path and workspace dependencies are not reported; a lockfile is asked about only when no manifest of its ecosystem changed beside it, in its folder or below (with one, the manifest names are the judgement and the lock's transitive names are what installing them brings), and when one run holds both an unlisted manifest name and a lockfile-only addition elsewhere the whole run blocks; a Maven `${...}` placeholder is judged as the literal text; no comment is stripped in Gradle, Swift or mix.exs (a `**/*.class` glob would open a fake block comment), so a commented-out dependency is reported; mix.exs is read as text, so a tuple whose version is a variable or module attribute is missed; also not read: Gradle `"implementation"(...)` and `id(...).version(...)` forms, an npm `jsr:` alias target, pyproject cibuildwheel and flit tables, .mvn/extensions.xml, differently named POMs (pom-ci.xml) and project types such as .nuproj and .sqlproj, and pnpm-workspace.yaml catalogs. Also: it checks that a name is listed, never that it exists in a registry, and never a dependency's version or source (a listed name pointed at another git URL passes); a list built by code is not read (a setup.py list built from a variable, `+` or `**kw`; a multi-line `gem(` call; a Swift raw-string or variable URL; Gradle map notation split anywhere but after a comma, `add("implementation", ...)` and settings-catalog `library(...)` calls); an npm name pointing at a git or URL spec, and a lockfile entry whose real name differs from its key, report only the key; an `-r` include is judged only when the same change holds the included file; a file that cannot be parsed asks; an XML manifest that declares a DOCTYPE or ENTITY, and one too large or too deeply nested to read, is refused as a finding keyed by a digest of its text.

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
