# Flag Package Lifecycle Scripts

`package-lifecycle-scripts` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | blocks — blocks on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 28 total, 28 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Blocks fetch-exec class hooks and asks about other new ones when a change adds or edits code that runs at install or build time: npm install/prepare/pack scripts, gypfile without native sources, bin shadowing, unpinned git/URL deps; setup.py cmdclass and import-time calls, .pth imports, conftest, pyproject build hooks; build.rs and build-deps; go:generate; MSBuild Exec; gemspec, extconf, Podfile, Composer, Maven, Gradle exec. Judges file text, not what a hook runs. Friction, not a security boundary.

## What it solves

Install-time and build-time hooks are how recent supply-chain worms spread (Shai-Hulud's preinstall, Phantom Gyp's binding.gyp, setup.py command overrides). A hook an agent adds runs on every machine that installs the package, before anyone reads it. This gate reads package manifests and build files across npm, Python, Rust, Go, .NET, Ruby, PHP and the JVM, and reports each install- or build-time hook a change adds or edits, and each git or URL dependency without a commit pin. It warns while its false-positive rate is measured; the script already sorts hooks that download, decode or evaluate code (to block) from other new hooks (to ask).

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> A change adds or edits code that runs when a package is installed or built (an npm lifecycle script, setup.py command override, build.rs, MSBuild Exec, gemspec extension and the like), or a git or URL dependency with no commit pin. Whoever controls that code or URL runs it on every machine that installs the package. Keep install and build steps offline and explicit: download to a file, verify a pinned checksum, run it as a separate reviewed step, and pin git dependencies to a 40-hex commit. A person who has reviewed the change approves the ask; there is no waiver yet.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/package-lifecycle-scripts/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add package-lifecycle-scripts
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/package-lifecycle-scripts  <your-repo>/.agents/policies/package-lifecycle-scripts
cd <your-repo> && chock sync --repo .
```

## Customising it

The file names and detectors live in `implementations/lifecycle/` (`dispatch.py` maps a file name to its detector; `signals.py` holds the download, decode and inline-code patterns; `npm.py` holds the allowed husky `prepare` values). There is no waiver yet: the gate only warns. Promotion to enforce adds a sidecar waiver, since package.json and TOML cannot carry an inline one.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals package-lifecycle-scripts
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/package-lifecycle-scripts/`](../../base/package-lifecycle-scripts/) · [all policies](../README.md)
