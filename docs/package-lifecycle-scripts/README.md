# Flag Package Lifecycle Scripts

`package-lifecycle-scripts` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 28 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns (observe rollout) when a change adds or edits code that runs at install or build time: npm install/prepare/pack scripts, gypfile without native sources, bin shadowing, unpinned git/URL deps; setup.py cmdclass and import-time calls, .pth imports, conftest, pyproject build hooks; build.rs and build-deps; go:generate; MSBuild Exec; gemspec, extconf, Podfile, Composer, Maven, Gradle exec. Never refuses yet; judges file text, not what a hook runs. Friction, not a security boundary.

## What it solves

Install-time and build-time hooks are how recent supply-chain worms spread (Shai-Hulud's preinstall, Phantom Gyp's binding.gyp, setup.py command overrides). A hook an agent adds runs on every machine that installs the package, before anyone reads it. This gate reads package manifests and build files across npm, Python, Rust, Go, .NET, Ruby, PHP and the JVM, and reports each install- or build-time hook a change adds or edits, and each git or URL dependency without a commit pin. It warns while its false-positive rate is measured; the script already sorts hooks that download, decode or evaluate code (to block) from other new hooks (to ask).

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
avoid(install_time_and_build_time_scripts); if_required: explain(why), keep_offline: true, pin(git_and_url_deps: commit)
prefer: download to a file, verify checksum, run as a reviewed step; never add hooks that fetch, decode or eval
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/package-lifecycle-scripts/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add package-lifecycle-scripts
chock sync --repo .
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
