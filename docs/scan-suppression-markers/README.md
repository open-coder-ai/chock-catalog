# Scan Suppression Markers

`scan-suppression-markers` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 32 total, 31 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Asks a person before a change adds a scanner suppression: inline ignore markers (bandit, gosec, ruff S codes, Sonar, Semgrep, ESLint security, Checkov, tfsec, Trivy, KICS, hadolint, cfn_nag, zizmor, gitleaks, detect-secrets, chock waivers, CodeQL, Java/C#/Rust security allows), scanner ignore files and skip keys, a CI scan set to pass on failure. Only added lines; prose skipped. Runs: commit, agent write, turn's end; CI annotates. Line-local, friction not a boundary.

## What it solves

An agent told to make a scanner pass can silence the scanner instead of fixing the finding: an inline ignore marker, an entry in a scanner's ignore file, or a CI security step told to pass when it fails. This gate asks a person before such a change lands, so a suppression is a decision a person made, not one an agent slipped into a diff. Only what the change adds is judged; suppressions already committed stay quiet.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `ask`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> This change adds a scanner suppression: an inline ignore marker, an ignore-file entry or skip key, or a CI security step told to pass when it fails. Fix what the scanner reports instead of silencing it. If the finding is a reviewed false positive, a person keeps the suppression by committing from their own shell with CHOCK_ALLOW=scan-suppression-markers for that one commit; an agent asks the person and never sets it.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/scan-suppression-markers/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add scan-suppression-markers
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/scan-suppression-markers  <your-repo>/.agents/policies/scan-suppression-markers
cd <your-repo> && chock sync --repo .
```

## Customising it

A reviewed false positive is kept by a person committing from their own shell with CHOCK_ALLOW=scan-suppression-markers set for that one commit. Ship it under `rollout: observe` in .chock/config.yaml first, read the gate log, and move to enforce once the asks it records are the ones you want asked. To stop judging the policy, list it under policies.disabled.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals scan-suppression-markers
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/scan-suppression-markers/`](../../base/scan-suppression-markers/) · [all policies](../README.md)
