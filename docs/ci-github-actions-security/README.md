# CI GitHub Actions Security

`ci-github-actions-security` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` |
| **On Claude Code** | blocks — blocks on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 43 total, 43 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Friction, not a security boundary: refuses or asks (each rule's tier) on GitHub Actions weaknesses a change adds to workflows, composite actions and dependabot.yml: event text in run/script, PR-head checkout under pull_request_target/workflow_run/issue_comment, missing or write-all permissions, secrets inherit or inlined, self-hosted runners on PRs, GITHUB_ENV writes, artifact and cache poisoning, agent steps on untrusted text. Misses: step outputs, composite internals, custom runner labels.

## What it solves

An agent that writes CI writes the workflow most likely to be attacked. Text from an issue or pull request expanded into `run:`, a pull_request_target job that builds the pull request's own code, a token left at write-all, `secrets: inherit` to another repository's workflow, a self-hosted runner open to forks, or a cache restored into a release each hand a stranger the repository's secrets in one line. This gate reads workflows, composite actions and dependabot.yml with a YAML key-path scanner and reports each such weakness a change adds, naming its rule, CWE, OWASP CI/CD risk and fix. It warns while its false-positive rate is measured, then a separate change makes it block.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> A GitHub Actions workflow, composite action or Dependabot file gained a weakness (each finding names its rule, CWE and fix). Fix it as the finding says. A person who has reviewed one may keep it with '# chock: allow <rule id>' on that line and commit from their own shell; in the agent only a line already committed in HEAD counts, so an agent asks the person rather than writing the comment.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/ci-github-actions-security/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add ci-github-actions-security
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/ci-github-actions-security  <your-repo>/.agents/policies/ci-github-actions-security
cd <your-repo> && chock sync --repo .
```

## Customising it

The curated action lists (agent actions, caches, publishers, auto-merge, cloud-key inputs) are `implementations/ghascan/data/actions.json`; the rules and their tiers are `implementations/ghascan/rules.py`. A person keeps a reviewed finding with `# chock: allow <rule id>` on its line; in the agent a waiver counts only for a line already in HEAD. Unpinned actions stay with pin-github-actions, not this gate.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals ci-github-actions-security
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/ci-github-actions-security/`](../../base/ci-github-actions-security/) · [all policies](../README.md)
