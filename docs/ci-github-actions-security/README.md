# CI GitHub Actions Security

`ci-github-actions-security` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 43 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Friction, not a security boundary: warns (observe) on GitHub Actions weaknesses a change adds to workflows, composite actions and dependabot.yml: event text in run/script, PR-head checkout under pull_request_target/workflow_run/issue_comment, missing or write-all permissions, secrets inherit or inlined, self-hosted runners on PRs, GITHUB_ENV writes, artifact and cache poisoning, agent steps on untrusted text. Misses: step outputs, composite internals, custom runner labels.

## What it solves

An agent that writes CI writes the workflow most likely to be attacked. Text from an issue or pull request expanded into `run:`, a pull_request_target job that builds the pull request's own code, a token left at write-all, `secrets: inherit` to another repository's workflow, a self-hosted runner open to forks, or a cache restored into a release each hand a stranger the repository's secrets in one line. This gate reads workflows, composite actions and dependabot.yml with a YAML key-path scanner and reports each such weakness a change adds, naming its rule, CWE, OWASP CI/CD risk and fix. It warns while its false-positive rate is measured, then a separate change makes it block.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text

```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/ci-github-actions-security/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add ci-github-actions-security
chock sync --repo .
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
