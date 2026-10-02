# CI GitHub Actions Security

`ci-github-actions-security` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: advise`) |
| **Mechanism** | guard script `ci-github-actions-security-gate.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 43 total, 43 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Friction, not a security boundary: warns (observe) on GitHub Actions weaknesses a change adds to workflows, composite actions and dependabot.yml: event text in run/script, PR-head checkout under pull_request_target/workflow_run/issue_comment, missing or write-all permissions, secrets inherit or inlined, self-hosted runners on PRs, GITHUB_ENV writes, artifact and cache poisoning, agent steps on untrusted text. Misses: step outputs, composite internals, custom runner labels.

## What it solves

An agent that writes CI writes the workflow most likely to be attacked. Text from an issue or pull request expanded into `run:`, a pull_request_target job that builds the pull request's own code, a token left at write-all, `secrets: inherit` to another repository's workflow, a self-hosted runner open to forks, or a cache restored into a release each hand a stranger the repository's secrets in one line. This gate reads workflows, composite actions and dependabot.yml with a YAML key-path scanner and reports each such weakness a change adds, naming its rule, CWE, OWASP CI/CD risk and fix. It warns while its false-positive rate is measured, then a separate change makes it block.

## How it works

A guard script, `implementations/ci-github-actions-security-gate.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text

```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/ci-github-actions-security/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

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
