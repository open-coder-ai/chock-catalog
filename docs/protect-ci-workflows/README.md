# Protect CI Workflows

`protect-ci-workflows` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | asks — refuses a matched shell command before it runs. Asks on an agent's file writes. It refuses at turn end, because this client cannot prompt there. If the hook errors, the action goes through (measured) |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 71 total, 71 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Asks a person before an agent weakens the checks that review its work. Shell guard refuses writes to .github/workflows/, .github/actions/, .github/dependabot.y*ml (redirect, rm/mv/tee/sed -i/yq -i/sponge/ curl -o, git checkout/apply, patch, cmdlets); reads and `chock sync` pass. Edit/Write and an agent's commit ask before a change to CI, hook or bot config (GitLab, Jenkins, CircleCI, CODEOWNERS, husky, more). Not judged: deletions, empty writes, non-GitHub CI paths in the shell, a patch not readable by path, a path set outside the command; plugin installs ship no gate.

## What it solves

The gate an agent can quietly widen: its own CI. When the checks that must pass before a change lands live in the repo -- `.github/workflows/`, the composite actions they call, the dependabot config -- an agent fixing a red build can "fix" it by deleting the job that went red, loosening a trigger, or dropping a required scan, and the diff looks like just another edit. The work that was supposed to be reviewed then merges with the reviewer removed.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `ask`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> This path is CI, release, hook or dependency-bot configuration: the checks that review an agent's own work. An agent's change to it needs a person's decision. Say which file should change, what and why, and let the person approve the edit or make it from their own shell. Where a person cannot be asked, the write is refused: propose the change instead. At the turn's end this is a reminder that such a file is still changed and uncommitted. A person's own commit is not judged.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/protect-ci-workflows/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add protect-ci-workflows
chock sync .
```

Or [Open in the chock.sh builder](https://chock.sh/coding/builder/#s=eyJzY2hlbWEiOjIsImNsaWVudCI6ImNsYXVkZS1jb2RlIiwiYnVuZGxlIjp7InZlcnNpb24iOiIxLjAuMCJ9LCJjYXRhbG9nIjp7InNvdXJjZSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9vcGVuLWNvZGVyLWFpL2Nob2NrLWNhdGFsb2ciLCJyZWYiOiJiZDNhNTVlM2U5ZDUwZmI5NDA1NzcxZmJhODNhOGViYzhjZjdiZjJiIn0sInBvbGljaWVzIjpbeyJmcm9tIjoiY2F0YWxvZyIsImlkIjoicHJvdGVjdC1jaS13b3JrZmxvd3MiLCJ2ZXJzaW9uIjoiMC4yLjgiLCJzaGEyNTYiOiJmZjI4NDM1Yzk2ZDZmNWY5N2E3ZmMzZTdhYWI2OTg4MmFjZmJkYjMyYjZiZTYwYTUyNDYxNWVhOTM3N2MwMjVhIn1dfQ): this policy preselected for Claude Code, one merged plugin, installed with `chock install --selection <code> --apply`.

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/protect-ci-workflows  <your-repo>/.agents/policies/protect-ci-workflows
cd <your-repo> && chock sync --repo .
```

## Customising it

The protected paths in the guard script are the whole policy: `.github/workflows/`, `.github/actions/`, `.github/dependabot.yml`. Add the CI config your stack actually keeps elsewhere (a `.gitlab-ci.yml`, a `Jenkinsfile`, a `.circleci/`). It refuses shell writes only -- reads pass and `chock sync` passes -- so an agent proposes CI changes in a PR for a human to merge. The escape marker is an audit trail, not authentication; the check an agent cannot self-approve is branch protection enforced server-side, which this does not replace.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals protect-ci-workflows
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/protect-ci-workflows/`](../../base/protect-ci-workflows/) · [all policies](../README.md)
