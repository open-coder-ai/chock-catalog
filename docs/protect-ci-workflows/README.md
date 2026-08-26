# Protect CI Workflows

`protect-ci-workflows` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `protect-ci-workflows.sh` |
| **Reaches** | `enforced` once `chock sync` has run — the tool call is refused before it runs |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 19 total, 19 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Guard against an agent weakening the automated checks that review its own work. CI/CD workflow files (.github/workflows/), the composite actions they call (.github/actions/) and the dependency-update automation (.github/dependabot.yml) define what must pass before a change lands -- so a shell command that rewrites or deletes them is the agent removing the gate that would catch it. The guard refuses shell write-commands targeting those paths; reads pass, and tool-driven regeneration (chock sync) passes because it writes through the tool, not shell editing. Best-effort and deliberately coarse: a compound command that both reads a protected file and writes elsewhere may be refused -- rewrite it in two steps. The 'chock: approved-config-change' escape marker is friction plus an audit trail, not authentication -- the agent can write it too; the check an agent cannot self-approve is branch protection and required-status-checks enforced server-side.

## What it solves

The gate an agent can quietly widen: its own CI. When the checks that must pass before a change lands live in the repo -- `.github/workflows/`, the composite actions they call, the dependabot config -- an agent fixing a red build can "fix" it by deleting the job that went red, loosening a trigger, or dropping a required scan, and the diff looks like just another edit. The work that was supposed to be reviewed then merges with the reviewer removed.

## How it works

A guard script, `implementations/protect-ci-workflows.sh`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
ci_config(.github/workflows|.github/actions|.github/dependabot.yml): never(shell_edit|delete); propose_to_human
if(ci_change_needed): open PR; await(review)  # an agent must not disarm the checks on its own work
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/protect-ci-workflows/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add protect-ci-workflows
chock sync .
```

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
