# Block Wildcard IAM

`block-wildcard-iam` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | content_regex gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 12 total, 12 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Commit and agent-write gate, 1-line slice of ASI03: IAM Action or Resource set to a bare * (JSON double-quoted, YAML single-quoted), a one-element Terraform * list, the AdministratorAccess ARN, quoted GCP roles/owner or roles/editor. Probed misses: * in a JSON list, service wildcards (s3:*), YAML double-quoted or bare *, Terraform jsonencode, NotAction, Principal *, PowerUser, multi-line lists, Azure Owner, K8s RBAC. Waiver: 'pragma: allowlist broad-privilege' same line; agent: only if in HEAD.

## What it solves

The agent role granted `"Action": "*"` on Friday afternoon to make the demo work, still attached in production a year later. A compromise of that agent is a compromise of everything the account reaches -- and the grant was one greppable line.

## How it works

A declarative `content_regex` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `allowlist_pragma`
- `content_pattern`
- `scan`

On a match it prints:

> Broad privilege grant detected. Scope Action and Resource to what the task needs, or a person adds 'pragma: allowlist broad-privilege' on the same line for a reviewed exception (in the agent it counts only when that exact line is already committed in HEAD, so an agent asks a person). Strict JSON cannot carry the pragma; narrow the grant or manage that document in Terraform/YAML.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/block-wildcard-iam/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add block-wildcard-iam
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r agentic-security/block-wildcard-iam  <your-repo>/.agents/policies/block-wildcard-iam
cd <your-repo> && chock sync --repo .
```

## Customising it

Scoped wildcards (`s3:*`) pass deliberately; whether service-level breadth is too broad for your agent is the advisory policy's judgement, not a regex's. Note the JSON limitation: strict JSON carries no comments, so the pragma escape only exists in Terraform/YAML -- for raw JSON documents the options are narrowing the grant or moving the document.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-wildcard-iam
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`agentic-security/block-wildcard-iam/`](../../agentic-security/block-wildcard-iam/) · [all policies](../README.md)
