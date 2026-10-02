# IAM Policy Scan

`iam-policy-scan` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 43 total, 43 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Reads whole IAM, RBAC and role documents, not lines: JSON, YAML, Terraform, ARM, Bicep, Kubernetes. Refuses Allow with Action star or an inverted key, public or any-principal trust, cluster-admin, subscription Owner. Asks for service wildcards on a named resource and cross-account trust. Only added grants. Misses computed grants (concat, for, locals), services beyond s3/iam/sts/kms/ec2, templated YAML that will not parse, unlisted file extensions. Waiver: pragma, or .chock/iam-policy-scan.json.

## What it solves

The wildcard grant that survives a line-by-line check because it was written over several lines: `"Action": [` then `"*"` on its own line, an Allow with `NotAction`, a statement pretty-printed by a formatter, a `jsonencode` object in Terraform, a YAML alias. The same one-line gate that catches `"Action": "*"` cannot see any of those; this one reads the whole document and judges the statement.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> Broad IAM, RBAC or role grant added. Name the actions, resources and principals the task needs: no Action star, no Allow with NotAction, NotResource or NotPrincipal, no public principal without a Condition, no cluster-admin binding, no Owner or Contributor at subscription scope. A reviewed exception is a person's: a pragma comment 'pragma: allowlist broad-privilege' beside the grant (YAML, Terraform, Bicep), or an entry in .chock/iam-policy-scan.json for strict JSON, which cannot carry a comment. In the agent a waiver counts only once a person has committed it, so an agent asks a person.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/iam-policy-scan/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add iam-policy-scan
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r agentic-security/iam-policy-scan  <your-repo>/.agents/policies/iam-policy-scan
cd <your-repo> && chock sync --repo .
```

## Customising it

New packs run in the `observe` rollout first (`rollout: observe` in `.chock/config.yaml`) until the false-positive rate on your own repository is known. A reviewed exception is a `# pragma: allowlist broad-privilege` comment beside the grant, or, for JSON, which cannot carry a comment, an entry in `.chock/iam-policy-scan.json` naming the path, the rule and the statement id the refusal prints. Computed grants (a reference, a function result) and templated YAML that will not parse are not judged.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals iam-policy-scan
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`agentic-security/iam-policy-scan/`](../../agentic-security/iam-policy-scan/) · [all policies](../README.md)
