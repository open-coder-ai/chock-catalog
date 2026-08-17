# Block Wildcard Agent Permissions

`block-wildcard-agent-permissions` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | content_regex gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 7 total, 7 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Pre-commit gate for the mechanizable slice of excessive agency: committed agent permission grants that allow everything. A settings file whose shell grant or allow-list is a bare wildcard hands the agent unlimited tool authority for every future session, in a file reviewers rarely read as code. The agent-world twin of block-wildcard-iam: scope grants to what the task needs (e.g. Bash(git status:*)). Escape: 'pragma: allowlist broad-agency' on the same line.

## What it solves

Excessive agency as a committed artifact. A bare-wildcard allow-list or shell grant hands every future session unlimited tool authority, in a JSON file reviewers rarely read as code -- and unlike a risky command, a permission grant fires long after the commit that introduced it. The agent-world twin of block-wildcard-iam.

## How it works

A declarative `content_regex` gate, evaluated on `commit`, action `block`.

Parameters, from `manifest.yaml`:

- `allowlist_pragma`
- `content_pattern`
- `scan`

On a match it prints:

> Wildcard agent permission grant detected. Scope the grant to specific tools or commands (e.g. Bash(git status:*), a named tool list), or add 'pragma: allowlist broad-agency' on the same line for a reviewed exception.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/block-wildcard-agent-permissions/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add block-wildcard-agent-permissions
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/block-wildcard-agent-permissions  <your-repo>/.agents/policies/block-wildcard-agent-permissions
cd <your-repo> && chock sync --repo .
```

## Customising it

Add the grant syntaxes of the agents you actually run -- the pattern ships with Claude-style permissions and MCP always-allow lists. Scoped wildcards like Bash(git status:*) pass by design; the gate blocks only the everything-grant, because a guard that argues with every scoped grant gets disabled within a week.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-wildcard-agent-permissions
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/block-wildcard-agent-permissions/`](../../base/block-wildcard-agent-permissions/) · [all policies](../README.md)
