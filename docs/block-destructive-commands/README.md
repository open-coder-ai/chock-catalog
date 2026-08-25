# Block Destructive Commands

`block-destructive-commands` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `block-destructive.sh` |
| **Reaches** | `enforced` once `chock sync` has run — the tool call is refused before it runs |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 34 total, 34 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort guard against destructive commands: rm -rf targeting absolute, home, or root-adjacent paths; git push --force (not --force-with-lease); git reset --hard; git clean -f; kubectl delete; terraform destroy. Known bypass classes include aliases, quoted arguments, non-standard clients, and scripts that invoke these commands indirectly. This is friction, not a security boundary.

## What it solves

The command that cannot be undone: `rm -rf` against an absolute or home path, a force push over someone else's work, `git reset --hard` across uncommitted changes, `terraform destroy`. The cost is not the mistake, it is that there is nothing to recover from.

## How it works

A guard script, `implementations/block-destructive.sh`, run before the agent executes a Bash command. It tokenizes the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```
block(destructive_command): rm_-rf(/|~|.), git_push_--force, git_reset_--hard, git_checkout_., git_clean_-f, kubectl_delete, terraform_destroy
require_approval: reset_hard|rm_-rf|branch_-D; prefer: stash|soft_reset|force-with-lease|dry-run
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/block-destructive-commands/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add block-destructive-commands
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/block-destructive-commands  <your-repo>/.agents/policies/block-destructive-commands
cd <your-repo> && chock sync --repo .
```

## Customising it

The command list in the guard script is the whole policy; add the destructive commands your stack actually has (`helm uninstall`, `aws s3 rm --recursive`, `dropdb`). Read the manifest description first: it names the bypass classes this cannot see, and adding entries does not narrow them.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-destructive-commands
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/block-destructive-commands/`](../../base/block-destructive-commands/) · [all policies](../README.md)
