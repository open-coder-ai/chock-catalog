# Block Destructive Commands

`block-destructive-commands` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | commit-time guard script `block-destructive-commands-pre-push.py` |
| **Reaches** | `enforced-at-commit` — the script exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ambient-rule` |
| **Eval cases** | 81 total, 81 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort, on parsed commands (echo ignored). Blocks rm -rf on absolute, ~, $HOME, . or .. paths; recursive Remove-Item/rd/del on drive paths; git push --force or +refspec, reset --hard, clean -f, checkout .; kubectl delete; terraform destroy; aws s3 rm --recursive/rb --force; dropdb; helm uninstall; docker volume rm/prune, system prune; find -delete/-exec rm; shred; truncate; wipefs -a/-o; gcloud with any `delete` operand. branch -D asks. Pre-push hook refuses non-fast-forward pushes.

## What it solves

The command that cannot be undone: `rm -rf` against an absolute or home path, a force push over someone else's work, `git reset --hard` across uncommitted changes, `terraform destroy`. The cost is not the mistake, it is that there is nothing to recover from.

## How it works

A guard script, `implementations/block-destructive-commands-pre-push.py`, run by the git hook at every commit with no arguments. It reads the staged revision of each file from git and exits non-zero to refuse the commit.

The rule text ships alongside, so an agent reading its context knows the constraint before it stages the change rather than only after being refused:

```text
block(destructive_command @position-aware): rm_-rf(abs|~|$HOME|.|..)|Remove-Item|rd|del_-Recurse, git_push_--force, git_reset_--hard, git_checkout_., git_clean_-f, kubectl_delete, terraform_destroy, aws_s3(rm_--recursive|rb_--force), dropdb, helm(uninstall|delete), docker_volume(rm|prune)|system_prune, gcloud_delete(any_operand), find(-delete|-exec_rm)|shred|truncate @dangerous_target, wipefs(-a|-o)
require_approval: branch_-D; prefer: stash|soft_reset|dry-run; push: refuse_non_ff
```

## Which primitive it becomes

A **commit-time guard script**. `recompile` registers `implementations/block-destructive-commands-pre-push.py` under `.git/hooks/pre-commit.d/`, and the hook runs it at every commit (a commit-msg script gets git's message file as its one argument, any other none). The script reads the change from git itself and exits non-zero to refuse; the rule text compiles to `ambient-rule` beside it, so the agent knows the constraint before the commit is refused.

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
