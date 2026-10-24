# Block Destructive Commands

`block-destructive-commands` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | blocks — refuses a matched shell command before it runs. Where its description says it asks, it asks. If the hook errors, the action goes through (measured) |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | commit-time guard script `block-destructive-commands-pre-push.py` |
| **Reaches** | `enforced-at-commit` — the script exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ambient-rule` |
| **Eval cases** | 191 total, 191 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort, on parsed commands (echo ignored); one verdict table shared with rtk-dangerous-actions-blocker. Blocks recursive deletes of root, home, abs paths or .git; mv/chmod/chown -R of system dirs; dd to devices, mkfs; lockouts; force, delete, mirror pushes; history rewrites; switch --discard; IaC destroy; cloud deletes; DB drops. Asks: rm -rf off a safe list, one named kubectl delete, bare lease, stash drop, -auto-approve, drain, prunes, API deletes. Dry runs pass. Pre-push: no non-ff.

## What it solves

The command that cannot be undone: `rm -rf` against an absolute or home path, a force push over someone else's work, `git reset --hard` across uncommitted changes, `terraform destroy`. The cost is not the mistake, it is that there is nothing to recover from.

## How it works

A guard script, `implementations/block-destructive-commands-pre-push.py`, run by the git hook at every commit with no arguments. It reads the staged revision of each file from git and exits non-zero to refuse the commit.

The rule text ships alongside, so an agent reading its context knows the constraint before it stages the change rather than only after being refused:

```text
block: rm|mv|chmod|chown_-R(root|home|sys),rm_-rf(abs|.|$PWD|.git),dd_of=/dev|mkfs|wipefs|shred,lockout(authkeys|usermod|passwd|chattr_+i|kill_-1|crontab),git(push_-f|+ref|-d|:ref|--mirror,reset_--hard,clean_-f,checkout|restore_.|switch_--discard,reflog|gc|filter),iac_destroy,cloud|k8s|helm_delete,sql_drop
ask: rm_-rf(off safe_list),kubectl_delete(1_named),lease_bare,stash_drop,branch_-D,-auto-approve,drain,prune,pkill_-f,systemctl_disable,api_DELETE;allow: tool_dry_run;push: refuse_non_ff
```

## Which primitive it becomes

A **commit-time guard script**. `recompile` registers `implementations/block-destructive-commands-pre-push.py` under `.git/hooks/pre-commit.d/`, and the hook runs it at every commit (a commit-msg script gets git's message file as its one argument, any other none). The script reads the change from git itself and exits non-zero to refuse; the rule text compiles to `ambient-rule` beside it, so the agent knows the constraint before the commit is refused.

## Installing it

```bash
chock add block-destructive-commands
chock sync .
```

Or [Open in the chock.sh builder](https://chock.sh/coding/builder/#s=eyJzY2hlbWEiOjIsImNsaWVudCI6ImNsYXVkZS1jb2RlIiwiYnVuZGxlIjp7InZlcnNpb24iOiIxLjAuMCJ9LCJjYXRhbG9nIjp7InNvdXJjZSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9vcGVuLWNvZGVyLWFpL2Nob2NrLWNhdGFsb2ciLCJyZWYiOiJhMjNhYzk0YmJkZWRmYThhN2QyMzJhYWI2ZmIyYWYyZjNlY2FhZTBlIn0sInBvbGljaWVzIjpbeyJmcm9tIjoiY2F0YWxvZyIsImlkIjoiYmxvY2stZGVzdHJ1Y3RpdmUtY29tbWFuZHMiLCJ2ZXJzaW9uIjoiMC4zLjEiLCJzaGEyNTYiOiI3MmVhOTA4Nzc5NjI2ODUyNzUzYjBkZGY2NGI1NTMzNTEzMWYxZTRlODFjNDg5ZTYzYmY2NzRkNjg0YTRlYzQ1In1dfQ): this policy preselected for Claude Code, one merged plugin, installed with `chock install --selection <code> --apply`.

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
