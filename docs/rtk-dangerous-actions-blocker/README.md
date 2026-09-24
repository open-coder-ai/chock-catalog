# rtk Dangerous Actions Blocker

`rtk-dangerous-actions-blocker` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `rtk-dangerous-actions-blocker.sh` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 78 total, 78 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Carved out for rtk-ai/rtk#1007: rtk's own decision table as a chock policy (rtk's own hooks may not block). Refuses rm -rf on root, home, parent or absolute paths; git push --force and '+' refspecs (not --force-with-lease); reads of credential files (.env, *.pem, *.key, id_rsa, ~/.ssh, ~/.aws) and echoes or inline literals of *_API_KEY/*_SECRET/*_TOKEN; DROP/TRUNCATE/unscoped DELETE through psql, mysql, sqlite3, mongosh, redis-cli, and dropdb; plus the base policy's cloud rows (kubectl delete, terraform destroy, aws s3 rm --recursive, helm uninstall, gcloud delete, docker volume rm). Asks where rtk's table says ask: rm -rf on a relative path off the safe list; git reset --hard, clean -f, checkout ., branch -D; docker prune and docker rm -f over a substitution. File checks are skipped inside docker/kubectl exec, as rtk specifies; rtk is a transparent prefix. Bypasses: aliases, quoting, indirection, sourced files, interpreters, indirect scripts. This is friction, not a security boundary.

## What it solves

A project asked for exactly this guard and could not merge it: rtk-ai/rtk#1007 wants a PreToolUse hook that refuses `rm -rf /`, force pushes, credential reads and `DROP TABLE`, and asks before `rm -rf` on an ordinary directory, `git reset --hard` or a docker prune -- while rtk's own hook contract says its hooks never block. This policy is that table, carved out under rtk's name, so it exists as a policy anyone can install beside rtk's rewrite hook rather than as code rtk cannot take. It is also the worked example of the catalog's premise: when someone wants a specific policy for a specific agent, the catalog carves it out with its own tooling, and the folder is theirs to fork.

## How it works

A guard script, `implementations/rtk-dangerous-actions-blocker.sh`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
block: rm_-rf(/|~|..|abs), git_push(--force|+ref), read(.env|*.pem|*.key|id_rsa|~/.ssh|~/.aws), echo|inline($*_API_KEY|$*_SECRET|$*_TOKEN), sql(DROP|TRUNCATE|DELETE_no_WHERE)|dropdb|FLUSHALL, kubectl_delete|terraform_destroy|aws_s3_rm_-r|helm_uninstall|gcloud_delete|docker_volume_rm
ask: rm_-rf(relative, off safe_list), git(reset_--hard|clean_-f|checkout_.|branch_-D), docker_*_prune|docker_rm_-f_$(..); skip_inside: docker|kubectl_exec; prefix: rtk; prefer: force-with-lease|stash|dry-run
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/rtk-dangerous-actions-blocker/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add rtk-dangerous-actions-blocker
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/rtk-dangerous-actions-blocker  <your-repo>/.agents/policies/rtk-dangerous-actions-blocker
cd <your-repo> && chock sync --repo .
```

## Customising it

Two knobs carry rtk's opinions and are the ones to turn: `is_safe_dir` lists the directories `rm -rf` may delete without asking, and each `ask` call in the guard is one line away from a refusal (print the message and `exit 1`) or from silence (delete the call). The container rule is one `if`: remove the `in_container` guard to keep the file checks inside `docker exec`, which is what the base `block-destructive-commands` does. Read the manifest description first: it names the bypass classes this cannot see.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals rtk-dangerous-actions-blocker
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/rtk-dangerous-actions-blocker/`](../../base/rtk-dangerous-actions-blocker/) · [all policies](../README.md)
