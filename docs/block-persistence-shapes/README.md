# Block Persistence Shapes

`block-persistence-shapes` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `block-persistence-shapes.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 98 total, 98 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort guard against shell commands that publish or keep access after the session: npm/pnpm/yarn/twine/ poetry/uv/cargo/gem publish, docker/podman push and login, npm token and registry edits, repos made public; user services, launch agents, cron/at/schtasks, Run keys, authorized_keys, runner registration, sudoers, setuid bits, detached downloads. Asks on gh release create, git remote add, git push to a URL. Misses: scripts, aliases, system units, shell rc files, ssh-run commands.

## What it solves

Publishing a package, making a repository public, or leaving something running after the session ends are
the steps a supply-chain worm takes next, and each is one shell line an agent can be talked into. This guard
reads the command and refuses publishes, registry-auth edits, user services, launch agents, scheduled jobs,
Run keys, ssh login keys, runner registration, sudoers edits, setuid bits and detached downloads. It asks
before a release or a new remote. It is friction on the command text, not a security boundary.

## How it works

A guard script, `implementations/block-persistence-shapes.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
never(run): publish(npm|pnpm|yarn|twine|poetry|uv|cargo|gem|docker|podman), registry_login_or_token, repo_public, persist(user_service|launch_agent|cron|at|schtasks|run_key|authorized_keys|runner|sudoers|setuid|detached_download)
ask(person): release_create, remote_add, push_to_url; allow: dry_run, pack, build, status, list  # human decisions
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/block-persistence-shapes/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add block-persistence-shapes
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/block-persistence-shapes  <your-repo>/.agents/policies/block-persistence-shapes
cd <your-repo> && chock sync --repo .
```

## Customising it

The verbs, flags and paths are data in `implementations/data/shapes.json`; add a program or a path there and an
eval case beside it. Keep the `as_of` date current, since CI fails the table a year after it.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-persistence-shapes
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/block-persistence-shapes/`](../../base/block-persistence-shapes/) · [all policies](../README.md)
