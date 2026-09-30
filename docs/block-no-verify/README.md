# Block No-Verify

`block-no-verify` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `block-no-verify.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 74 total, 74 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort guard against skipping git hooks: --no-verify on commit, push, merge, am and rebase, -n on commit and am (on push -n is --dry-run, allowed), and core.hooksPath set by -c, --config-env, `git config` or GIT_CONFIG_*. Read as parsed commands: wrappers are seen, message text is not. Also refuses an agent setting a person-only variable (CHOCK_ALLOW*, CHOCK_AGENT_COMMIT, CHOCK_DIFF_LIMIT) or hiding CLAUDECODE/AI_AGENT/CHOCK_AGENT_COMMIT; it says ask the person. Bypasses: aliases, scripts.

## What it solves

Every other gate in this catalog, bypassed with six characters. `--no-verify` is reached for when a hook is failing and the failure is inconvenient, which is exactly when the hook is doing its job.

## How it works

A guard script, `implementations/block-no-verify.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
never(commit|merge|am|rebase|push): --no-verify|-n(commit|am); never(set): core.hooksPath; never(agent_set|unset): CHOCK_ALLOW*|CHOCK_AGENT_COMMIT|CHOCK_DIFF_LIMIT|CLAUDECODE|AI_AGENT
if(hook_fails|override_needed): fix_issue|ask_person; never(skip_hook)
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/block-no-verify/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add block-no-verify
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/block-no-verify  <your-repo>/.agents/policies/block-no-verify
cd <your-repo> && chock sync --repo .
```

## Customising it

There is little to tune, and that is the point. If you find yourself widening this one, the hook it keeps bypassing is the thing to fix.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-no-verify
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/block-no-verify/`](../../base/block-no-verify/) · [all policies](../README.md)
