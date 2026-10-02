# Block Unguarded Agent Spawn

`block-unguarded-agent-spawn` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `block-unguarded-agent-spawn.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 43 total, 43 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort guard against launching a coding agent with safety checks off: claude --dangerously-skip-permissions, bypassPermissions or a wildcard --allowedTools; codex --full-auto, --yolo, --ask-for-approval never, danger-full-access; gemini --yolo or --approval-mode yolo; cursor-agent --force; aider --yes-always; copilot --allow-all-tools; amp, cline, goose, opencode auto-approve. Looks through cd, bash -c, sudo, env, npx, uvx. Misses: config, aliases, scripts, ssh.

## What it solves

An agent that launches another agent with its permission prompts switched off (`claude
--dangerously-skip-permissions`, `codex --yolo`, `gemini --yolo`) hands that child every tool with no
human in the loop, and every guard in this repository stops applying to what the child does. That is
OWASP ASI10 (rogue agents): the unattended process acts outside the boundary the person set.

## How it works

A guard script, `implementations/block-unguarded-agent-spawn.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
never(spawn_agent): claude(--dangerously-skip-permissions|bypassPermissions|--allowedTools_*), codex(--full-auto|--yolo|-a_never|--sandbox_danger-full-access), gemini(--yolo|-y|--approval-mode_yolo), cursor-agent(--force|-f), aider(--yes-always), copilot(--allow-all-tools), amp|cline|goose|opencode(auto-approve flags)
if(unattended_run_needed): ask_person; person_starts_it  # spawn with default approvals and sandbox
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/block-unguarded-agent-spawn/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add block-unguarded-agent-spawn
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/block-unguarded-agent-spawn  <your-repo>/.agents/policies/block-unguarded-agent-spawn
cd <your-repo> && chock sync --repo .
```

## Customising it

Each agent's unsafe flags are one small function in `implementations/block-unguarded-agent-spawn.py`; add
a program or a flag there and an eval case beside it. A sandbox you have proven safe is a reason to edit this policy in
your own copy, not to run the flag past it.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-unguarded-agent-spawn
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/block-unguarded-agent-spawn/`](../../base/block-unguarded-agent-spawn/) · [all policies](../README.md)
