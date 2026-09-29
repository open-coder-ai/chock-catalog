# Block Unguarded Agent Spawn

`block-unguarded-agent-spawn` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `block-unguarded-agent-spawn.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 25 total, 25 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort guard against an agent launching a coding agent with its safety checks off: claude --dangerously-skip-permissions or --permission-mode bypassPermissions, codex --full-auto, --yolo, --dangerously-bypass-approvals-and-sandbox or --sandbox danger-full-access, gemini --yolo, -y or --approval-mode yolo, cursor-agent --force. A spawned agent that never asks and never sandboxes is an unsupervised agent (OWASP ASI10, rogue agents). Read as a parsed command, so `cd repo && claude ...`, `bash -c '...'`, sudo/env wrappers and `npx @openai/codex ...` are caught, while a normal invocation, `codex --sandbox workspace-write`, or a command that only mentions the flag (echo, grep, a commit message) is not. Known bypass classes include shell aliases, wrapper scripts, config files that set the mode, and agents this list does not name. Run the agent with its default approvals; a human decides when an unattended run is acceptable.

## What it solves

An agent that launches another agent with its permission prompts switched off (`claude
--dangerously-skip-permissions`, `codex --yolo`, `gemini --yolo`) hands that child every tool with no
human in the loop, and every guard in this repository stops applying to what the child does. That is
OWASP ASI10 (rogue agents): the unattended process acts outside the boundary the person set.

## How it works

A guard script, `implementations/block-unguarded-agent-spawn.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
never(spawn_agent): claude(--dangerously-skip-permissions|--permission-mode_bypassPermissions), codex(--full-auto|--yolo|--dangerously-bypass-approvals-and-sandbox|--sandbox_danger-full-access), gemini(--yolo|-y|--approval-mode_yolo), cursor-agent(--force)
if(unattended_run_needed): propose_to_human; await(approval)  # spawn with default approvals and sandbox
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
