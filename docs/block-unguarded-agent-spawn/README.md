# Block Unguarded Agent Spawn

`block-unguarded-agent-spawn` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | blocks — refuses a matched shell command before it runs. If the hook errors, the action goes through (measured) |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | guard script `block-unguarded-agent-spawn.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 58 total, 58 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best effort. Refuses agents with safety off: claude --dangerously-skip-permissions, bypassPermissions, wildcard --allowedTools; codex --full-auto, --yolo, -a never, danger-full-access; gemini --yolo; cursor-agent --force; aider --yes-always; copilot --allow-all-tools; amp, cline, goose, opencode auto-approve; DeepSeek Harness 127.0.0.1:3080/api calls lifting sandbox/approvals (CVE-2026-82533). Sees through bash -c, sudo, npx. Misses: config, aliases, scripts, ssh, other dsh ports, file bodies.

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
never(http_to(dsh 127.0.0.1:3080/api)+body(danger-full-access|approval_never)); if(unattended_run_needed|wider_access): ask_person; person_starts_it
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/block-unguarded-agent-spawn/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add block-unguarded-agent-spawn
chock sync .
```

Or [Open in the chock.sh builder](https://chock.sh/coding/builder/#s=eyJzY2hlbWEiOjIsImNsaWVudCI6ImNsYXVkZS1jb2RlIiwiYnVuZGxlIjp7InZlcnNpb24iOiIxLjAuMCJ9LCJjYXRhbG9nIjp7InNvdXJjZSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9vcGVuLWNvZGVyLWFpL2Nob2NrLWNhdGFsb2ciLCJyZWYiOiI5NWZmNzIxNWQyOGUwZGMyNzg5YWJhNDJmZWM2ZjVjZmM0MjViYWVjIn0sInBvbGljaWVzIjpbeyJmcm9tIjoiY2F0YWxvZyIsImlkIjoiYmxvY2stdW5ndWFyZGVkLWFnZW50LXNwYXduIiwidmVyc2lvbiI6IjAuMi4xIiwic2hhMjU2IjoiODg0YjVkZjI4MGFkM2FhMDczMzgyYWQ1MDdhZjNlMGZkMzYzM2JhM2UyYzQ4MmRiMzMwNWQ3ZTdhOTZiZjQ1MyJ9XX0): this policy preselected for Claude Code, one merged plugin, installed with `chock install --selection <code> --apply`.

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
