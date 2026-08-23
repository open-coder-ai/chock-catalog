# Protect Agent Config

`protect-agent-config` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `protect-agent-config.sh` |
| **Reaches** | `enforced` once `chock sync` has run — the tool call is refused before it runs |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 8 total, 8 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Guard against an agent hand-editing its own guardrails. Agent instruction files (AGENTS.md and the per-agent wrappers), permission files (.claude/settings.json, .mcp.json) and vendored enforcement (.chock/bin/, .chock/compiled/) define what the agent may do -- so a shell command that rewrites them is the agent modifying its own authority (MITRE ATLAS AML.T0081; the AIVSS self-modification factor). The guard refuses shell write-commands targeting those paths; reads pass, and regeneration through `chock sync` passes because the tool writes them itself rather than through shell editing. Best-effort and deliberately coarse: a compound command that both reads a protected file and writes elsewhere may be refused -- rewrite it in two steps. The 'chock: approved-config-change' escape marker is friction plus an audit trail, not authentication -- the agent can write it too; the check an agent cannot self-approve is the commit-time gate and CI.

## What it solves

Self-modification: the agent editing its own authority. Instruction files, permission files and vendored enforcement define what the agent may do, and a one-line sed against .claude/settings.json rewrites those boundaries silently (MITRE ATLAS calls this Modify Agent Configuration, AML.T0081). Chock's drift checks detect tampering after the fact; this refuses the shell edit up front.

## How it works

A guard script, `implementations/protect-agent-config.sh`, run before the agent executes a Bash command. It tokenizes the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```
agent_config(AGENTS.md|wrappers|.claude/settings|.mcp.json|.chock/bin|.chock/compiled): never(hand_edit|delete); regenerate_via(chock sync)
if(config_change_needed): propose_to_human; await(approval)  # an agent must not widen or disarm its own guardrails
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/protect-agent-config/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add protect-agent-config
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/protect-agent-config  <your-repo>/.agents/policies/protect-agent-config
cd <your-repo> && chock sync --repo .
```

## Customising it

The protected-path list mirrors the adapter set -- add your organisation's own agent config files. The escape marker ('chock: approved-config-change') is the point, not a loophole: it forces the approval to be visible in the command a human sees. Deliberately coarse on compound commands; split a blocked read-then-write into two steps rather than widening the guard.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals protect-agent-config
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/protect-agent-config/`](../../base/protect-agent-config/) · [all policies](../README.md)
