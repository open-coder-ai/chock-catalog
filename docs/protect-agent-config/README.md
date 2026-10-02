# Protect Agent Config

`protect-agent-config` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `pathconf.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 722 total, 722 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md and wrappers, .claude/settings, MCP and hook client configs (.mcp.json, .cursor/mcp.json, .gemini/settings.json, more), .git/{hooks,config}, policy implementations/ and .chock/{config.yaml,security.json,agentic-security.json,dependency-allowlist.txt,bin,compiled,state}: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore. Reads and `chock sync` pass. Edit/Write: tool_use gate.

## What it solves

Self-modification: the agent editing its own authority. Instruction files, permission files and vendored enforcement define what the agent may do, and a one-line sed against .claude/settings.json rewrites those boundaries silently (MITRE ATLAS calls this Modify Agent Configuration, AML.T0081). Chock's drift checks detect tampering after the fact; this refuses the shell edit up front.

## How it works

A guard script, `implementations/pathconf.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
agent_config(AGENTS.md+wrappers|.claude/settings|.mcp.json|.chock/{config.yaml,*security.json,*allowlist.txt,bin,compiled,state}|.git/{hooks,config}|.agents/policies/*/implementations|.{cursor,codex,windsurf}/hooks.json|.{cursor,vscode}/mcp.json|.{codex,grok}/config.toml|.gemini/settings.json|.junie/mcp/mcp.json|.devin/{mcp_config,config,hooks.v1}.json|.grok/hooks/|.agents/{mcp_config,hooks}.json|.tabnine/agent/settings.json|.github/hooks/): never(edit|delete)
else ask_person; no marker passes
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
