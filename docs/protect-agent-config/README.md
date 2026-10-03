# Protect Agent Config

`protect-agent-config` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `pathconf.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 1391 total, 1391 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md, whole agent folders (.claude/, .cursor/, .codex/, .gemini/, .windsurf/, .agents/, .chock/, ...), MCP/hook client configs (.mcp.json, ...), hook files of Cline, Kiro, Augment and Windsurf (user and machine level too), Claude Code plugin roots (.claude-plugin/, their hooks/), .git/{hooks,config}, policy implementations/: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, a write through a symlink to one; CLAUDE_CODE_PLUGIN_DIRS, claude --plugin-dir. Folder names match without regard to case. An instruction file under docs/ asks a person instead. Coarse: also eval or sh -c of computed text, shells fed by pipe/variable, interpreter one-liners naming such a path. Reads, `chock sync` pass. Edit/Write: tool gate, the same set and verdicts.

## What it solves

Self-modification: the agent editing its own authority. Instruction files, permission files and vendored enforcement define what the agent may do, and a one-line sed against .claude/settings.json rewrites those boundaries silently (MITRE ATLAS calls this Modify Agent Configuration, AML.T0081). Chock's drift checks detect tampering after the fact; this refuses the shell edit up front.

## How it works

A guard script, `implementations/pathconf.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
agent_config(AGENTS.md+wrappers|.{claude,cursor,codex,gemini,windsurf,agents,chock,junie,devin,grok,tabnine,augment,claude-plugin}/**|.github/{copilot*,hooks/}|.{clinerules,kiro}/hooks/|.kiro/agents/|<plugin>/hooks/|.mcp.json|.vscode/mcp.json|.git/{hooks,config}): never(edit|delete|set CLAUDE_CODE_PLUGIN_DIRS|--plugin-dir); any case; symlink same
docs/**/{AGENTS,CLAUDE,GEMINI,copilot-instructions}.md|.cursorrules|.windsurfrules|.aider.conf.yml: ask_person; else ask_person; no marker passes
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
