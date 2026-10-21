# Protect Agent Config

`protect-agent-config` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | blocks — refuses a matched shell command before it runs. Where its description says it asks, it asks. Blocks on an agent's file writes and at turn end. Where its description says it asks, it asks at the write and refuses at turn end, because this client cannot prompt there. If the hook errors, the action goes through (measured) |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | guard script `pathconf.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 1560 total, 1560 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Stops an agent editing its guardrails (MITRE ATLAS AML.T0081). Shell guard refuses writes to AGENTS.md, whole agent folders (.claude/, .cursor/, .codex/, .gemini/, .agents/, .chock/, ...), MCP/hook client configs (.mcp.json, ...), guardrails toggles, plugin install markers, chock.lock, hook files of Cline, Kiro, Augment, Windsurf and Devin (user and machine level), ~/.claude.json, Claude Code plugin roots, project config of Kilo Code, opencode, Factory, Amp, Continue and Goose, .git/{hooks,config}, policy implementations/: redirect, rm/mv/tee/sed -i, cp into, git checkout/restore, a write through a symlink; CLAUDE_CODE_PLUGIN_DIRS, claude --plugin-dir, chock resume (best effort). Any case. An instruction file under docs/ asks a person. Coarse: also eval or sh -c of computed text, shells fed by pipe/variable, interpreter one-liners naming such a path. Reads, `chock sync` pass. Edit/Write: tool gate, same set and verdicts. Misses: user config under ~/.config/, writes a script makes, an existing hard link.

## What it solves

Self-modification: the agent editing its own authority. Instruction files, permission files and vendored enforcement define what the agent may do, and a one-line sed against .claude/settings.json rewrites those boundaries silently (MITRE ATLAS calls this Modify Agent Configuration, AML.T0081). Chock's drift checks detect tampering after the fact; this refuses the shell edit up front.

## How it works

A guard script, `implementations/pathconf.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
agent_config(AGENTS.md+wrappers|.goosehints|.{claude,cursor,codex,gemini,windsurf,agents,chock,junie,devin,grok,tabnine,augment,claude-plugin,kilo{,code},opencode,factory,amp,continue}/|{opencode,kilo}.json*|.continuerc.json|.github/{copilot*,hooks/}|.{clinerules,kiro}/hooks/|.kiro/agents/|<plugin>/hooks/|{.,.vscode/}mcp.json|~/.claude.json|chock.{selection.json,lock}|.git/{hooks,config}): never(edit|delete|*PLUGIN_DIRS|--plugin-dir); any case; links same
docs/**/<instruction>: ask; no waiver
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/protect-agent-config/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add protect-agent-config
chock sync .
```

Or [Open in the chock.sh builder](https://chock.sh/coding/builder/#s=eyJzY2hlbWEiOjIsImNsaWVudCI6ImNsYXVkZS1jb2RlIiwiYnVuZGxlIjp7InZlcnNpb24iOiIxLjAuMCJ9LCJjYXRhbG9nIjp7InNvdXJjZSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9vcGVuLWNvZGVyLWFpL2Nob2NrLWNhdGFsb2ciLCJyZWYiOiJlODg1ZjkxOGEzMzVlMjBkZmRkYjRmYWQwMzMxZDRkNWI0YzVlYjQzIn0sInBvbGljaWVzIjpbeyJmcm9tIjoiY2F0YWxvZyIsImlkIjoicHJvdGVjdC1hZ2VudC1jb25maWciLCJ2ZXJzaW9uIjoiMC43LjEiLCJzaGEyNTYiOiIxOTY0NDU3NTM2NWYyNTVhNjEyMzQ1NDJjNjc2YjNiZGYwMjhiZmQyMGE3YzIwNTczYWMyM2QzMGI1OTA4N2ExIn1dfQ): this policy preselected for Claude Code, one merged plugin, installed with `chock install --selection '<code>' --apply`.

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
