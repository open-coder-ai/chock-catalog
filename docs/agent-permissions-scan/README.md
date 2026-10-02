# Agent Permissions Scan

`agent-permissions-scan` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `agent-permissions-scan.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 38 total, 38 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns only (observe): parses agent permission configs (.claude/settings*, .codex, .gemini, .vscode, .cursor/cli.json, opencode, .aider, .continue) and flags added bare or wildcard allows (Bash, curl/rm/sudo/git push, WebFetch, Write/Edit globs, mcp__*), removed deny entries, bypass/auto modes, codex never+danger, yolo, autoAccept, yes-always, regex-all VS Code approve. Misses: MCP configs, scripts, Read.

## What it solves

Permission grants an agent's config can hold that a line-based pattern cannot judge: a bare `Bash` or `WebFetch`, a `curl:*` or `git push:*` prefix wildcard, a star alone on its own line, an unquoted bypass default mode in YAML, a regex-all terminal auto-approve rule, and a deny entry that quietly disappears. An agent prompt-injected into widening its own grants gets unasked tool authority on the next session.

## How it works

A guard script, `implementations/agent-permissions-scan.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
agent_permissions(.claude/settings*|.codex/config.toml|.gemini/settings.json|.vscode/settings.json|.cursor/cli.json|opencode.json|.aider.conf.yml|.continue/**): grant named, scoped actions only
never(add): bare|wildcard allow, bypass|auto default mode, yolo|autoAccept|yes-always, regex-all auto-approve; never(remove): deny entry; observe: warns at commit+tool_use, enforce later
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/agent-permissions-scan/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add agent-permissions-scan
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/agent-permissions-scan  <your-repo>/.agents/policies/agent-permissions-scan
cd <your-repo> && chock sync --repo .
```

## Customising it

It ships at action warn (observe): it reports and never refuses. Measure what it reports with `chock check --history`, then move `hook.gate.action` to block. A reviewed exception is a `{file, path, value}` entry under `waive` in `.chock/devenv.json`, added by a person in their own commit; the file is a closed schema and an unknown key voids every waiver in it.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals agent-permissions-scan
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/agent-permissions-scan/`](../../base/agent-permissions-scan/) · [all policies](../README.md)
