# Agent Permissions Scan

`agent-permissions-scan` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | blocks — blocks on an agent's file writes and at turn end. If the hook errors, the action goes through (measured) |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 54 total, 54 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Blocks: parses agent permission configs (.claude/settings*, .codex, .gemini, .vscode, .cursor/cli.json, opencode, .aider, .continue) and flags added bare or wildcard allows (Bash, curl/rm/sudo/git push, WebFetch, Write/Edit globs, mcp__*), removed deny entries, bypass/auto modes, codex never+danger, yolo, autoAccept, yes-always, regex-all VS Code approve, Claude project env API-endpoint overrides and enableAllProjectMcpServers. Misses: other MCP configs, user-level settings, scripts, Read.

## What it solves

Permission grants an agent's config can hold that a line-based pattern cannot judge: a bare `Bash` or `WebFetch`, a `curl:*` or `git push:*` prefix wildcard, a star alone on its own line, an unquoted bypass default mode in YAML, a regex-all terminal auto-approve rule, and a deny entry that quietly disappears. An agent prompt-injected into widening its own grants gets unasked tool authority on the next session.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> An agent permission config grants more than named, scoped actions (a bare or wildcard allow, a bypass or auto default mode, an auto-approve switch or rule, codex approval never with no sandbox, a project env override of the API endpoint, every .mcp.json server enabled without a prompt), a deny entry is gone, or the config cannot be read. Scope the grant (Bash(npm test:*), a named tool list), keep the deny entry, use a mode that asks. Set an API endpoint in your own shell or user-level settings, and name the reviewed servers in enabledMcpjsonServers. A reviewed exception is a {file, path, value} entry under waive in .chock/devenv.json, added by a person in their own commit; in the agent only one already in HEAD counts, so an agent asks the person and never writes it.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/agent-permissions-scan/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add agent-permissions-scan
chock sync .
```

Or [Open in the chock.sh builder](https://chock.sh/coding/builder/#s=eyJzY2hlbWEiOjIsImNsaWVudCI6ImNsYXVkZS1jb2RlIiwiYnVuZGxlIjp7InZlcnNpb24iOiIxLjAuMCJ9LCJjYXRhbG9nIjp7InNvdXJjZSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9vcGVuLWNvZGVyLWFpL2Nob2NrLWNhdGFsb2ciLCJyZWYiOiJjMDVmOGQ5MGQ1NGM4NGI2N2M2ZjVhODhkNDI4ZTk0MjgyN2QyNWFkIn0sInBvbGljaWVzIjpbeyJmcm9tIjoiY2F0YWxvZyIsImlkIjoiYWdlbnQtcGVybWlzc2lvbnMtc2NhbiIsInZlcnNpb24iOiIwLjIuMSIsInNoYTI1NiI6IjIwODgzYzMzOTAwZTczYTgwOTFlNTg1NGE5N2VlNDdjNWU0ODJmNzI3YzUwYmU2YjVlMmU4NWI5OTIxMWNhOTgifV19): this policy preselected for Claude Code, one merged plugin, installed with `chock install --selection <code> --apply`.

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
