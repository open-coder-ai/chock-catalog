# Verify MCP Allowlist

`verify-mcp-allowlist` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 58 total, 58 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Gate MCP server configuration as protected content. A shell write to .mcp.json is refused unless every mcpServers entry on the line, parsed as JSON, matches a name+source pair on the allowlist -- an unlisted name blocks, and an allowed name whose command/args/url changed blocks too. `claude mcp add|add-json` is checked the same way (add-from-claude-desktop cannot be verified and is refused). The allowlist ships inside this guard's own script, protected like every policy's implementations/ source -- edit only with 'chock: approved-config-change'. The shell guard reads Claude Code's .mcp.json, best-effort (PreToolUse fails open on a crash; a write with no visible content fails closed). A script gate at commit and tool use parses every written MCP config (.mcp.json, .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json, .gemini/settings.json, .codex/config.toml) against the same allowlist; only servers the change adds or alters are refused, at commit and tool use. No pragma.

## What it solves

Config-as-attack-surface: agents auto-load MCP servers from repo-committed config, so a PR -- or an agent acting on injected instructions -- that adds a server entry to .mcp.json hands every future session a new tool surface, and nothing in the catalog watched it before this. A name match alone would not be enough; an attacker who reuses an approved server's name while pointing its command or args elsewhere needs the source checked too.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> An MCP server that is not on the allowlist is configured. Only servers listed, by name and exact command/args/url, in implementations/verify-mcp-allowlist.py may be added. Ask a person to review the server and add it to that list; do not edit the allowlist yourself.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/verify-mcp-allowlist/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add verify-mcp-allowlist
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/verify-mcp-allowlist  <your-repo>/.agents/policies/verify-mcp-allowlist
cd <your-repo> && chock sync --repo .
```

## Customising it

The allowlist is the policy, and it ships inside the guard script itself rather than a separate file: guard-mode evals run against an empty sandbox repo, so an allowlist that lived anywhere else could never be exercised by this suite. Add your own approved servers as `name<TAB>source` lines; protect-agent-config's own protected-path coverage of every policy's `implementations/` already keeps a shell edit to this list honest, gated behind the same `chock: approved-config-change` marker. Covers Claude Code's `.mcp.json` only -- agentseam has no recorded MCP-config-path for the other agents it lists, and this policy does not guess at one.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals verify-mcp-allowlist
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/verify-mcp-allowlist/`](../../base/verify-mcp-allowlist/) · [all policies](../README.md)
