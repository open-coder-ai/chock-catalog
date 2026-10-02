# Verify MCP Allowlist

`verify-mcp-allowlist` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 103 total, 103 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Gates MCP servers against .chock/mcp-allowlist.json, empty by default (name, launcher with exact args, or url host). Shell guard refuses `claude|codex|gemini|cursor-agent mcp add` and shell writes of MCP configs or the allowlist unless listed. Script gate (commit, tool use, turn end) reads 13 client configs: unlisted or altered servers refuse; unpinned or shell launchers, http urls, literal credentials, old versions only warn for now. Misses: aliases, scripts.

## What it solves

Config-as-attack-surface: agents auto-load MCP servers from repo-committed config, so a PR -- or an agent acting on injected instructions -- that adds a server entry to .mcp.json hands every future session a new tool surface, and nothing in the catalog watched it before this. A name match alone would not be enough; an attacker who reuses an approved server's name while pointing its command or args elsewhere needs the source checked too.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> An MCP server is not on the allowlist, differs from its allowlisted entry, or its config cannot be parsed. Only servers listed in .chock/mcp-allowlist.json (name with launcher and exact arguments, or url host) may be configured; the server must also be pinned to an exact version or image digest, run no shell command line, use https, and carry credentials only as references. Ask a person to review the server and edit the allowlist from their own shell; do not edit the allowlist yourself.

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
