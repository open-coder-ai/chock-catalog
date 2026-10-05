# Verify MCP Allowlist

`verify-mcp-allowlist` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | blocks — refuses a matched shell command before it runs; blocks on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 108 total, 108 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Gates MCP servers against .chock/mcp-allowlist.json, empty by default (name, launcher with exact args, or url host). Shell guard refuses `<agent> mcp add` and shell writes of MCP configs or the allowlist unless listed. Script gate (commit, tool use, turn end) reads 13 client configs: a server off the list, or with other command, args or url host, refuses; unpinned or shell launchers, http, literal credentials, old versions only warn. Misses: aliases, scripts, gitignored files, other clients.

## What it solves

Config-as-attack-surface: agents auto-load MCP servers from repo-committed config, so a PR -- or an agent acting on injected instructions -- that adds a server entry to .mcp.json hands every future session a new tool surface, and nothing in the catalog watched it before this. A name match alone would not be enough; an attacker who reuses an approved server's name while pointing its command or args elsewhere needs the source checked too.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> An MCP server is not on the allowlist, differs from its allowlisted entry, or its config cannot be parsed. Only servers listed in .chock/mcp-allowlist.json (name with launcher and exact arguments, or url host) may be configured. Pin it to an exact version or image digest, run no shell command line, use https and carry credentials only as references (these rules warn for now). Ask a person to review the server and edit the allowlist from their own shell; do not edit the allowlist yourself.

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

The allowlist is `.chock/mcp-allowlist.json`, empty by default: a `servers` list whose entries are a `name` with a `launcher` and the `spec` (its arguments, joined by single spaces), or a `name` with a `url_host`. An agent is judged by the copy HEAD holds and cannot grow it; a person edits it from their own shell and commits it. Beside it the gate warns, while the rules are observed, about unpinned or shell launchers, http urls, literal credentials, denied options and packages below their floor (the tables in `implementations/data/`). It reads thirteen client config paths, not only `.mcp.json`; a shell write is checked for the files that hold nothing but servers.

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
