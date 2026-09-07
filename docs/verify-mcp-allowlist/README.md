# Verify MCP Allowlist

`verify-mcp-allowlist` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `verify-mcp-allowlist.sh` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 15 total, 15 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Gate MCP server configuration as protected content. A shell write to .mcp.json is refused unless every mcpServers entry on the line matches a name+source pair on the allowlist -- an unlisted name blocks, and an allowed name whose command/args/url changed blocks too (catches a server renamed to an allowed name but pointed elsewhere). The allowlist ships inside this guard's own script, protected like every policy's implementations/ source -- edit only with 'chock: approved-config-change'. Claude Code's .mcp.json only: agentseam 0.2.1 records no per-vendor MCP config path, so other agents are left out, not guessed at. Tool-time (Bash) only, best-effort: PreToolUse fails open on a crash, a file-write tool bypasses this guard, a write with no visible content fails closed. No commit-time gate -- chock 0.8.0 has no gate kind pairing name+source against an external allowlist. Matching and path checks are exact-string and substring-coarse. No pragma for .mcp.json -- matching the allowlist is the only way through.

## What it solves

Config-as-attack-surface: agents auto-load MCP servers from repo-committed config, so a PR -- or an agent acting on injected instructions -- that adds a server entry to .mcp.json hands every future session a new tool surface, and nothing in the catalog watched it before this. A name match alone would not be enough; an attacker who reuses an approved server's name while pointing its command or args elsewhere needs the source checked too.

## How it works

A guard script, `implementations/verify-mcp-allowlist.sh`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
mcp_config(.mcp.json): server(name,source=cmd+args|url) must(match: allowlist(this_guard_source)); block(unlisted|source_mismatch); allow(exact_match)
allowlist: lives in implementations/verify-mcp-allowlist.sh; edit requires 'chock: approved-config-change'; scope: claude_code only, tool-time(Bash) only
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/verify-mcp-allowlist/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

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
