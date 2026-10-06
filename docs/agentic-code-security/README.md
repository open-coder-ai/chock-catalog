# Agentic Code Security

`agentic-code-security` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` |
| **On Claude Code** | blocks — blocks on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 141 total, 136 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: writing agent code or agent config -- Python or TypeScript using AutoGen, CrewAI, LangChain, LangGraph, mem0, the OpenAI Agents or Claude Agent SDK, an MCP server or client (.mcp.json, .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json, .codex/config.toml, .gemini/settings.json), docker-compose files for agents. avoid: code execution on the host, unpinned MCP servers and models, shell-reaching tools, approvals switched off, whole-environment and credential-store leaks, TLS verification off, unbounded loops, SQL and eval built from strings, stripped provenance markers. 29 rules in 10 packs -- exec, supply, tools, approval, identity, comms, bounds, prompt-memory, code, provenance -- each pack or rule allow|deny in .chock/agentic-security.json; bounds, prompt-memory and one supply rule start as allow.

## What it solves

The OWASP Top 10 for Agentic Applications lists what goes wrong when an agent is built carelessly, and most of
the entries leave a mark in code or config a static read can see: a code executor that runs on the host, an MCP
server launched at whatever version the registry serves today, a tool that hands the model's string to a shell,
a human approval switched off, the whole environment passed to a child process, certificate checks disabled.
Each is one line, easy to write while wiring an agent and easy to miss in review. This gate reads the code and
the MCP and agent client configs an agent writes and refuses those constructs as they are written and again at
commit, naming the rule, its CWE and OWASP ASI entry, and the fix. It refuses only what is new, so adopting it in
an existing repository does not start by rejecting what is already there. It is a static read: a sandbox that is
badly designed but never says `use_docker: False` passes, which is why the advisory OWASP ASI policies stay.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> agentic-code-security: a construct one of its rules denies -- the refusal above names the rule, its CWE and OWASP ASI entry, and the fix. Only what the change adds is refused, at commit, as the agent writes and at its turn's end: an old finding on lines it leaves alone never blocks. Each rule's verdict is allow|deny in .chock/agentic-security.json, per rule or per pack (exec, supply, tools, approval, identity, comms, bounds, prompt-memory, code, provenance). Only a human reviewer waives a line, with # chock: allow <rule-id> (// in JavaScript), never the agent: in the agent a waiver counts once a human has committed it. JSON configs are waived in the selection file only.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/agentic-code-security/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add agentic-code-security
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r agentic-security/agentic-code-security  <your-repo>/.agents/policies/agentic-code-security
cd <your-repo> && chock sync --repo .
```

## Customising it

Choose verdicts, not patterns, in `.chock/agentic-security.json` (a different file from java-security's
`.chock/security.json`, so a repository can carry both): `{"version": 1, "packs": {"exec": {"verdict": "deny"},
"bounds": {"verdict": "deny"}, "supply": {"rules": {"supply-hf-unpinned-revision": "deny"}}}}`. A pack or a rule
is `allow` or `deny`; a rule may differ from its pack; a pack or rule the file does not name runs at its default.
The noisy heuristics (bounds, prompt-memory, supply-hf-unpinned-revision) start as `allow`. A single line is
waived by a human reviewer with `# chock: allow <rule-id>` (`//` in JavaScript); the agent's own waiver is
refused, and a JSON config, which has no comments, is waived in the selection file. The rule catalogue in
`references/rule-catalogue.md` lists every rule with its weakness, ASI entry and fix.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals agentic-code-security
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`agentic-security/agentic-code-security/`](../../agentic-security/agentic-code-security/) · [all policies](../README.md)
