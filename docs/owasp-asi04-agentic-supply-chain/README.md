# OWASP ASI04 — Agentic Supply Chain Vulnerabilities

`owasp-asi04-agentic-supply-chain` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 6 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Verify agent components before loading them, and keep verifying, because runtime tool discovery changes the supply chain after deployment. Use when adding an MCP server, agent framework, plugin, tool registry, or model artifact, and when reviewing what an agent may pull at runtime. Do NOT use for ordinary application dependencies already covered by `verify-dependency-exists`.

## What it solves

A dependency tree that is never final. An agent that discovers tools at runtime can load something tonight that no lockfile, review, or SCA run has ever seen.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```
before(load: tool|mcp_server|framework|model): verify(signature + provenance) + pin(version) + record(AIBOM); apply(SCA) pre_pull
re_verify(runtime_discovered_components) each_load; never(auto_trust): registry_listing | popularity; see .agents/policies/owasp-asi04-agentic-supply-chain/references/supply-chain.md
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/owasp-asi04-agentic-supply-chain/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add owasp-asi04-agentic-supply-chain
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r agentic-security/owasp-asi04-agentic-supply-chain  <your-repo>/.agents/policies/owasp-asi04-agentic-supply-chain
cd <your-repo> && chock sync --repo .
```

## Customising it

The publisher allowlist is the practical control; expand it deliberately and by key, not by name. If you cannot remove runtime discovery, keep the load-time gate and log what actually loaded -- an AIBOM built from intent rather than observation is fiction.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals owasp-asi04-agentic-supply-chain
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`agentic-security/owasp-asi04-agentic-supply-chain/`](../../agentic-security/owasp-asi04-agentic-supply-chain/) · [all policies](../README.md)
