# Firecrawl Fallback Only

`firecrawl-fallback-only` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 5 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: web research where a direct fetch fails, is blocked, or needs JS rendering. avoid: reaching for the Firecrawl connector as the default fetch path.

## What it solves

A metered web connector quietly becoming the default fetch path. Firecrawl exists for the research pages a direct fetch cannot read -- blocked, JS-rendered, rate-limited -- but once connected it is one tool call away from serving every URL, spending credits and an external dependency on pages a plain fetch would have returned identically.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
web_access: prefer(native: WebFetch|WebSearch|curl); firecrawl_connector: fallback_only
use_firecrawl_if: research_task & direct_fetch(failed|blocked|js_only|rate_limited); never(default): firecrawl; on_use: note_fallback_reason
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/firecrawl-fallback-only/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add firecrawl-fallback-only
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/firecrawl-fallback-only  <your-repo>/.agents/policies/firecrawl-fallback-only
cd <your-repo> && chock sync --repo .
```

## Customising it

The fallback conditions are the policy. Add conditions your sources actually hit (paywalls, geo-blocks) or drop ones they never do, and swap the connector name if your fallback scraper is a different service -- the native-first ordering is the part to keep.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals firecrawl-fallback-only
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/firecrawl-fallback-only/`](../../base/firecrawl-fallback-only/) · [all policies](../README.md)
