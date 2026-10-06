# Firecrawl Fallback Only

`firecrawl-fallback-only` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | advisory — advisory only: skill text, nothing stops a violation |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | guard script `firecrawl-fallback-gate.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 8 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: web research where a direct fetch fails, is blocked, or needs JS rendering. avoid: reaching for the Firecrawl connector as the default fetch path.

## What it solves

A metered web connector quietly becoming the default fetch path. Firecrawl exists for the research pages a direct fetch cannot read -- blocked, JS-rendered, rate-limited -- but once connected it is one tool call away from serving every URL, spending credits and an external dependency on pages a plain fetch would have returned identically.

## How it works

A guard script, `implementations/firecrawl-fallback-gate.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
web_access: prefer(native: WebFetch|WebSearch|curl); firecrawl_connector: fallback_only
use_firecrawl_if: research_task & direct_fetch(failed|blocked|js_only|rate_limited); never(default): firecrawl; on_use: note_fallback_reason
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/firecrawl-fallback-only/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add firecrawl-fallback-only
chock sync .
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
