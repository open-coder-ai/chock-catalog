# OWASP ASI10 — Rogue Agents

`owasp-asi10-rogue-agents` · rule · advises

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

Make an agent that has drifted, been compromised, or was never inventoried detectable and stoppable. Require an owner, expiry, and inventory entry for every agent, sandbox by default, baseline behaviour and alert on deviation, and keep a tested kill switch. Use when deploying a long-running or autonomous agent, allowing sub-agent spawning, or reviewing agent lifecycle and monitoring. Do NOT use for a single hijacked request within a supervised session — that is `owasp-asi01-agent-goal-hijack`.

## What it solves

The agent nobody can point to an owner for, still running, still credentialed, doing something competently wrong across sessions while every dashboard reads green.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```
every(agent): owner + purpose + expiry + inventory_entry + kill_switch(tested); default(runtime): sandboxed; never(allow): uninventoried_subagent_spawn
baseline(behavior) + alert(deviation) continuously; on(deviation): halt + escalate(human); see .agents/policies/owasp-asi10-rogue-agents/references/rogue-agents.md
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/owasp-asi10-rogue-agents/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add owasp-asi10-rogue-agents
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r agentic-security/owasp-asi10-rogue-agents  <your-repo>/.agents/policies/owasp-asi10-rogue-agents
cd <your-repo> && chock sync --repo .
```

## Customising it

Expiry length is the main dial, and it is also the compensating control if you cannot afford continuous monitoring. Baseline on breadth as well as volume: an agent touching entirely new resources at an ordinary request rate passes a rate-only baseline.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals owasp-asi10-rogue-agents
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`agentic-security/owasp-asi10-rogue-agents/`](../../agentic-security/owasp-asi10-rogue-agents/) · [all policies](../README.md)
