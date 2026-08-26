# OWASP ASI08 — Cascading Failures

`owasp-asi08-cascading-failures` · rule · advises

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

Keep one agent's bad output from propagating through everything downstream. Isolate blast radius per agent and per environment, separate development from production access, validate agent-to-agent handoffs, and add circuit breakers that halt automation on behavioural deviation. Use when chaining agents, designing orchestration, granting production access, or wiring agent output into downstream automation. Do NOT use for the transport security of those handoffs — that is `owasp-asi07-insecure-inter-agent-communication`.

## What it solves

A hallucination at stage one arriving at stage four as an established premise, and a change freeze enforced by telling the agent about it rather than by revoking its access.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
isolate(blast_radius): per_agent + per_environment; separate(dev, prod) hard; never(chain): agent_output -> agent_input | downstream_automation without(validation)
circuit_breaker(on: behavioral_deviation | error_rate | volume_spike) -> halt + escalate(human); see .agents/policies/owasp-asi08-cascading-failures/references/cascading-failures.md
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/owasp-asi08-cascading-failures/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add owasp-asi08-cascading-failures
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r agentic-security/owasp-asi08-cascading-failures  <your-repo>/.agents/policies/owasp-asi08-cascading-failures
cd <your-repo> && chock sync --repo .
```

## Customising it

Breaker thresholds must come from your own baseline; borrowed numbers either never fire or fire constantly. Keep the rule that an agent's self-report is not verification of its own action -- that is the clause the Replit incident turned on.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals owasp-asi08-cascading-failures
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`agentic-security/owasp-asi08-cascading-failures/`](../../agentic-security/owasp-asi08-cascading-failures/) · [all policies](../README.md)
