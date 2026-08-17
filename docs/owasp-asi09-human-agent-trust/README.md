# OWASP ASI09 — Human-Agent Trust Exploitation

`owasp-asi09-human-agent-trust` · rule · advises

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

Stop an agent from controlling the information a human approves against. Show the raw action rather than a model-authored summary at every confirmation step, forbid persuasive framing in sensitive workflows, and keep an immutable record of what was presented versus what executed. Use when designing approval prompts, human-in-the-loop checkpoints, agent-written PR descriptions, or consent and disclosure flows. Do NOT use for what the agent is permitted to do once approved — that is `owasp-asi02-tool-misuse`.

## What it solves

The reason "human in the loop" is not a mitigation for the other nine. If the human approves an agent-authored summary, the agent has approved itself through a proxy.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```
at(approval_step): render(raw_action + real_target + real_scope); never(substitute): agent_summary for(the_thing_approved)
forbid(persuasive_framing | urgency | false_confidence) in(sensitive_workflow); log(immutable): presented vs executed; see .agents/policies/owasp-asi09-human-agent-trust/references/human-trust.md
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/owasp-asi09-human-agent-trust/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add owasp-asi09-human-agent-trust
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r agentic-security/owasp-asi09-human-agent-trust  <your-repo>/.agents/policies/owasp-asi09-human-agent-trust
cd <your-repo> && chock sync --repo .
```

## Customising it

Which actions count as sensitive is yours to set. What should not move is showing the resolved action rather than the templated one: `rm -rf $WORKDIR` is not a disclosure. If an action cannot be displayed legibly, shrink the action rather than the display.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals owasp-asi09-human-agent-trust
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`agentic-security/owasp-asi09-human-agent-trust/`](../../agentic-security/owasp-asi09-human-agent-trust/) · [all policies](../README.md)
