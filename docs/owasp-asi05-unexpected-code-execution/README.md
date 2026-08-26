# OWASP ASI05 — Unexpected Code Execution

`owasp-asi05-unexpected-code-execution` · rule · advises

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

Contain code an agent generates or is induced to run. Execute in a sandboxed container with least privilege and deny-by-default egress, prefer parameterised APIs over raw shell, and treat any string reaching a subprocess or interpreter as attacker-controlled. Use when adding a code interpreter, shell tool, subprocess call, or eval-style API to an agent. Do NOT use for eval/exec appearing in ordinary application code — that is `code-safety`.

## What it solves

Model output reaching an interpreter. Usually not through a dramatic sandbox escape but through an f-string, a subprocess with `shell=True`, or a sandbox that inherited the orchestrator's environment variables and therefore all its credentials.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
run(agent_generated_code): container(least_privilege) + egress(deny_by_default) + filesystem(scoped) + timeout; never(host_execution)
never(pass): untrusted_string -> shell | eval | interpreter | deserializer; prefer(parameterized_api) over(raw_shell); see .agents/policies/owasp-asi05-unexpected-code-execution/references/code-execution.md
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/owasp-asi05-unexpected-code-execution/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add owasp-asi05-unexpected-code-execution
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r agentic-security/owasp-asi05-unexpected-code-execution  <your-repo>/.agents/policies/owasp-asi05-unexpected-code-execution
cd <your-repo> && chock sync --repo .
```

## Customising it

Egress allowlists are the expected local edit. The two lines to leave alone are secrets never mounted into the execution sandbox, and no untrusted string reaching a shell. If you have no sandbox, the honest change is to remove the interpreter, not to relax this.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals owasp-asi05-unexpected-code-execution
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`agentic-security/owasp-asi05-unexpected-code-execution/`](../../agentic-security/owasp-asi05-unexpected-code-execution/) · [all policies](../README.md)
