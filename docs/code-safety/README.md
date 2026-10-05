# Code Safety Rule

`code-safety` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | advisory — advisory only: skill text, nothing stops a violation |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 4 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: secrets, eval/exec, unsanitized SQL, hallucinated dependencies. avoid: committing credentials, adding unverified packages, executing dynamic code. Install scan-secrets (commit, agent write) for secrets and verify-dependency-exists (opt-in; needs an allowlist) for dependencies. Advisory: eval/exec and SQL guidance; a gate decides only the non-literal slice (agentic-code-security code pack: Python eval/exec, SQL built from strings in Python and JS).

## What it solves

The four ways generated code becomes a liability: committed credentials, `eval`/`exec` on untrusted input, string-built SQL, and dependencies that do not exist. An agent proposes all four fluently and none of them look wrong in a diff.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
see(scan-secrets): commit|agent_write(secrets|keys|tokens|passwords|.env); see(verify-dependency-exists, opt_in): add(unlisted_dependency)
see(agentic-code-security pack code): refuses Python eval|exec of non-literal text and SQL built from strings (Python|JS); advisory: avoid(eval|exec|unsanitized_sql); on_find(secret|hallucinated_pkg): propose_removal_to_human
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/code-safety/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add code-safety
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/code-safety  <your-repo>/.agents/policies/code-safety
cd <your-repo> && chock sync --repo .
```

## Customising it

Add the patterns your language actually presents -- deserialization sinks, template injection, shell interpolation. This is advisory text, so being generous costs an agent's attention rather than a blocked commit.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals code-safety
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/code-safety/`](../../base/code-safety/) · [all policies](../README.md)
