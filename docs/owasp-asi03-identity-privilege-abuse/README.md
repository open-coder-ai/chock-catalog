# OWASP ASI03 — Identity & Privilege Abuse

`owasp-asi03-identity-privilege-abuse` · rule · advises

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

Give each agent its own scoped, short-lived identity so a compromise does not inherit a human's or a shared account's full permissions. Use when an agent needs credentials, a service account, a cloud role, an API token, or when reviewing delegation and impersonation between an agent and its user. Do NOT use for keeping secrets out of the repository — that is `code-safety` and `scan-secrets`.

## What it solves

The personal access token lent to an agent "just to get it working", and the shared service account four agents authenticate with, which makes every action unattributable.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```
identity(per_agent): unique + short_lived + task_scoped; never: reuse(human_credential) | share(service_account) | issue(long_lived_broad_token)
review(agent_permissions) on(human_access_review_schedule); expire(credentials) automatically; see .agents/policies/owasp-asi03-identity-privilege-abuse/references/identity.md
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/owasp-asi03-identity-privilege-abuse/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add owasp-asi03-identity-privilege-abuse
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r agentic-security/owasp-asi03-identity-privilege-abuse  <your-repo>/.agents/policies/owasp-asi03-identity-privilege-abuse
cd <your-repo> && chock sync --repo .
```

## Customising it

TTLs should match your job durations rather than a round number. The clause not to weaken is scope intersection on delegation: an agent acting for a user must not exceed that user's own permissions, however broad the agent's own grant is.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals owasp-asi03-identity-privilege-abuse
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`agentic-security/owasp-asi03-identity-privilege-abuse/`](../../agentic-security/owasp-asi03-identity-privilege-abuse/) · [all policies](../README.md)
