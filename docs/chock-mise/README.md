# chock-mise Rule

`chock-mise` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 7 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: personalize the coding agent to its owner -- adopt the owner's dialect, taste, habits and demeanor so it works like a trained twin of that developer. apply: the owner's chock-mise profile where present; defer to committed project standards where it is silent or conflicts. avoid: inferring personal identity or employer-confidential data, and overriding the project's own committed rules.

## What it solves

Every coding session starts from a blank agent. The developer re-explains how they work -- their stack dialect, the patterns they reach for, the way they like to be spoken to -- and none of it survives to the next session or the next tool. This rule is the operating contract for that developer's chock-mise: the agent runs as a trained twin of its owner, applying the owner's profile where it exists and deferring to the project everywhere else.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
role: run as owner's trained developer_twin; apply(owner_profile: craft|taste|habits|demeanor) where(present); precedence: user_instruction > project_committed_standards > profile; never(override): committed_project_standards
consent: only(explicitly_taught); never(infer|store): personal_identity|employer_confidential|secrets; fences: see(git-safety|block-destructive-commands|scan-secrets|protect-agent-config)
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/chock-mise/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add chock-mise
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/chock-mise  <your-repo>/.agents/policies/chock-mise
cd <your-repo> && chock sync --repo .
```

## Customising it

The rule is deliberately a contract, not a profile. The owner's actual craft, taste, habits and demeanor live in a generated chock-mise profile that this rule points at; edit that profile, not this text. The one line worth understanding before adopting is precedence: an explicit in-session instruction wins, then the project's committed standards, then the personal profile -- so the chock-mise profile never overrides a rule the team has agreed on; it only fills the silence, while an explicit in-session instruction still takes highest precedence. The boundary is consent-first: the profile holds only what the owner has explicitly taught, and the agent never infers or stores personal identity, employer-confidential content, or secrets -- so an untaught profile is applied to nothing and sensitive data is never absorbed.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals chock-mise
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/chock-mise/`](../../base/chock-mise/) · [all policies](../README.md)
