# EU AI Act — High-Risk Triage

`eu-ai-act-high-risk-triage` · rule · advises

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

Flag when code puts an AI system into an EU AI Act Annex III high-risk domain — biometrics, critical infrastructure, education, employment, essential services and credit, law enforcement, migration, justice and elections — and require the Article 9-15 obligations be owned before the capability ships. Use when adding scoring, ranking, eligibility, or screening over people. Do NOT use for banned practices (see eu-ai-act-prohibited-practices) or for systems with no natural-person impact.

## What it solves

A ranking or eligibility model that lands in an Annex III domain -- hiring, credit, education, benefits -- without anyone deciding it had. Article 12 logging and Article 14 human oversight are cheap to design in and expensive to retrofit, and the Digital AI Omnibus deferral to December 2027 reads as permission to skip them rather than as more time to do them properly.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
on_touch(Annex III domain: biometrics|critical_infra|education|employment|essential_services|credit|insurance|law_enforcement|migration|justice|elections): flag + name(domain) + require owner for Art 9-15 (risk_mgmt, data_governance, tech_doc, logging, human_oversight, accuracy_robustness_cybersecurity)
never(silently add): high_risk capability; decision belongs to the repo owner; see .agents/policies/eu-ai-act-high-risk-triage/references/annex-iii.md
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/eu-ai-act-high-risk-triage/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add eu-ai-act-high-risk-triage
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r compliance/eu-ai-act-high-risk-triage  <your-repo>/.agents/policies/eu-ai-act-high-risk-triage
cd <your-repo> && chock sync --repo .
```

## Customising it

The domain list is the trigger surface and it is deliberately broad; narrow it to the domains your product can actually reach so the flag stays meaningful. What should not be softened is the escalation: the Article 6(3) derogation requires a documented assessment, and an agent that asserts it on its own has made the compliance decision for you.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals eu-ai-act-high-risk-triage
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`compliance/eu-ai-act-high-risk-triage/`](../../compliance/eu-ai-act-high-risk-triage/) · [all policies](../README.md)
