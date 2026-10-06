# EU AI Act — High-Risk Triage

`eu-ai-act-high-risk-triage` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | warns — warns on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | warn-only `content_regex` gate |
| **Reaches** | `advisory` — the gate runs and prints its findings; it never refuses |
| **Compiles to** | `git-hook`, `ci-gate`, `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 11 total, 4 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns when code puts an AI system into an EU AI Act Annex III high-risk domain — biometrics, critical infrastructure, education, employment, essential services and credit, law enforcement, migration, justice and elections — and asks for an owner of the Article 9-15 obligations before the capability ships. Use when adding scoring, ranking, eligibility, or screening over people. Do NOT use for banned practices (see eu-ai-act-prohibited-practices) or for systems with no natural-person impact.

## What it solves

A ranking or eligibility model that lands in an Annex III domain -- hiring, credit, education, benefits -- without anyone deciding it had. Article 12 logging and Article 14 human oversight are cheap to design in and expensive to retrofit, and the Digital AI Omnibus deferral to December 2027 reads as permission to skip them rather than as more time to do them properly.

## How it works

A `content_regex` gate runs on `commit` and `tool_use` and only warns: its action is `warn`, so it prints its findings and never refuses. It does not enforce anything, so the policy counts as advisory.

On a finding it prints:

> Possible EU AI Act Annex III high-risk domain (scoring, ranking or screening of people). Name the domain and the provider or deployer role, and get an owner for Articles 9-15 before this ships. This only flags: the domain call is the repo owner's.

The rule text ships alongside, in the agent's ambient context:

```text
on_touch(Annex III domain: biometrics|critical_infra|education|employment|essential_services|credit|insurance|law_enforcement|migration|justice|elections): flag + name(domain) + require owner for Art 9-15 (risk_mgmt, data_governance, tech_doc, logging, human_oversight, accuracy_robustness_cybersecurity)
never(silently add): high_risk capability; decision belongs to the repo owner; see .agents/policies/eu-ai-act-high-risk-triage/references/annex-iii.md
```

## Which primitive it becomes

A **warn-only gate**. `recompile` writes it under `.chock/compiled/eu-ai-act-high-risk-triage/` for each surface its `on` names (the git hook, CI, the agent's write path) beside the ambient rule. It runs and prints, but its exit never refuses a commit or a write.

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
