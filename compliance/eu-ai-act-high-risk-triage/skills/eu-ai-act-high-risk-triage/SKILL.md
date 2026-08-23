---
name: eu-ai-act-high-risk-triage
description: "Flag when code puts an AI system into an EU AI Act Annex III high-risk domain \u2014 biometrics, critical infrastructure, education, employment, essential services and credit, law enforcement, migration, justice and elections \u2014 and require the Article 9-15 obligations be owned before the capability ships. Use when adding scoring, ranking, eligibility, or screening over people. Do NOT use for banned practices (see eu-ai-act-prohibited-practices) or for systems with no natural-person impact."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# EU AI Act — High-Risk Triage

Flag when code puts an AI system into an EU AI Act Annex III high-risk domain — biometrics, critical infrastructure, education, employment, essential services and credit, law enforcement, migration, justice and elections — and require the Article 9-15 obligations be owned before the capability ships. Use when adding scoring, ranking, eligibility, or screening over people. Do NOT use for banned practices (see eu-ai-act-prohibited-practices) or for systems with no natural-person impact.

```
on_touch(Annex III domain: biometrics|critical_infra|education|employment|essential_services|credit|insurance|law_enforcement|migration|justice|elections): flag + name(domain) + require owner for Art 9-15 (risk_mgmt, data_governance, tech_doc, logging, human_oversight, accuracy_robustness_cybersecurity)
never(silently add): high_risk capability; decision belongs to the repo owner; see .agents/policies/eu-ai-act-high-risk-triage/references/annex-iii.md
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
