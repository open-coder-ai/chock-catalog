---
name: New policy proposal
about: Propose a policy for the catalog
labels: proposal
---

**What must always or never happen:**

**Can it be deterministic?** A policy that exits non-zero is a control; one that does not is
advice. Both are welcome — the catalog ships seven advisory policies — but the answer decides
how it is labelled.

- [ ] Expressible as a gate (`content_regex`, `forbidden_ref`, `dependency_allowlist`)
- [ ] Expressible as a guard script consulted before a command runs
- [ ] Advisory only — rule text compiled into agent context

**Can it be satisfied?** Describe the change that makes a blocked commit pass.

**Adversarial cases** — how would someone get past it by accident?
