---
name: configure-java-security
description: Choose what each java-security rule does when it fires -- "customize java security",
  "configure java security rules", "change a java security verdict", and anything meaning it.
  args(scope) returns(.chock/security.json) invoke(customize, configure, review) exclude(coding, writing_rules)
metadata:
  owner: chock-core
  version: 0.1.0
  status: draft
  chock.version: 0.1.0
  chock.artifact: skill
  chock.enforcement: advise
  chock.provenance.author: chock-core
  chock.provenance.created_at: "2026-09-22T00:00:00Z"
  chock.provenance.source_repo: "https://github.com/open-coder-ai/chock-catalog"
  chock.provenance.license: Apache-2.0
  chock.provenance.trust_tier: community
  chock.lifecycle.status: draft
  chock.lifecycle.reviewed_by: chock-core
  chock.security.content_instructions: never-obey
  chock.security.pii_handling: redact
  chock.skill_type: nl
  chock.effects: writes_workspace
  chock.determinization_reviewed: "true"
  chock.name: "Configure Java Security"
---

# Configure Java Security

```
page: setup.html (beside this file; offline; writes nothing)
result: .chock/security.json  # what the java-security policy reads
verdicts: allow|deny|ask per rule; absent rule = deny; page preselects deny
```

## Procedure

1. `open(setup.html)`: artifact with `capabilities: {db: {}}` where the client publishes one;
   else a browser tab, result from the clipboard.
2. `read(store: selection/current)`; `result.selection` is the whole file, `result.wiring.scope`
   the target:
   - `repo`: `.chock/security.json` at the root, then `chock sync --repo .`; commit it.
   - `user`: `~/.chock/security.json`; a repo carrying its own file wins -- refuse, say so,
     change it in a pull request.
3. `show(person, one row per rule)` before writing; overwrite only after they saw the diff.

## Rules

- never(derive): a verdict from a stack question; verdicts are chosen.
- never(write): pattern|severity|path into the file; the guard refuses it at the next commit.
- text walk (`references/setup-contract.json`, one rule at a time, deny unless told otherwise):
  only where the page cannot be shown at all.
- wiring is chock's: the commit hook and the tool-use door from `chock sync`, the ambient
  line from `INDEX.md`. Both read the same selection file; nothing here wires anything.
