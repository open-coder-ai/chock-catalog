# OWASP Agentic Security coverage, in full

The README's [OWASP ASI01–10 coverage](../README.md#the-policies) `<details>` gives the
table and the headline numbers. This is the section it was condensed from, verbatim —
how the coverage claim is re-derived and what it does and doesn't mean.

## OWASP Agentic Security coverage — scored by the tool, not the README

The [`agentic-security/`](../agentic-security/) tree covers **every control in the OWASP Top 10
for Agentic Applications** (ASI01–ASI10): **10/10 controls covered · 0 fully covered.**

That number is not written here by hand. CI re-derives it on every build: the staged adopter
repo installs every published policy and runs the same command you can —

```bash
chock init . && chock add owasp-asi01-agent-goal-hijack   # ... through asi10
chock compliance report --framework owasp_asi
```

The same report also speaks `mitre_atlas`, `nist_ai_rmf` and `eu_ai_act` — policies here
claim technique- and article-level controls, and every claim is `partial` with a note
saying exactly what the mechanism reaches.

— and the build fails if any control reads `uncovered`. Every row reads `partial`, because
most of the pack is advisory (rules and skills the agent reads) rather than deterministic
gates, and this tool refuses to label advisory coverage as more than it is. 3 hard guards
(`block-unsafe-code-execution`, `block-wildcard-iam`, `block-unpinned-agent-components`)
upgrade specific attack classes to commit-time enforcement. `full` means runtime enforcement,
and rows will only say it when that mechanism exists — the report prints every gap precisely
so nobody has to take our word for anything.
