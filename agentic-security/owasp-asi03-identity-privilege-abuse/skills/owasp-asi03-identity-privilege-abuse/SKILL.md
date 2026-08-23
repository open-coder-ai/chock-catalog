---
name: owasp-asi03-identity-privilege-abuse
description: "Give each agent its own scoped, short-lived identity so a compromise does not inherit a human's or a shared account's full permissions. Use when an agent needs credentials, a service account, a cloud role, an API token, or when reviewing delegation and impersonation between an agent and its user. Do NOT use for keeping secrets out of the repository \u2014 that is `code-safety` and `scan-secrets`."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# OWASP ASI03 — Identity & Privilege Abuse

Give each agent its own scoped, short-lived identity so a compromise does not inherit a human's or a shared account's full permissions. Use when an agent needs credentials, a service account, a cloud role, an API token, or when reviewing delegation and impersonation between an agent and its user. Do NOT use for keeping secrets out of the repository — that is `code-safety` and `scan-secrets`.

```
identity(per_agent): unique + short_lived + task_scoped; never: reuse(human_credential) | share(service_account) | issue(long_lived_broad_token)
review(agent_permissions) on(human_access_review_schedule); expire(credentials) automatically; see .agents/policies/owasp-asi03-identity-privilege-abuse/references/identity.md
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
