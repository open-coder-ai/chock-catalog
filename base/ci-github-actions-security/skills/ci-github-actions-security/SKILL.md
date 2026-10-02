---
name: ci-github-actions-security
description: "Friction, not a security boundary: warns (observe) on GitHub Actions weaknesses a change adds to workflows, composite actions and dependabot.yml: event text in run/script, PR-head checkout under pull_request_target/workflow_run/issue_comment, missing or write-all permissions, secrets inherit or inlined, self-hosted runners on PRs, GITHUB_ENV writes, artifact and cache poisoning, agent steps on untrusted text. Misses: step outputs, composite internals, custom runner labels."
metadata:
  chock.artifact: hook
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# CI GitHub Actions Security

Friction, not a security boundary: warns (observe) on GitHub Actions weaknesses a change adds to workflows, composite actions and dependabot.yml: event text in run/script, PR-head checkout under pull_request_target/workflow_run/issue_comment, missing or write-all permissions, secrets inherit or inlined, self-hosted runners on PRs, GITHUB_ENV writes, artifact and cache poisoning, agent steps on untrusted text. Misses: step outputs, composite internals, custom runner labels.

```
on(commit|tool_use): warn(script) script=ci-github-actions-security-gate.py
A GitHub Actions workflow, composite action or Dependabot file gained a weakness (each finding names its rule, CWE and fix). Fix it as the finding says. A person who has reviewed one may keep it with '# chock: allow <rule id>' on that line and commit from their own shell; in the agent only a line already committed in HEAD counts, so an agent asks the person rather than writing the comment.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` warns at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
