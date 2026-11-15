---
name: iam-policy-scan
description: "Reads IAM, RBAC and role documents whole (JSON, YAML, Terraform, ARM, Bicep, k8s), not by line. Refuses Allow with Action star, an inverted key, a service wildcard or iam:PassRole on every resource; AdministratorAccess attached; public trust; cluster-admin; subscription Owner. Asks for write actions on every resource, cross-account trust. Only added grants. Misses computed grants, partial wildcards, GCP, Azure role definitions, k8s escalate/bind/anonymous. Waiver: pragma or sidecar."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# IAM Policy Scan

Reads IAM, RBAC and role documents whole (JSON, YAML, Terraform, ARM, Bicep, k8s), not by line. Refuses Allow with Action star, an inverted key, a service wildcard or iam:PassRole on every resource; AdministratorAccess attached; public trust; cluster-admin; subscription Owner. Asks for write actions on every resource, cross-account trust. Only added grants. Misses computed grants, partial wildcards, GCP, Azure role definitions, k8s escalate/bind/anonymous. Waiver: pragma or sidecar.

```
on(commit|tool_use): block(script) script=iam-policy-scan-gate.py
Broad IAM, RBAC or role grant added. Name the actions, resources and principals the task needs: no Action star, no service wildcard or iam:PassRole on every resource, no write actions on every resource, no AdministratorAccess attached, no Allow with NotAction, NotResource or NotPrincipal, no public principal without a Condition, no cluster-admin binding, no Owner or Contributor at subscription scope. A reviewed exception is a person's: a pragma comment 'pragma: allowlist broad-privilege' beside the grant (YAML, Terraform, Bicep), or an entry in .chock/iam-policy-scan.json for strict JSON, which cannot carry a comment. In the agent a waiver counts only once a person has committed it, so an agent asks a person.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
