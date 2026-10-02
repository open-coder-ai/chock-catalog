---
name: iam-policy-scan
description: "Reads whole IAM, RBAC and role documents, not lines: JSON, YAML, Terraform, ARM, Bicep, Kubernetes. Refuses Allow with Action star or an inverted key, public or any-principal trust, cluster-admin, subscription Owner. Asks for service wildcards on a named resource and cross-account trust. Only added grants. Misses computed grants (concat, for, locals), services beyond s3/iam/sts/kms/ec2, templated YAML that will not parse, unlisted file extensions. Waiver: pragma, or .chock/iam-policy-scan.json."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# IAM Policy Scan

Reads whole IAM, RBAC and role documents, not lines: JSON, YAML, Terraform, ARM, Bicep, Kubernetes. Refuses Allow with Action star or an inverted key, public or any-principal trust, cluster-admin, subscription Owner. Asks for service wildcards on a named resource and cross-account trust. Only added grants. Misses computed grants (concat, for, locals), services beyond s3/iam/sts/kms/ec2, templated YAML that will not parse, unlisted file extensions. Waiver: pragma, or .chock/iam-policy-scan.json.

```
on(commit|tool_use): block(script) script=iam-policy-scan-gate.py
Broad IAM, RBAC or role grant added. Name the actions, resources and principals the task needs: no Action star, no Allow with NotAction, NotResource or NotPrincipal, no public principal without a Condition, no cluster-admin binding, no Owner or Contributor at subscription scope. A reviewed exception is a person's: a pragma comment 'pragma: allowlist broad-privilege' beside the grant (YAML, Terraform, Bicep), or an entry in .chock/iam-policy-scan.json for strict JSON, which cannot carry a comment. In the agent a waiver counts only once a person has committed it, so an agent asks a person.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
