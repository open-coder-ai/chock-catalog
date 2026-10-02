---
name: block-wildcard-iam
description: "Pre-commit gate for the mechanizable slice of ASI03, one line at a time: a wildcard action, resource or principal in string or list form and either quote style (JSON, YAML, Terraform, CDK, escaped JSON), whole-service wildcards on s3, iam, sts, kms and ec2, Allow with an inverted action or resource key, administrator, power-user and IAM-admin managed policies, GCP owner and editor roles and public members, Kubernetes RBAC wildcards and cluster-admin bindings, Azure wildcard actions and Owner. A Deny written on one line passes. Friction, not a security boundary: grants split across lines, partial wildcards, YAML aliases or tags, unicode-escaped keys and runtime-built grants pass, and a Deny split across lines is still refused. Escape: 'pragma: allowlist broad-privilege' on the same line, honoured at commit; at agent tool-use it counts only when that exact line is already committed in HEAD."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Wildcard IAM

Pre-commit gate for the mechanizable slice of ASI03, one line at a time: a wildcard action, resource or principal in string or list form and either quote style (JSON, YAML, Terraform, CDK, escaped JSON), whole-service wildcards on s3, iam, sts, kms and ec2, Allow with an inverted action or resource key, administrator, power-user and IAM-admin managed policies, GCP owner and editor roles and public members, Kubernetes RBAC wildcards and cluster-admin bindings, Azure wildcard actions and Owner. A Deny written on one line passes. Friction, not a security boundary: grants split across lines, partial wildcards, YAML aliases or tags, unicode-escaped keys and runtime-built grants pass, and a Deny split across lines is still refused. Escape: 'pragma: allowlist broad-privilege' on the same line, honoured at commit; at agent tool-use it counts only when that exact line is already committed in HEAD.

```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+broad-privilege content_pattern(regex)
Broad privilege grant detected. Name the actions and resources the task needs (no wildcard action, resource or principal, no whole-service wildcard, no admin managed policy, owner role, public member or cluster-admin binding), or a person adds 'pragma: allowlist broad-privilege' on the same line for a reviewed exception (in the agent it counts only when that exact line is already committed in HEAD, so an agent asks a person). Strict JSON cannot carry the pragma; narrow the grant, or keep that document in Terraform/YAML.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
