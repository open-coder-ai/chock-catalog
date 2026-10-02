---
name: block-wildcard-iam
description: "Commit and agent-write gate, 1-line slice of ASI03: IAM Action or Resource set to a bare * (JSON double-quoted, YAML single-quoted), a one-element Terraform * list, the AdministratorAccess ARN, quoted GCP roles/owner or roles/editor. Probed misses: * in a JSON list, service wildcards (s3:*), YAML double-quoted or bare *, Terraform jsonencode, NotAction, Principal *, PowerUser, multi-line lists, Azure Owner, K8s RBAC. Waiver: 'pragma: allowlist broad-privilege' same line; agent: only if in HEAD."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Wildcard IAM

Commit and agent-write gate, 1-line slice of ASI03: IAM Action or Resource set to a bare * (JSON double-quoted, YAML single-quoted), a one-element Terraform * list, the AdministratorAccess ARN, quoted GCP roles/owner or roles/editor. Probed misses: * in a JSON list, service wildcards (s3:*), YAML double-quoted or bare *, Terraform jsonencode, NotAction, Principal *, PowerUser, multi-line lists, Azure Owner, K8s RBAC. Waiver: 'pragma: allowlist broad-privilege' same line; agent: only if in HEAD.

```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+broad-privilege content_pattern(regex)
Broad privilege grant detected. Scope Action and Resource to what the task needs, or a person adds 'pragma: allowlist broad-privilege' on the same line for a reviewed exception (in the agent it counts only when that exact line is already committed in HEAD, so an agent asks a person). Strict JSON cannot carry the pragma; narrow the grant or manage that document in Terraform/YAML.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
