---
name: block-wildcard-iam
description: "Pre-commit gate for the mechanizable slice of ASI03: wildcard Action or Resource in IAM policy documents, AdministratorAccess attachment, GCP roles/owner or roles/editor, and Terraform wildcard action/resource lists. An agent's identity design stays with the advisory owasp-asi03 policy; this blocks the grants whose blast radius is everything. Escape: 'pragma: allowlist broad-privilege' on the same line."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Wildcard IAM

Pre-commit gate for the mechanizable slice of ASI03: wildcard Action or Resource in IAM policy documents, AdministratorAccess attachment, GCP roles/owner or roles/editor, and Terraform wildcard action/resource lists. An agent's identity design stays with the advisory owasp-asi03 policy; this blocks the grants whose blast radius is everything. Escape: 'pragma: allowlist broad-privilege' on the same line.

```
on(commit): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+broad-privilege ...
Broad privilege grant detected. Scope Action and Resource to what the task needs, or add 'pragma: allowlist broad-privilege' on the same line for a reviewed exception. Strict JSON cannot carry the pragma; narrow the grant or manage that document in Terraform/YAML.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
