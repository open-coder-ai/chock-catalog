---
name: scan-secrets
description: "Pre-commit hook that blocks commits of credential files and high-entropy secret values. Best-effort guard; not a replacement for a dedicated secret scanner."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Scan Secrets

Pre-commit hook that blocks commits of credential files and high-entropy secret values. Best-effort guard; not a replacement for a dedicated secret scanner.

```
on(commit): block(content_regex) scan=added_lines forbidden_path_regex=\.(env|pem|key|p12|pfx|jks|keystore)$ ...
Potential secret detected in staged changes. Remove credentials and rotate any exposed keys. Add '# pragma: allowlist secret' on the same line only for documented test fixtures.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
