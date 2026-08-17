---
name: block-unsafe-code-execution
description: "Pre-commit gate for the mechanizable slice of ASI05: bare eval/exec, shell-mode subprocess calls, os.system, pickle/marshal loads, yaml.load without SafeLoader, execSync, new Function. Best-effort line scan; sandbox design, egress, and inherited credentials stay with the advisory owasp-asi05 policy. Escape hatch for vetted uses: 'pragma: allowlist exec' on the same line."
metadata:
  chock:
    artifact: hook
    enforcement: block
    coverage_without_chock: advisory
---

# Block Unsafe Code Execution

Pre-commit gate for the mechanizable slice of ASI05: bare eval/exec, shell-mode subprocess calls, os.system, pickle/marshal loads, yaml.load without SafeLoader, execSync, new Function. Best-effort line scan; sandbox design, egress, and inherited credentials stay with the advisory owasp-asi05 policy. Escape hatch for vetted uses: 'pragma: allowlist exec' on the same line.

```
on(commit): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+exec ...
Dynamic execution primitive detected. Replace it with a parameterized API (subprocess argument vector, safe_load, a real parser), or add 'pragma: allowlist exec' on the same line for a reviewed, deliberate use.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
