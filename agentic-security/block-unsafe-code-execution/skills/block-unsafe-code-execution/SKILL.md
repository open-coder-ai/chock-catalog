---
name: block-unsafe-code-execution
description: "Pre-commit gate for the mechanizable slice of ASI05: bare eval/exec, shell-mode subprocess calls, os.system, pickle/marshal loads, yaml.load without SafeLoader, execSync, new Function. Best-effort line scan; sandbox design, egress, and inherited credentials stay with the advisory owasp-asi05 policy. Escape hatch for vetted uses: 'pragma: allowlist exec' on the same line, honoured at commit; at agent tool-use it counts only for a line already committed in HEAD."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Unsafe Code Execution

Pre-commit gate for the mechanizable slice of ASI05: bare eval/exec, shell-mode subprocess calls, os.system, pickle/marshal loads, yaml.load without SafeLoader, execSync, new Function. Best-effort line scan; sandbox design, egress, and inherited credentials stay with the advisory owasp-asi05 policy. Escape hatch for vetted uses: 'pragma: allowlist exec' on the same line, honoured at commit; at agent tool-use it counts only for a line already committed in HEAD.

```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+exec content_pattern(regex)
Dynamic execution primitive detected. Replace it with a parameterized API (subprocess argument vector, safe_load, a real parser), or have a person add 'pragma: allowlist exec' on the same line for a reviewed, deliberate use (in the agent it counts only when that exact line is already committed in HEAD).
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
