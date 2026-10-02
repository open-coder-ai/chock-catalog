---
name: block-unsafe-code-execution
description: "Commit and agent-write gate, greppable slice of ASI05: bare, global-receiver and indirect eval/exec forms, the Function constructor, string timers, exec-mode compile, import by computed name, shell-mode and implicit-shell process APIs, unsafe deserializers (pickle family, unsafe yaml loaders, model loads) and shell eval of a variable. File-type-blind line scan: friction, not a security boundary. Waiver 'pragma: allowlist exec' on the line; in the agent only if already committed in HEAD."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Unsafe Code Execution

Commit and agent-write gate, greppable slice of ASI05: bare, global-receiver and indirect eval/exec forms, the Function constructor, string timers, exec-mode compile, import by computed name, shell-mode and implicit-shell process APIs, unsafe deserializers (pickle family, unsafe yaml loaders, model loads) and shell eval of a variable. File-type-blind line scan: friction, not a security boundary. Waiver 'pragma: allowlist exec' on the line; in the agent only if already committed in HEAD.

```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+exec content_pattern(regex)
Dynamic execution primitive detected. Replace it with a parameterized API (a subprocess argument vector without a shell, execFile/spawn without the shell option, yaml.safe_load, torch load with weights_only, a real parser or an explicit dispatch table), or have a person add 'pragma: allowlist exec' on the same line for a reviewed, deliberate use (in the agent it counts only when that exact line is already committed in HEAD).
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
