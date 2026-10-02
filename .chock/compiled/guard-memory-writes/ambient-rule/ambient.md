<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/guard-memory-writes/) -->
```
on(commit|tool_use): block(script) script=guard-memory-writes-gate.py
Memory write refused: it pastes git history, a code block over 20 lines, a duplicate line, or a secret. Store the non-derivable fact in one short line; link to the commit or file instead of pasting it. Rotate any secret that was written.
```
<!-- chock:hooks:end -->
