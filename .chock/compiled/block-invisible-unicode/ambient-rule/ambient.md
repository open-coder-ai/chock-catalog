<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/block-invisible-unicode/) -->
```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+invisible-unicode ...
Bidi-control or Unicode tag characters detected in this change. They change how code reads to a human or hide instructions an agent will still obey. Remove them. Waiver: 'pragma: allowlist invisible-unicode' on the same line. A person's commit honours it; in the agent (write, the turn's end, an agent's commit) only a line already in HEAD counts, and the MCP gateway never does. An agent asks a person; it never writes the pragma.
```
<!-- chock:hooks:end -->
