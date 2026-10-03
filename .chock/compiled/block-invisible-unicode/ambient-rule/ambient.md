<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/block-invisible-unicode/) -->
```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+invisible-unicode content_pattern(regex)
Hidden Unicode detected in this change: a bidi control, a tag character, a word joiner, two invisible characters in a row, a zero-width character, joiner or filler beside ASCII, a BOM after the start of a line, a direction mark outside right-to-left text, a variation selector after ASCII, or a long private-use run. It changes how code reads to a human or hides instructions an agent will still obey. Remove it; where the character is meant, write it as an escape sequence instead. Waiver: 'pragma: allowlist invisible-unicode' on the same line. A person's commit honours it; in the agent (write, the turn's end, an agent's commit) only a line already in HEAD counts, and the MCP gateway never does. An agent asks a person; it never writes the pragma.
```
<!-- chock:hooks:end -->
