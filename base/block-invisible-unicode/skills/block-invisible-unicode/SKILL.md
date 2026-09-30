---
name: block-invisible-unicode
description: "Blocks bidi override/embed/isolate controls (U+202A-202E, U+2066-2069; Trojan Source, CVE-2021-42574) and Unicode tag characters (U+E0001-E007F), which smuggle instructions. NOT matched: ZWSP U+200B, U+2060, U+FEFF, U+061C, variation selectors, ZWJ/ZWNJ, LRM/RLM. Runs: commit, agent write, turn's end. Waiver: 'pragma: allowlist invisible-unicode' same line. Person's commit: honoured. Agent: only if that line is already in HEAD; MCP gateway: never. Agent asks a person."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Bidi and Tag Unicode

Blocks bidi override/embed/isolate controls (U+202A-202E, U+2066-2069; Trojan Source, CVE-2021-42574) and Unicode tag characters (U+E0001-E007F), which smuggle instructions. NOT matched: ZWSP U+200B, U+2060, U+FEFF, U+061C, variation selectors, ZWJ/ZWNJ, LRM/RLM. Runs: commit, agent write, turn's end. Waiver: 'pragma: allowlist invisible-unicode' same line. Person's commit: honoured. Agent: only if that line is already in HEAD; MCP gateway: never. Agent asks a person.

```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+invisible-unicode ...
Bidi-control or Unicode tag characters detected in this change. They change how code reads to a human or hide instructions an agent will still obey. Remove them. Waiver: 'pragma: allowlist invisible-unicode' on the same line. A person's commit honours it; in the agent (write, the turn's end, an agent's commit) only a line already in HEAD counts, and the MCP gateway never does. An agent asks a person; it never writes the pragma.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
