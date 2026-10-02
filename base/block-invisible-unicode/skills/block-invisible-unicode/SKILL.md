---
name: block-invisible-unicode
description: "Blocks invisible Unicode in added lines: bidi controls (CVE-2021-42574), tag chars U+E0000-E007F, zero-width/joiners beside ASCII or in runs, mid-line BOM, variation-selector runs or after ASCII letters, private-use runs of 3+, noncharacters. Allows emoji ZWJ, RTL/Indic/Thai text, line-start BOM. Not caught: homoglyphs, LRM/RLM in prose, U+2028. Runs: commit, agent write, turn's end. Waiver: 'pragma: allowlist invisible-unicode' same line; agent: only if in HEAD; MCP gateway: never."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Invisible Unicode

Blocks invisible Unicode in added lines: bidi controls (CVE-2021-42574), tag chars U+E0000-E007F, zero-width/joiners beside ASCII or in runs, mid-line BOM, variation-selector runs or after ASCII letters, private-use runs of 3+, noncharacters. Allows emoji ZWJ, RTL/Indic/Thai text, line-start BOM. Not caught: homoglyphs, LRM/RLM in prose, U+2028. Runs: commit, agent write, turn's end. Waiver: 'pragma: allowlist invisible-unicode' same line; agent: only if in HEAD; MCP gateway: never.

```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+invisible-unicode content_pattern(regex)
Invisible or direction-changing Unicode detected in this change: a bidi control, a tag character, a zero-width character or joiner beside ASCII or in a run, a BOM after the start of a line, a variation-selector run, a private-use run or a noncharacter. It changes how code reads to a human or hides instructions an agent will still obey. Remove it; where the character is meant, write it as an escape sequence instead. Waiver: 'pragma: allowlist invisible-unicode' on the same line. A person's commit honours it; in the agent (write, the turn's end, an agent's commit) only a line already in HEAD counts, and the MCP gateway never does. An agent asks a person; it never writes the pragma.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
