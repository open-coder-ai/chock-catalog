---
name: block-invisible-unicode
description: "Blocks hidden Unicode in added lines: bidi, tag and plane-14 chars, word joiner, chained invisibles, zero-width/joiners/fillers by ASCII, mid-line BOM, LRM/RLM outside RTL text, selectors after ASCII, private-use runs of 16+. Allows emoji, RTL/Indic/Thai/CJK text, line-start BOM. Not caught: homoglyphs, a joiner between non-ASCII, binary files and text after U+2028 at commit. Runs: commit, agent write, turn's end. Waiver: 'pragma: allowlist invisible-unicode' same line; agent: HEAD only."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Invisible Unicode

Blocks hidden Unicode in added lines: bidi, tag and plane-14 chars, word joiner, chained invisibles, zero-width/joiners/fillers by ASCII, mid-line BOM, LRM/RLM outside RTL text, selectors after ASCII, private-use runs of 16+. Allows emoji, RTL/Indic/Thai/CJK text, line-start BOM. Not caught: homoglyphs, a joiner between non-ASCII, binary files and text after U+2028 at commit. Runs: commit, agent write, turn's end. Waiver: 'pragma: allowlist invisible-unicode' same line; agent: HEAD only.

```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+invisible-unicode content_pattern(regex)
Hidden Unicode detected in this change: a bidi control, a tag character, a word joiner, two invisible characters in a row, a zero-width character, joiner or filler beside ASCII, a BOM after the start of a line, a direction mark outside right-to-left text, a variation selector after ASCII, or a long private-use run. It changes how code reads to a human or hides instructions an agent will still obey. Remove it; where the character is meant, write it as an escape sequence instead. Waiver: 'pragma: allowlist invisible-unicode' on the same line. A person's commit honours it; in the agent (write, the turn's end, an agent's commit) only a line already in HEAD counts, and the MCP gateway never does. An agent asks a person; it never writes the pragma.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
