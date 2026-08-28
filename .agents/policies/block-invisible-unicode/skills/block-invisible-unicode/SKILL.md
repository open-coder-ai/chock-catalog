---
name: block-invisible-unicode
description: "The mechanizable slice of prompt-injection defense, enforced at two points: at commit (the git hook, over staged changes) and at agent tool-use (over a tool call's arguments, as the agent writes) -- invisible and direction-override Unicode. Bidi controls make code read differently than it parses (Trojan Source, CVE-2021-42574); Unicode tag-block characters smuggle instructions that are invisible to a human reviewer but fully legible to the agent reading the file. Zero-width joiners and bidi marks (ZWJ/ZWNJ/LRM/RLM) are deliberately NOT matched -- they are legitimate in emoji sequences and in Persian, Arabic and Indic text -- so ordinary internationalised content passes; only the override/embed/isolate controls and the tag block, which have no honest use in a source tree, are blocked. Escape: 'pragma: allowlist invisible-unicode' on the same line."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Invisible Unicode

The mechanizable slice of prompt-injection defense, enforced at two points: at commit (the git hook, over staged changes) and at agent tool-use (over a tool call's arguments, as the agent writes) -- invisible and direction-override Unicode. Bidi controls make code read differently than it parses (Trojan Source, CVE-2021-42574); Unicode tag-block characters smuggle instructions that are invisible to a human reviewer but fully legible to the agent reading the file. Zero-width joiners and bidi marks (ZWJ/ZWNJ/LRM/RLM) are deliberately NOT matched -- they are legitimate in emoji sequences and in Persian, Arabic and Indic text -- so ordinary internationalised content passes; only the override/embed/isolate controls and the tag block, which have no honest use in a source tree, are blocked. Escape: 'pragma: allowlist invisible-unicode' on the same line.

```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+invisible-unicode ...
Invisible or direction-override Unicode detected in this change. These characters change how code reads to a human or hide instructions an agent will still obey. Remove them. At commit, 'pragma: allowlist invisible-unicode' on the same line marks a documented exception (e.g. a test fixture); the pragma is NOT honored at tool-use, where the scanned text is a live tool argument an appended token could neutralize.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
