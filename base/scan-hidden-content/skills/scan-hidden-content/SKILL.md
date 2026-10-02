---
name: scan-hidden-content
description: "Warns (observe) when a change adds text a reader cannot see, or a URL that carries data out, to Markdown, HTML, SVG, XML, Word, agent instruction files, docs and templates: instruction-like or long comments, CSS-hidden, white or 1pt text, hidden Word runs, URLs with secret words, long queries, placeholders or encoded parts, remote embeds, camo runs, HTML data URIs. Runs: commit, agent write, turn's end. Waiver: a person's marker comment line above. Friction, not a boundary."
metadata:
  chock.artifact: hook
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Scan Hidden Content

Warns (observe) when a change adds text a reader cannot see, or a URL that carries data out, to Markdown, HTML, SVG, XML, Word, agent instruction files, docs and templates: instruction-like or long comments, CSS-hidden, white or 1pt text, hidden Word runs, URLs with secret words, long queries, placeholders or encoded parts, remote embeds, camo runs, HTML data URIs. Runs: commit, agent write, turn's end. Waiver: a person's marker comment line above. Friction, not a boundary.

```
on(commit|tool_use): warn(script) script=scan-hidden-content-gate.py
This change adds text a reader cannot see (a comment or hidden element that reads as an instruction, white or zero-size text) or a URL that can carry data out (a secret word or data-shaped part in its query or path, a remote embed, a dictionary of image URLs). Remove the hidden text or make it visible, and link only to fixed URLs that carry nothing from the repository or the session. A person may keep a reviewed line with a comment line just above it that holds only 'chock: allow scan-hidden-content', committed from their own shell; in the agent only a waiver already committed in HEAD counts, so an agent asks the person instead.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` warns at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
