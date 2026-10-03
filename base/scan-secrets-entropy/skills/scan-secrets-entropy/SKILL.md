---
name: scan-secrets-entropy
description: "Friction, not a security boundary: flags secrets scan-secrets misses -- high-entropy values (16-150 chars) by secret-like keys, GitHub/npm tokens with valid checksums, Stripe test keys, Slack/AWS key-id shapes, Luhn-valid cards. Warns only (observe). Misses: values split across lines, over 150 chars, cut by # or & when unquoted, under other key names, written like code (a.b(), ALL_CAPS, words, URLs, paths), wrapped in a call, parens or concatenation, in XML, or padded with control characters."
metadata:
  chock.artifact: hook
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Scan Secrets Entropy

Friction, not a security boundary: flags secrets scan-secrets misses -- high-entropy values (16-150 chars) by secret-like keys, GitHub/npm tokens with valid checksums, Stripe test keys, Slack/AWS key-id shapes, Luhn-valid cards. Warns only (observe). Misses: values split across lines, over 150 chars, cut by # or & when unquoted, under other key names, written like code (a.b(), ALL_CAPS, words, URLs, paths), wrapped in a call, parens or concatenation, in XML, or padded with control characters.

```
on(commit|tool_use): warn(script) script=scan-secrets-entropy-gate.py
Possible secret: a high-entropy value assigned to a secret-like key, a vendor token whose structure checks out, or a card number. Move it to an environment variable or a secret store and reference it; rotate it if it was ever real. A person who has checked a test value keeps it with 'pragma: allowlist secret' on the same line (a person's commit, push or CI honours it; in the agent only a line already in HEAD counts). An agent asks a person; it never writes the pragma.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` warns at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
