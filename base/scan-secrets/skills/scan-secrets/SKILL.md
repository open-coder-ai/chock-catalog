---
name: scan-secrets
description: "Blocks credentials: vendor tokens (AWS, GitHub, GitLab, Slack, OpenAI, HF, ...), JWTs, private-key and PGP blocks, named key/token/secret/password values (JSON, YAML, env, HCL, code), URI creds, Authorization literals, Azure storage keys and SAS signatures, CLI password flags; files by path (.env*, .p12, .pfx, .jks, .keystore). Allows AWS's documented example keys and a command password beside a loopback host. Misses: split or encoded values, a value split across lines, a password flag of a tool not listed, a quote escaped twice, quoted values with spaces, unlisted names, a key file (.pem, .key) with no header line, reference-, placeholder- or expression-like values (a call, a subscript, a member chain, a lower-case dotted passphrase). Runs: commit, agent write, turn end. Pragma same line; agent: only if in HEAD; MCP gateway: never."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Scan Secrets

Blocks credentials: vendor tokens (AWS, GitHub, GitLab, Slack, OpenAI, HF, ...), JWTs, private-key and PGP blocks, named key/token/secret/password values (JSON, YAML, env, HCL, code), URI creds, Authorization literals, Azure storage keys and SAS signatures, CLI password flags; files by path (.env*, .p12, .pfx, .jks, .keystore). Allows AWS's documented example keys and a command password beside a loopback host. Misses: split or encoded values, a value split across lines, a password flag of a tool not listed, a quote escaped twice, quoted values with spaces, unlisted names, a key file (.pem, .key) with no header line, reference-, placeholder- or expression-like values (a call, a subscript, a member chain, a lower-case dotted passphrase). Runs: commit, agent write, turn end. Pragma same line; agent: only if in HEAD; MCP gateway: never.

```
on(commit|tool_use): block(content_regex) scan=added_lines forbidden_path_regex(regex) allowlist_pragma=#\s*pragma:\s*allowlist\s+secret content_pattern(regex)
Potential secret detected in this change. Remove credentials and rotate any exposed keys. '# pragma: allowlist secret' on the same line marks a documented test fixture; in the agent (tool use, the turn's end) it counts only when that exact line is already committed in HEAD, so an agent asks a person rather than writing the pragma itself.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
