---
name: scan-secrets
description: "Blocks credentials: vendor token shapes (AWS, GitHub, GitLab, Slack, OpenAI, Hugging Face, ...), JWTs, private-key and PGP blocks, key/token/secret/password values in code, JSON, YAML, .env and HCL, URI credentials, Authorization literals, CLI password flags; files by path (.env*, keys). Misses: values split over lines or encoded, digitless bare values, values shaped like references or placeholders. Pragma '# pragma: allowlist secret' same line; agent: only if in HEAD."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Scan Secrets

Blocks credentials: vendor token shapes (AWS, GitHub, GitLab, Slack, OpenAI, Hugging Face, ...), JWTs, private-key and PGP blocks, key/token/secret/password values in code, JSON, YAML, .env and HCL, URI credentials, Authorization literals, CLI password flags; files by path (.env*, keys). Misses: values split over lines or encoded, digitless bare values, values shaped like references or placeholders. Pragma '# pragma: allowlist secret' same line; agent: only if in HEAD.

```
on(commit|tool_use): block(content_regex) scan=added_lines forbidden_path_regex(regex) allowlist_pragma=#\s*pragma:\s*allowlist\s+secret content_pattern(regex)
Potential secret detected in this change. Remove credentials and rotate any exposed keys. '# pragma: allowlist secret' on the same line marks a documented test fixture; in the agent (tool use, the turn's end) it counts only when that exact line is already committed in HEAD, so an agent asks a person rather than writing the pragma itself.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
