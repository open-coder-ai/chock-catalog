---
name: scan-secrets
description: "Blocks credentials: vendor key prefixes (AWS, GitHub, ...), JWTs, private-key blocks, key/token/password assignments; and whole files by path (.env*, *.pem|key|p12|pfx|jks|keystore). Runs: commit, agent write, turn's end. Not yet caught: quoted-colon forms (\"password\": \"...\", api_key: \"...\"), access_token=, client_secret=. Waiver: '# pragma: allowlist secret' same line (path hit: anywhere in the file). Person's commit: honoured. Agent: only if in HEAD; MCP gateway: never. Agent asks a person."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Scan Secrets

Blocks credentials: vendor key prefixes (AWS, GitHub, ...), JWTs, private-key blocks, key/token/password assignments; and whole files by path (.env*, *.pem|key|p12|pfx|jks|keystore). Runs: commit, agent write, turn's end. Not yet caught: quoted-colon forms ("password": "...", api_key: "..."), access_token=, client_secret=. Waiver: '# pragma: allowlist secret' same line (path hit: anywhere in the file). Person's commit: honoured. Agent: only if in HEAD; MCP gateway: never. Agent asks a person.

```
on(commit|tool_use): block(content_regex) scan=added_lines forbidden_path_regex=(\.env(\.(?!(sample|example|template|dist|def... ...
Potential secret detected in this change. Remove credentials and rotate any exposed keys. '# pragma: allowlist secret' on the same line marks a documented test fixture; in the agent (tool use, the turn's end) it counts only when that exact line is already committed in HEAD, so an agent asks a person rather than writing the pragma itself.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
