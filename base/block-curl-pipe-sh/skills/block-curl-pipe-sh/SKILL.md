---
name: block-curl-pipe-sh
description: "Best-effort guard on parsed commands: refuses a download wired into a shell or interpreter (sh..fish, python, perl, ruby, node, php, lua, pwsh, deno, bun, busybox, su, $SHELL, source, eval, iex) by pipe, substitution, here-string or process substitution, also inside bash -c/ssh/docker exec bodies, or downloaded and run in one command with no checksum or signature step. nc/socat/one-liner reads ask. Misses: aliases, functions, variables set outside the command, encoded text. Friction only."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Curl-Pipe-Shell

Best-effort guard on parsed commands: refuses a download wired into a shell or interpreter (sh..fish, python, perl, ruby, node, php, lua, pwsh, deno, bun, busybox, su, $SHELL, source, eval, iex) by pipe, substitution, here-string or process substitution, also inside bash -c/ssh/docker exec bodies, or downloaded and run in one command with no checksum or signature step. nc/socat/one-liner reads ask. Misses: aliases, functions, variables set outside the command, encoded text. Friction only.

```
block(remote_exec): fetch(curl|wget|iwr|irm) piped|substituted|here-string|run-after-download into interpreter(sh|bash|python|php|pwsh|source|eval|iex), quoted bodies too; ask: nc|socat|net one-liner
allow: download_to_file, fetch|non_interpreter(jq|tar|gpg), download+verify(sha256sum -c|gpg --verify)+run; prefer: curl -o file; read; verify; run
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs. See https://github.com/open-coder-ai/chock
