---
name: block-curl-pipe-sh
description: "Best-effort guard: refuses a download (curl, wget, iwr; ssh host cmd, scp/rsync/aws s3 cp to stdout) wired into a shell or interpreter (sh..fish, python, perl, ruby, node, php, lua, pwsh, deno, bun, su, source, eval, iex) by pipe, substitution or here-string, also inside bash -c/ssh/docker exec bodies, or downloaded then run with no checksum or signature step. nc/socat/one-liner reads ask. Misses: aliases, functions, outside variables, encoded text, renamed downloads. Friction only."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Curl-Pipe-Shell

Best-effort guard: refuses a download (curl, wget, iwr; ssh host cmd, scp/rsync/aws s3 cp to stdout) wired into a shell or interpreter (sh..fish, python, perl, ruby, node, php, lua, pwsh, deno, bun, su, source, eval, iex) by pipe, substitution or here-string, also inside bash -c/ssh/docker exec bodies, or downloaded then run with no checksum or signature step. nc/socat/one-liner reads ask. Misses: aliases, functions, outside variables, encoded text, renamed downloads. Friction only.

```
block(remote_exec): fetch(curl|wget|iwr|irm|ssh_host_cmd|scp|rsync|aws_s3_cp to_stdout) piped|substituted|here-string|run-after-download into interpreter(sh|bash|python|php|pwsh|source|eval|iex), quoted bodies too; ask: nc|socat|net one-liner
allow: download_to_file, fetch|non_interpreter(jq|tar|gpg), download+verify(sha256sum -c|gpg --verify)+run; prefer: curl -o file; read; verify; run
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs. See https://github.com/open-coder-ai/chock
