<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/block-curl-pipe-sh/) -->
```
block(remote_exec): fetch(curl|wget|iwr|irm|ssh_host_cmd|scp|rsync|aws_s3_cp to_stdout) piped|substituted|here-string|run-after-download into interpreter(sh|bash|python|php|pwsh|source|eval|iex), quoted bodies too; ask: nc|socat|net one-liner
allow: download_to_file, fetch|non_interpreter(jq|tar|gpg), download+verify(sha256sum -c|gpg --verify)+run; prefer: curl -o file; read; verify; run
```
<!-- chock:hooks:end -->
