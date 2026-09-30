---
name: block-curl-pipe-sh
description: "Best-effort guard against piping a download into a shell or interpreter: curl, wget, lynx, aria2c, iwr/irm and similar fetchers piped into sh/bash/zsh/dash/ksh/fish/python/perl/ruby/node, bare, path-qualified or quoted, in a subshell group or behind sudo/exec/env/xargs/nohup/timeout; also bash -c \"$(curl ...)\", bash <(curl ...) and PowerShell `| iex`. Saving to a file, or piping into jq/tar/grep, is allowed. Bypasses: aliases, variables, obfuscation. Friction only."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Curl-Pipe-Shell

Best-effort guard against piping a download into a shell or interpreter: curl, wget, lynx, aria2c, iwr/irm and similar fetchers piped into sh/bash/zsh/dash/ksh/fish/python/perl/ruby/node, bare, path-qualified or quoted, in a subshell group or behind sudo/exec/env/xargs/nohup/timeout; also bash -c "$(curl ...)", bash <(curl ...) and PowerShell `| iex`. Saving to a file, or piping into jq/tar/grep, is allowed. Bypasses: aliases, variables, obfuscation. Friction only.

```
block(remote_exec): fetch(curl|wget|iwr|irm) piped/substituted into interpreter(sh|bash|python|perl|node|iex)
allow: download_to_file, fetch|non_interpreter(jq|tar); prefer: curl -o file; read; run
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
