---
name: block-curl-pipe-sh
description: "Best-effort guard against piping a network download straight into a shell or script interpreter: curl|wget|iwr ... | sh/bash/zsh/python/perl/ruby/node (bare or path-qualified, including subshell groups and sudo/exec/command/env wrappers), bash -c \"$(curl ...)\", bash <(curl ...), and the PowerShell iwr ... | iex form. Downloading to a file, or piping a fetch into a non-interpreter tool (jq, tar, grep), stays allowed. Known bypass classes include aliases, variable indirection, base64/obfuscated payloads, env-var-prefixed interpreters, and non-standard fetch clients. This is friction, not a security boundary."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Curl-Pipe-Shell

Best-effort guard against piping a network download straight into a shell or script interpreter: curl|wget|iwr ... | sh/bash/zsh/python/perl/ruby/node (bare or path-qualified, including subshell groups and sudo/exec/command/env wrappers), bash -c "$(curl ...)", bash <(curl ...), and the PowerShell iwr ... | iex form. Downloading to a file, or piping a fetch into a non-interpreter tool (jq, tar, grep), stays allowed. Known bypass classes include aliases, variable indirection, base64/obfuscated payloads, env-var-prefixed interpreters, and non-standard fetch clients. This is friction, not a security boundary.

```
block(remote_exec): fetch(curl|wget|iwr|irm) piped/substituted into interpreter(sh|bash|python|perl|node|iex)
allow: download_to_file, fetch|non_interpreter(jq|tar); prefer: curl -o file; read; run
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
