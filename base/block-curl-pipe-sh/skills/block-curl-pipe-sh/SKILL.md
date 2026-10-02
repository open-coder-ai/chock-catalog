---
name: block-curl-pipe-sh
description: "Best-effort guard: refuses a download piped into a shell or interpreter (curl, wget, lynx, aria2c, iwr/irm into sh/bash/zsh/dash/ksh/fish/python/perl/ruby/node; bare, path-qualified or quoted; in a subshell or behind sudo/env/xargs/nohup/timeout), bash -c \"$(curl ...)\", bash <(curl ...), `| iex`. Probed misses: fetch inside a quoted command (bash -c \"...\", ssh host \"...\"), eval \"$(curl ...)\", source <(curl ...), pipe into php/pwsh/deno/busybox/su -c/$SHELL, download then run. Friction only."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Curl-Pipe-Shell

Best-effort guard: refuses a download piped into a shell or interpreter (curl, wget, lynx, aria2c, iwr/irm into sh/bash/zsh/dash/ksh/fish/python/perl/ruby/node; bare, path-qualified or quoted; in a subshell or behind sudo/env/xargs/nohup/timeout), bash -c "$(curl ...)", bash <(curl ...), `| iex`. Probed misses: fetch inside a quoted command (bash -c "...", ssh host "..."), eval "$(curl ...)", source <(curl ...), pipe into php/pwsh/deno/busybox/su -c/$SHELL, download then run. Friction only.

```
block(remote_exec): fetch(curl|wget|iwr|irm) piped/substituted into interpreter(sh|bash|python|perl|node|iex)
allow: download_to_file, fetch|non_interpreter(jq|tar); prefer: curl -o file; read; run
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs. See https://github.com/open-coder-ai/chock
