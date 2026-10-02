---
name: block-curl-pipe-sh
description: "Best-effort: refuses curl/wget/lynx/aria2c/iwr/irm piped into sh/bash/zsh/dash/ksh/fish/python/perl/ruby/node (path-qualified, quoted, in a subshell, after bare sudo/env/xargs/nohup/timeout), bash -c \"$(curl ...)\", bash <(curl ...), `| iex`. Probed misses: fetch right after a quote (bash -c \"curl ...\", ssh), eval \"$(curl ...)\", source <(curl ...), wrapper options (sudo -u, env VAR=, /usr/bin/env), doas, csh/tcsh/mksh/lua/php/pwsh/deno/busybox, su -c, $SHELL, download then run. Friction only."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Curl-Pipe-Shell

Best-effort: refuses curl/wget/lynx/aria2c/iwr/irm piped into sh/bash/zsh/dash/ksh/fish/python/perl/ruby/node (path-qualified, quoted, in a subshell, after bare sudo/env/xargs/nohup/timeout), bash -c "$(curl ...)", bash <(curl ...), `| iex`. Probed misses: fetch right after a quote (bash -c "curl ...", ssh), eval "$(curl ...)", source <(curl ...), wrapper options (sudo -u, env VAR=, /usr/bin/env), doas, csh/tcsh/mksh/lua/php/pwsh/deno/busybox, su -c, $SHELL, download then run. Friction only.

```
block(remote_exec): fetch(curl|wget|iwr|irm) piped/substituted into interpreter(sh|bash|python|perl|node|iex)
allow: download_to_file, fetch|non_interpreter(jq|tar); prefer: curl -o file; read; run
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs. See https://github.com/open-coder-ai/chock
