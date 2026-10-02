---
name: block-fetch-exec-in-files
description: "Warns (observe rollout) when a line added to a script, Dockerfile, Makefile, CI workflow or package.json wires a download into a code runner: curl/wget/aria2c/lynx/iwr/irm piped into a shell, python/perl/ruby/node/php/lua on stdin, pwsh or iex; bash -c, eval, source or a here-string of a $(...) or <(...) download; Dockerfile ADD of a URL without --checksum. One line at a time: continuation lines, variables, unicode-escaped JSON, split or quoted command names, a download saved to a file and run on a later step, and interpreters or fetchers outside the lists are missed. Never refuses. Friction only."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Flag Fetch-Exec in Files

Warns (observe rollout) when a line added to a script, Dockerfile, Makefile, CI workflow or package.json wires a download into a code runner: curl/wget/aria2c/lynx/iwr/irm piped into a shell, python/perl/ruby/node/php/lua on stdin, pwsh or iex; bash -c, eval, source or a here-string of a $(...) or <(...) download; Dockerfile ADD of a URL without --checksum. One line at a time: continuation lines, variables, unicode-escaped JSON, split or quoted command names, a download saved to a file and run on a later step, and interpreters or fetchers outside the lists are missed. Never refuses. Friction only.

```
flag(fetch_exec_in_file): added line wires a downloader (curl, wget, iwr, irm) into a shell or interpreter by pipe, $(..), <(..) or here-string; Dockerfile ADD <url> without --checksum
prefer: download to a file, verify (sha256sum -c, gpg --verify, ADD --checksum=sha256:...), then run; waiver: same-line pragma, person only
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` warns at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
