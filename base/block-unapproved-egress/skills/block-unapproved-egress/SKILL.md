---
name: block-unapproved-egress
description: "Best-effort guard on the tool channel: blocks sending data to a host outside the allowlist (.chock/egress-allowlist.txt, else a built-in registry list): curl/wget/iwr uploads, nc/socat/telnet, scp/rsync/sftp, ssh commands, aws/gsutil/az uploads, git push|remote add URLs, $(..)/$VAR in a URL or host. Asks on interpreter HTTP one-liners, gh gist/--body-file, curl --proxy/--resolve/Host:. Blocks ~/.curlrc writes. A floor, not a sandbox: other clients, runtimes, obfuscation."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Unapproved Egress

Best-effort guard on the tool channel: blocks sending data to a host outside the allowlist (.chock/egress-allowlist.txt, else a built-in registry list): curl/wget/iwr uploads, nc/socat/telnet, scp/rsync/sftp, ssh commands, aws/gsutil/az uploads, git push|remote add URLs, $(..)/$VAR in a URL or host. Asks on interpreter HTTP one-liners, gh gist/--body-file, curl --proxy/--resolve/Host:. Blocks ~/.curlrc writes. A floor, not a sandbox: other clients, runtimes, obfuscation.

```
block(egress): curl|wget|iwr upload, nc|socat|telnet, scp|rsync|sftp, ssh host cmd, aws s3|gsutil|az blob, git push|remote add <url> to host NOT in .chock/egress-allowlist.txt (default: registries); $(..)|$VAR in URL or hostname; write ~/.curlrc|~/.wgetrc; unusable allowlist file = refuse; curl -K refused
ask: interpreter HTTP one-liner, gh gist|--body-file, curl --proxy|--resolve|Host:. allow: GET, allowlisted host, git push origin; floor_not_sandbox; no pragma passes: ask_person
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs. See https://github.com/open-coder-ai/chock
