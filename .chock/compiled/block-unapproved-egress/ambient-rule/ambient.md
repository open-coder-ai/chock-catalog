<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/block-unapproved-egress/) -->
```
block(egress): curl|wget|iwr upload, nc|socat|telnet, scp|rsync|sftp, ssh host cmd, aws s3|gsutil|az blob, git push|remote add <url> to host NOT in .chock/egress-allowlist.txt (default: registries); $(..)|$VAR in URL or hostname; write ~/.curlrc|~/.wgetrc; unusable allowlist file = refuse; curl -K refused
ask: interpreter HTTP one-liner, gh gist|--body-file, curl --proxy|--resolve|Host:. allow: GET, allowlisted host, git push origin; floor_not_sandbox; no pragma passes: ask_person
```
<!-- chock:hooks:end -->
