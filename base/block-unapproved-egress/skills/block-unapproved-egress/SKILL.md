---
name: block-unapproved-egress
description: "Best-effort guard on the tool channel: curl, wget or iwr/irm (Invoke-WebRequest/RestMethod) that UPLOADS (POST/PUT/PATCH, -d/--data*/--json, -F/--form, -T/--upload-file, wget --post-*/--body-*, -Body/-InFile/-Form) to a host outside the allowlist (registries, code hosts, localhost; exact or .suffix match). Fetch-only passes; curl -K/--config is refused. No pragma bypass: ask a person. A floor, not a sandbox: ~/.curlrc, obfuscation, other clients, runtimes."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Unapproved Egress

Best-effort guard on the tool channel: curl, wget or iwr/irm (Invoke-WebRequest/RestMethod) that UPLOADS (POST/PUT/PATCH, -d/--data*/--json, -F/--form, -T/--upload-file, wget --post-*/--body-*, -Body/-InFile/-Form) to a host outside the allowlist (registries, code hosts, localhost; exact or .suffix match). Fetch-only passes; curl -K/--config is refused. No pragma bypass: ask a person. A floor, not a sandbox: ~/.curlrc, obfuscation, other clients, runtimes.

```
block(egress): fetch(curl|wget|iwr|irm) + upload(-d|--data*|--json|-F|-T|--upload-file|-X POST|PUT|PATCH|-Body|-InFile) to host NOT in allowlist; curl -K|--config refused
allow: fetch_only(GET), allowlisted_host(github|pypi|npm|...); floor_not_sandbox; no marker or pragma passes: ask_person
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs. See https://github.com/open-coder-ai/chock
