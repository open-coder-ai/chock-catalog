<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/block-unapproved-egress/) -->
```
block(egress): fetch(curl|wget|iwr) + upload(-d|--data|-F|--upload-file|-X POST|PUT) to host NOT in allowlist
allow: fetch_only(GET), allowlisted_host(github|pypi|npm|...); floor_not_sandbox; escape: 'pragma: allowlist egress'
```
<!-- chock:hooks:end -->
