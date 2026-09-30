<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/block-unapproved-egress/) -->
```
block(egress): fetch(curl|wget|iwr|irm) + upload(-d|--data*|--json|-F|-T|--upload-file|-X POST|PUT|PATCH|-Body|-InFile) to host NOT in allowlist; curl -K|--config refused
allow: fetch_only(GET), allowlisted_host(github|pypi|npm|...); floor_not_sandbox; no marker or pragma passes: ask_person
```
<!-- chock:hooks:end -->
