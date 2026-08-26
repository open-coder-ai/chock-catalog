<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/block-curl-pipe-sh/) -->
```
block(remote_exec): fetch(curl|wget|iwr|irm) piped/substituted into interpreter(sh|bash|python|perl|node|iex)
allow: download_to_file, fetch|non_interpreter(jq|tar); prefer: curl -o file; read; run
```
<!-- chock:hooks:end -->
