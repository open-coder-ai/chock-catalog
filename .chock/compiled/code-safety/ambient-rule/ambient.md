<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/code-safety/) -->
```
see(scan-secrets): commit(secrets|keys|tokens|passwords|.env); see(verify-dependency-exists, opt_in): add(unlisted_dependency)
advisory: avoid(eval|exec|unsanitized_sql); on_find(secret|hallucinated_pkg): propose_removal_to_human
```
<!-- chock:hooks:end -->
