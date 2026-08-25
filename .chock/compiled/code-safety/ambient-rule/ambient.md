<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/code-safety/) -->
```
enforced_when_installed(scan-secrets): commit(secrets|keys|tokens|passwords|.env); enforced_when_installed(verify-dependency-exists): add(unlisted_dependency)
advisory: avoid(eval|exec|unsanitized_sql); on_find(secret|hallucinated_pkg): propose_removal_to_human
```
<!-- chock:hooks:end -->
