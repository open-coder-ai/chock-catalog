<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/code-safety/) -->
```
see(scan-secrets): commit|agent_write(secrets|keys|tokens|passwords|.env); see(verify-dependency-exists, opt_in): add(unlisted_dependency)
see(agentic-code-security pack code): refuses Python eval|exec of non-literal text and SQL built from strings (Python|JS); advisory: avoid(eval|exec|unsanitized_sql); on_find(secret|hallucinated_pkg): propose_removal_to_human
```
<!-- chock:hooks:end -->
