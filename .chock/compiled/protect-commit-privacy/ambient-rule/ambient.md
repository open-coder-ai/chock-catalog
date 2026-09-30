<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/protect-commit-privacy/) -->
```
commit_message|pr_description: describe(change); never(narrate: conversation|plan|who_asked|user_quotes|session_refs|internal_doc_paths)
if(marker_hit|sensitive_context): ask_person before(commit); no_waiver(person removes phrase from MARKERS); never(edit MARKERS)  # history is published forever
```
<!-- chock:hooks:end -->
