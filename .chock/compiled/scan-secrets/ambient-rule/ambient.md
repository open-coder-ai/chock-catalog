<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/scan-secrets/) -->
```
on(commit|tool_use): block(content_regex) scan=added_lines forbidden_path_regex=(\.env(\.(?!(sample|example|template|dist|def... ...
Potential secret detected in this change. Remove credentials and rotate any exposed keys. At commit, add '# pragma: allowlist secret' on the same line only for documented test fixtures; the pragma is NOT honored at tool-use, where the scanned text is a live tool argument an appended token could neutralize.
```
<!-- chock:hooks:end -->
