<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/block-invisible-unicode/) -->
```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+invisible-unicode ...
Invisible or direction-override Unicode detected in this change. These characters change how code reads to a human or hide instructions an agent will still obey. Remove them. At commit, 'pragma: allowlist invisible-unicode' on the same line marks a documented exception (e.g. a test fixture); the pragma is NOT honored at tool-use, where the scanned text is a live tool argument an appended token could neutralize.
```
<!-- chock:hooks:end -->
