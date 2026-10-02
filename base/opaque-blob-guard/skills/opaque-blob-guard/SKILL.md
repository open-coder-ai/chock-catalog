---
name: opaque-blob-guard
description: "Warns (observe rollout; never refuses yet) when a change adds or edits, in tests/, test/, fixtures/, testdata/, spec/, m4/, vendor/ or gradle/wrapper/: a file with an archive, executable or wasm signature (any extension), a random-looking file over 100 KB, or a symlink out of the repo; or m4/configure/*.am text that decodes and evaluates, or a changed gradle wrapper jar. Misses payloads elsewhere and text-encoded ones under 100 KB. Friction, not a security boundary."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Flag Opaque Blobs

Warns (observe rollout; never refuses yet) when a change adds or edits, in tests/, test/, fixtures/, testdata/, spec/, m4/, vendor/ or gradle/wrapper/: a file with an archive, executable or wasm signature (any extension), a random-looking file over 100 KB, or a symlink out of the repo; or m4/configure/*.am text that decodes and evaluates, or a changed gradle wrapper jar. Misses payloads elsewhere and text-encoded ones under 100 KB. Friction, not a security boundary.

```
binary_or_archive_in(tests|fixtures|testdata|spec|m4|vendor|gradle/wrapper): avoid; if_required: state(purpose), list(sha256+path in .chock/blob-allowlist.txt), person_commits
prefer: generate_in_test_setup | pinned_checksummed_download; never decode_and_eval(test_file)
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` warns at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
