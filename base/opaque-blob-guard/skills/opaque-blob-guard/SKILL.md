---
name: opaque-blob-guard
description: "Warns (observe rollout; never refuses yet) when a change adds or edits, in tests/, fixtures/, testdata/, spec/, m4/, vendor/, gradle/wrapper/: a file whose first bytes are an archive, executable, wasm or database signature (any extension), a random-looking non-media file over 100 KB, or a symlink out of the repo; m4/configure/Makefile text that decodes and evaluates; a gradle wrapper jar changed with no new distributionSha256Sum. Misses text-encoded or prefixed payloads, other folders."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Flag Opaque Blobs

Warns (observe rollout; never refuses yet) when a change adds or edits, in tests/, fixtures/, testdata/, spec/, m4/, vendor/, gradle/wrapper/: a file whose first bytes are an archive, executable, wasm or database signature (any extension), a random-looking non-media file over 100 KB, or a symlink out of the repo; m4/configure/Makefile text that decodes and evaluates; a gradle wrapper jar changed with no new distributionSha256Sum. Misses text-encoded or prefixed payloads, other folders.

```
binary_or_archive_in(tests|fixtures|testdata|spec|m4|vendor|gradle/wrapper): avoid; if_required: state(purpose), list(sha256+path in .chock/blob-allowlist.txt), person_commits
prefer: generate_in_test_setup | pinned_checksummed_download; never decode_and_eval(test_file)
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` warns at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
