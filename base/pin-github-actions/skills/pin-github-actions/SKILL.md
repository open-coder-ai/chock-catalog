---
name: pin-github-actions
description: "Pre-commit gate for the mechanizable slice of CI supply-chain hardening: a workflow that references a third-party GitHub Action by a movable ref -- a branch or a version tag -- instead of a full 40-character commit SHA. A tag like v4 or a branch like main can be re-pointed at new code after review, so the action that runs tomorrow need not be the one that was audited today; a compromised or rug-pulled release rides in on exactly that mutability. The gate blocks an added line that references an action by a non-SHA ref (owner/repo at a tag/branch); a full 40-char SHA pin passes, local actions (no ref) pass, and 'pragma: allowlist unpinned-action' on the same line is a visible, deliberate exception. This is the OpenSSF Scorecard Pinned-Dependencies control for the slice a diff can show; signature and provenance verification stay out of scope."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Pin GitHub Actions

Pre-commit gate for the mechanizable slice of CI supply-chain hardening: a workflow that references a third-party GitHub Action by a movable ref -- a branch or a version tag -- instead of a full 40-character commit SHA. A tag like v4 or a branch like main can be re-pointed at new code after review, so the action that runs tomorrow need not be the one that was audited today; a compromised or rug-pulled release rides in on exactly that mutability. The gate blocks an added line that references an action by a non-SHA ref (owner/repo at a tag/branch); a full 40-char SHA pin passes, local actions (no ref) pass, and 'pragma: allowlist unpinned-action' on the same line is a visible, deliberate exception. This is the OpenSSF Scorecard Pinned-Dependencies control for the slice a diff can show; signature and provenance verification stay out of scope.

```
on(commit): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+unpinned-action ...
Unpinned GitHub Action detected: a workflow references an action by a tag or branch (owner/repo at a movable ref) rather than a full 40-character commit SHA. Pin it to the SHA -- keep the version in a trailing comment for readability -- so a re-tagged or compromised release cannot change what runs. For a deliberate exception, add 'pragma: allowlist unpinned-action' on the same line.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
