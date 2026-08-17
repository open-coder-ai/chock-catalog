---
name: block-unpinned-agent-components
description: "Pre-commit gate for the mechanizable slice of ASI04: agent components pulled at an unpinned version. Blocks npx/uvx/bunx launches at @latest \u2014 the standard MCP server idiom \u2014 quoted \"@latest\" arguments in agent config, and :latest container images. Language-manifest dependencies are verify-dependency-exists; signature and provenance stay with the advisory owasp-asi04 policy. Escape: 'pragma: allowlist unpinned' on the same line."
metadata:
  chock:
    artifact: hook
    enforcement: block
    coverage_without_chock: advisory
---

# Block Unpinned Agent Components

Pre-commit gate for the mechanizable slice of ASI04: agent components pulled at an unpinned version. Blocks npx/uvx/bunx launches at @latest — the standard MCP server idiom — quoted "@latest" arguments in agent config, and :latest container images. Language-manifest dependencies are verify-dependency-exists; signature and provenance stay with the advisory owasp-asi04 policy. Escape: 'pragma: allowlist unpinned' on the same line.

```
on(commit): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+unpinned ...
Unpinned agent component detected. Pin the version (name@1.2.3, image:tag) so what runs tomorrow is what was reviewed today, or add 'pragma: allowlist unpinned' on the same line for a deliberate exception.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
