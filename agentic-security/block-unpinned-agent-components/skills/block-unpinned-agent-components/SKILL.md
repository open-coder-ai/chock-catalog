---
name: block-unpinned-agent-components
description: "Gate for the line-visible slice of ASI04: agent components fetched at a floating version. Blocks dist-tags (latest, next, canary, beta, rc, nightly) on npx/uvx/bunx, dlx, add/install and pipx run; FROM at latest or an untagged registry path; floating docker run/pull and docker:// refs; pip --pre; go install at latest; unversioned cargo installs; git+ installs and requirements, and github: dependencies, with no commit SHA. Per line: friction, not a boundary (limits in references)."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Block Unpinned Agent Components

Gate for the line-visible slice of ASI04: agent components fetched at a floating version. Blocks dist-tags (latest, next, canary, beta, rc, nightly) on npx/uvx/bunx, dlx, add/install and pipx run; FROM at latest or an untagged registry path; floating docker run/pull and docker:// refs; pip --pre; go install at latest; unversioned cargo installs; git+ installs and requirements, and github: dependencies, with no commit SHA. Per line: friction, not a boundary (limits in references).

```
on(commit|tool_use): block(content_regex) scan=added_lines allowlist_pragma=pragma:\s*allowlist\s+unpinned content_pattern(regex)
Unpinned agent component detected. Pin an exact version or digest (name@1.2.3, image:1.27.1 or image@sha256:..., a 40-hex commit for git+ and github: refs, cargo install name@1.2.3, no pip --pre) so what runs tomorrow is what was reviewed today, or add 'pragma: allowlist unpinned' on the same line for a deliberate exception (a person's; in the agent it counts only when that exact line is already committed in HEAD, so an agent asks a person).
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
