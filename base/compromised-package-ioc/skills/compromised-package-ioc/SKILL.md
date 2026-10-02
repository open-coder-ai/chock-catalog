---
name: compromised-package-ioc
description: "Blocks adding a known-malicious package version (npm, PyPI, crates, Go, RubyGems, Packagist manifests and lockfiles), a re-pointed action ref, or an IOC file name, from a dated, sourced list (data/ioc.json, CI fails 120 days after as_of). Runs: commit, agent write, turn's end; only additions judged. Exact versions only: a range is not resolved. A snapshot, not a feed; friction, not a boundary. Adopt under rollout observe."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Compromised Package IOC

Blocks adding a known-malicious package version (npm, PyPI, crates, Go, RubyGems, Packagist manifests and lockfiles), a re-pointed action ref, or an IOC file name, from a dated, sourced list (data/ioc.json, CI fails 120 days after as_of). Runs: commit, agent write, turn's end; only additions judged. Exact versions only: a range is not resolved. A snapshot, not a feed; friction, not a boundary. Adopt under rollout observe.

```
on(commit|tool_use): block(script) script=compromised-package-ioc-gate.py
A known-malicious package version, compromised action ref or IOC file name was added. Use a release outside the list (the cited advisory names the fixed one) or drop the dependency, pin the action to a reviewed commit, or delete the file. The list changes only in a reviewed pull request to this policy's data/ioc.json; there is no in-line waiver.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
