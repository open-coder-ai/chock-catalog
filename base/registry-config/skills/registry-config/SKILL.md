---
name: registry-config
description: "Refuses package-manager config that redirects installs or weakens them: literal tokens, http or unlisted registry hosts (parsed, so lookalike and userinfo spellings fail), TLS or checksum checks off, install scripts on (npm, Yarn, pnpm, Bun, pip, uv, Poetry, conda, Go, Cargo, NuGet, Maven, Bundler, Composer, Hex, Dependabot); asks on extra indexes, replaces, no cooldown. Added only. Ship observe first. Friction, not a boundary."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Registry Config

Refuses package-manager config that redirects installs or weakens them: literal tokens, http or unlisted registry hosts (parsed, so lookalike and userinfo spellings fail), TLS or checksum checks off, install scripts on (npm, Yarn, pnpm, Bun, pip, uv, Poetry, conda, Go, Cargo, NuGet, Maven, Bundler, Composer, Hex, Dependabot); asks on extra indexes, replaces, no cooldown. Added only. Ship observe first. Friction, not a boundary.

```
on(commit|tool_use): block(script) script=registry-config-gate.py
This change points a package manager at an unapproved or clear-text registry, writes a credential into its config, turns TLS or checksum verification off, lets dependencies run install scripts, or redirects where packages come from. Use https registries on the default hosts, read tokens from environment references and keep verification on. An internal mirror is added by a person to .chock/registry-hosts.txt in a reviewed commit. A finding that only asks (extra index, replace, missing cooldown) is kept by a person committing from their own shell with CHOCK_ALLOW=registry-config; an agent asks the person and never sets it.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
