---
name: block-unguarded-agent-spawn
description: "Best-effort guard against an agent launching a coding agent with safety checks off: claude --dangerously-skip-permissions or --permission-mode bypassPermissions; codex --full-auto, --yolo, --dangerously-bypass-approvals-and-sandbox, --sandbox/-s danger-full-access; gemini --yolo, -y, --approval-mode yolo; cursor-agent --force/-f. Parsed: cd, bash -c, sudo/env, npx/bunx/pnpx wrappers are caught; echo/grep/commit text is not. Bypasses: aliases, scripts, config-set modes, unlisted agents."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Unguarded Agent Spawn

Best-effort guard against an agent launching a coding agent with safety checks off: claude --dangerously-skip-permissions or --permission-mode bypassPermissions; codex --full-auto, --yolo, --dangerously-bypass-approvals-and-sandbox, --sandbox/-s danger-full-access; gemini --yolo, -y, --approval-mode yolo; cursor-agent --force/-f. Parsed: cd, bash -c, sudo/env, npx/bunx/pnpx wrappers are caught; echo/grep/commit text is not. Bypasses: aliases, scripts, config-set modes, unlisted agents.

```
never(spawn_agent): claude(--dangerously-skip-permissions|--permission-mode_bypassPermissions), codex(--full-auto|--yolo|--dangerously-bypass-approvals-and-sandbox|--sandbox|-s_danger-full-access), gemini(--yolo|-y|--approval-mode_yolo), cursor-agent(--force|-f)
if(unattended_run_needed): ask_person; person_starts_it  # spawn with default approvals and sandbox
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
