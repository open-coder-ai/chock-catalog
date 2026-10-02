---
name: block-unguarded-agent-spawn
description: "Best-effort guard against launching a coding agent with safety checks off: claude --dangerously-skip-permissions, bypassPermissions or a wildcard --allowedTools; codex --full-auto, --yolo, --ask-for-approval never, danger-full-access; gemini --yolo; cursor-agent --force; aider --yes-always; copilot --allow-all-tools; amp, cline, goose, opencode auto-approve. Looks through cd, bash -c, sudo, env, npx and uvx; echo text passes. Misses: aliases, scripts, config."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Unguarded Agent Spawn

Best-effort guard against launching a coding agent with safety checks off: claude --dangerously-skip-permissions, bypassPermissions or a wildcard --allowedTools; codex --full-auto, --yolo, --ask-for-approval never, danger-full-access; gemini --yolo; cursor-agent --force; aider --yes-always; copilot --allow-all-tools; amp, cline, goose, opencode auto-approve. Looks through cd, bash -c, sudo, env, npx and uvx; echo text passes. Misses: aliases, scripts, config.

```
never(spawn_agent): claude(--dangerously-skip-permissions|bypassPermissions|--allowedTools_*), codex(--full-auto|--yolo|-a_never|--sandbox_danger-full-access), gemini(--yolo|-y), cursor-agent(--force|-f), aider(--yes-always), copilot(--allow-all-tools), amp|cline|goose|opencode(auto-approve flags)
if(unattended_run_needed): ask_person; person_starts_it  # spawn with default approvals and sandbox
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs. See https://github.com/open-coder-ai/chock
