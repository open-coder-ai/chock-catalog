---
name: block-unguarded-agent-spawn
description: "Best-effort guard against an agent launching a coding agent with its safety checks off: claude --dangerously-skip-permissions or --permission-mode bypassPermissions, codex --full-auto, --yolo, --dangerously-bypass-approvals-and-sandbox or --sandbox danger-full-access, gemini --yolo, -y or --approval-mode yolo, cursor-agent --force. A spawned agent that never asks and never sandboxes is an unsupervised agent (OWASP ASI10, rogue agents). Read as a parsed command, so `cd repo && claude ...`, `bash -c '...'`, sudo/env wrappers and `npx @openai/codex ...` are caught, while a normal invocation, `codex --sandbox workspace-write`, or a command that only mentions the flag (echo, grep, a commit message) is not. Known bypass classes include shell aliases, wrapper scripts, config files that set the mode, and agents this list does not name. Run the agent with its default approvals; a human decides when an unattended run is acceptable."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Unguarded Agent Spawn

Best-effort guard against an agent launching a coding agent with its safety checks off: claude --dangerously-skip-permissions or --permission-mode bypassPermissions, codex --full-auto, --yolo, --dangerously-bypass-approvals-and-sandbox or --sandbox danger-full-access, gemini --yolo, -y or --approval-mode yolo, cursor-agent --force. A spawned agent that never asks and never sandboxes is an unsupervised agent (OWASP ASI10, rogue agents). Read as a parsed command, so `cd repo && claude ...`, `bash -c '...'`, sudo/env wrappers and `npx @openai/codex ...` are caught, while a normal invocation, `codex --sandbox workspace-write`, or a command that only mentions the flag (echo, grep, a commit message) is not. Known bypass classes include shell aliases, wrapper scripts, config files that set the mode, and agents this list does not name. Run the agent with its default approvals; a human decides when an unattended run is acceptable.

```
never(spawn_agent): claude(--dangerously-skip-permissions|--permission-mode_bypassPermissions), codex(--full-auto|--yolo|--dangerously-bypass-approvals-and-sandbox|--sandbox_danger-full-access), gemini(--yolo|-y|--approval-mode_yolo), cursor-agent(--force)
if(unattended_run_needed): propose_to_human; await(approval)  # spawn with default approvals and sandbox
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
