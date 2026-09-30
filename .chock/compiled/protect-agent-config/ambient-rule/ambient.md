<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/protect-agent-config/) -->
```
agent_config(AGENTS.md|wrappers|.claude/settings|.mcp.json|.chock/dependency-allowlist.txt|.chock/bin|.chock/compiled|.git/hooks|.agents/policies/*/implementations): never(hand_edit|delete); regenerate_via(chock sync)
if(config_change_needed): ask_person; person edits from own shell; no agent-typed marker passes  # an agent must not widen or disarm its own guardrails
```
<!-- chock:hooks:end -->
