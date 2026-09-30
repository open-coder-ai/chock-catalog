---
name: agentic-code-security
description: "trigger: writing agent code or agent config -- Python or TypeScript using AutoGen, CrewAI, LangChain, LangGraph, mem0, the OpenAI Agents or Claude Agent SDK, an MCP server or client (.mcp.json, .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json, .codex/config.toml, .gemini/settings.json), docker-compose files for agents. avoid: code execution on the host, unpinned MCP servers and models, shell-reaching tools, approvals switched off, whole-environment and credential-store leaks, TLS verification off, unbounded loops, SQL and eval built from strings, stripped provenance markers. 29 rules in 10 packs -- exec, supply, tools, approval, identity, comms, bounds, prompt-memory, code, provenance -- each pack or rule allow|deny in .chock/agentic-security.json; bounds, prompt-memory and one supply rule start as allow."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Agentic Code Security

trigger: writing agent code or agent config -- Python or TypeScript using AutoGen, CrewAI, LangChain, LangGraph, mem0, the OpenAI Agents or Claude Agent SDK, an MCP server or client (.mcp.json, .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json, .codex/config.toml, .gemini/settings.json), docker-compose files for agents. avoid: code execution on the host, unpinned MCP servers and models, shell-reaching tools, approvals switched off, whole-environment and credential-store leaks, TLS verification off, unbounded loops, SQL and eval built from strings, stripped provenance markers. 29 rules in 10 packs -- exec, supply, tools, approval, identity, comms, bounds, prompt-memory, code, provenance -- each pack or rule allow|deny in .chock/agentic-security.json; bounds, prompt-memory and one supply rule start as allow.

```
on(commit|tool_use): block(script) script=agentic-code-security-gate.py
agentic-code-security: a construct one of its rules denies -- the refusal above names the rule, its CWE and OWASP ASI entry, and the fix. Only what the change adds is refused, at commit, as the agent writes and at its turn's end: an old finding on lines it leaves alone never blocks. Each rule's verdict is allow|deny in .chock/agentic-security.json, per rule or per pack (exec, supply, tools, approval, identity, comms, bounds, prompt-memory, code, provenance). Only a human reviewer waives a line, with # chock: allow <rule-id> (// in JavaScript), never the agent: in the agent a waiver counts once a human has committed it. JSON configs are waived in the selection file only.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
