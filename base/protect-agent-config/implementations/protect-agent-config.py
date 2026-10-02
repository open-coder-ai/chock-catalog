#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse shell commands that write to agent-config or vendored enforcement paths; reads and `chock sync` pass.
# Best effort: a write must target a protected path or a directory holding one, as the command resolves it (cd, `..`, variables, globs; see pathguard.py).

import os
import re
import shlex
import sys

from chock_shellparse import commands, writes_files
from pathguard import refuses
from pathwrap import too_deep

PROTECTED = (
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "copilot-instructions.md",
    ".cursorrules",
    ".windsurfrules",
    ".aider.conf.yml",
    ".claude/settings",
    ".mcp.json",
    # Project-level MCP (and hook) config a supported client reads: a server an agent registers there runs with its authority.
    ".cursor/mcp.json",  # Cursor, and Grok
    ".vscode/mcp.json",  # VS Code Copilot
    ".gemini/settings.json",  # Gemini CLI
    ".codex/config.toml",  # Codex CLI
    ".junie/mcp/mcp.json",  # Junie
    ".devin/mcp_config.json",  # Devin
    ".devin/mcp_config.local.json",
    ".devin/config.json",  # Devin before v3000.3 keeps mcpServers here; it also holds permissions and hooks
    ".devin/config.local.json",
    ".grok/config.toml",  # Grok
    ".agents/mcp_config.json",  # Antigravity
    ".tabnine/agent/settings.json",  # Tabnine
    # The hook files `chock sync` writes for each client: an agent that deleted its entries would disarm the gates.
    ".cursor/hooks.json",
    ".codex/hooks.json",
    ".windsurf/hooks.json",
    ".github/hooks/",  # VS Code Copilot: chock.json, agentseam.json
    ".grok/hooks/",
    ".devin/hooks.v1.json",
    ".agents/hooks.json",  # Antigravity
    ".chock/bin",
    ".chock/compiled",
    ".chock/dependency-allowlist.txt",
    ".chock/config.yaml",
    ".chock/security.json",
    ".chock/agentic-security.json",
    ".chock/state",  # shell only: the engine's own session log there would fail the Edit/Write gate's turn's-end walk
    ".git/hooks",
    ".git/config",  # core.hooksPath, core.fsmonitor and aliases there run code the way a hook does
)
# The policy guards themselves: an agent must not rewrite the very guard the compiled hook executes.
GUARD_SOURCES = re.compile(r"\.agents/policies/.*implementations")
REASON = "shell write touching agent config is refused -- an agent must not edit its own guardrails. Regenerate managed files with `chock sync`. For any other change, ask the person: they make it from their own shell."

DEEP = "shell command nested too deep to check (a script inside a script, five or more levels) -- refused because it cannot be judged. Run the inner commands one at a time, or ask the person."


def normalise(path: str) -> str:
    """The path as matched: backslashes as slashes, `//` and `/./` collapsed, lowercase (macOS and Windows ignore case)."""
    normal = path.replace("\\", "/")
    previous = None
    while previous != normal:
        previous = normal
        normal = normal.replace("//", "/").replace("/./", "/")
    return normal.lower()


def hit(path: str) -> bool:
    """Whether a path names something this guard protects."""
    normal = normalise(path)
    return any(part.lower() in normal for part in PROTECTED) or GUARD_SOURCES.search(normal) is not None


def check(raw: str) -> str | None:
    """The reason a command edits protected files, or None."""
    if too_deep(raw):
        return DEEP
    if any(writes_files(cmd, hit) for cmd in commands(raw)) or refuses(raw, PROTECTED, hit, normalise):
        return REASON
    return None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        reason = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"protect-agent-config: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if reason:
        print(f"BLOCKED: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
