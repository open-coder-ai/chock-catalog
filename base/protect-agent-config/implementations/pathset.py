"""What the guard protects, and how a path is matched against it (stdlib only)."""

from __future__ import annotations

import re

from pathmatch import DEVICE
from pathplugin import plugin_hooks

# Instruction files an agent reads: below a `docs` folder they are documentation about the file, so a write asks a person instead.
INSTRUCTIONS = (
    "AGENTS.md",
    "CLAUDE.md",
    "CLAUDE.local.md",
    "GEMINI.md",
    "copilot-instructions.md",
    ".cursorrules",
    ".windsurfrules",
    ".aider.conf.yml",
)
# A name ending in `/` is a whole folder, matched as a path segment: everything below it is protected, whatever its name.
# Any other name is matched as text anywhere in the path.
PROTECTED = (
    *INSTRUCTIONS,
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
    ".codeium/windsurf/hooks.json",  # Windsurf, user level
    ".codeium/hooks.json",
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
    # Whole agent folders: its rules, commands, agents, skills, prompts and settings are all instructions the agent obeys.
    ".claude/",
    ".cursor/",
    ".codex/",
    ".gemini/",
    ".windsurf/",
    ".agents/",
    ".chock/",
    ".junie/",
    ".devin/",
    ".grok/",
    ".tabnine/",
    ".github/copilot",  # copilot-instructions.md, copilot-setup-steps.yml, copilot/: every `.github/copilot*`
    ".augment/",  # Augment: settings.json, hooks, rules
    ".claude-plugin/",  # Claude Code plugin manifests: a loaded plugin's hooks run above the project's own
    # Hook files of the other agents; a plugin's own `hooks/` folder is found on disk (pathplugin.py).
    ".clinerules/hooks/",  # Cline
    ".kiro/hooks/",  # Kiro hooks
    ".kiro/agents/",  # Kiro agent config, which declares hooks
)
# Files outside the repository, which no entry above names. A user's Cline folder (`~/Documents/Cline/Hooks`, as a segment whatever
# precedes it) and `~/.claude.json` (user-scope MCP servers and trust flags: the exact name, as a segment, so `.claude.json5` is not
# one) match anywhere; the machine-wide hook and settings files match from the start of the path, so `src/etc/` is not one.
_OUTSIDE = re.compile(
    r"(?:^|/)documents/cline/hooks(?:/|$)"
    r"|(?:^|/)\.claude\.json(?:[/:]|$)"
    r"|^(?:/etc/(?:(?:windsurf|devin)/hooks|augment/settings)\.json"
    r"|/library/application support/(?:(?:windsurf|devin)/hooks|augment/settings)\.json"
    r"|[a-z]:/programdata/(?:(?:windsurf|devin)/hooks|augment/settings)\.json)"
)
# The policy guards themselves: an agent must not rewrite the very guard the compiled hook executes.
GUARD_SOURCES = re.compile(r"\.agents/policies/.*implementations")
_FOLDERS = re.compile("|".join(f"(?:^|/){re.escape(p[:-1])}(?:/|$)" for p in PROTECTED if p.endswith("/")))
INSTRUCTION_TEXT = tuple(p.lower() for p in INSTRUCTIONS)
_FIRM = tuple(p.lower() for p in PROTECTED if not p.endswith("/") and p not in INSTRUCTIONS)
BLOCK, ASK = "block", "ask"


def normalise(path: str) -> str:
    """The path as matched: backslashes as slashes, no device prefix, `//` and `/./` collapsed, names without trailing dots or spaces (Windows drops them), lowercase."""
    normal = DEVICE.sub("", path.replace("\\", "/"))
    previous = None
    while previous != normal:
        previous = normal
        normal = normal.replace("//", "/").replace("/./", "/")
    return "/".join(part.rstrip(". ") or part for part in normal.split("/")).lower()


def verdict(path: str, base: str | None = None) -> str:
    """`block` for a protected path, `ask` for an instruction file below a `docs` folder and nothing else protected, else empty.

    `base` is the repository folder a relative path is read from, when a plugin's hooks folder is looked up on disk.
    """
    normal = normalise(path)
    if (
        any(part in normal for part in _FIRM)
        or _FOLDERS.search(normal)
        or GUARD_SOURCES.search(normal)
        or _OUTSIDE.search(normal)
        or plugin_hooks(normal, base)
    ):
        return BLOCK
    parts = normal.split("/")
    first = next((k for k, part in enumerate(parts) if any(name in part for name in INSTRUCTION_TEXT)), None)
    if first is None:
        return ""
    return ASK if "docs" in parts[:first] else BLOCK


def hit(path: str) -> bool:
    """Whether a path names something this guard protects, or asks about."""
    return verdict(path) != ""
