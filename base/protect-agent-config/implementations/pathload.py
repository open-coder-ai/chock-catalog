"""A shell command that makes Claude Code load a plugin from a folder: `CLAUDE_CODE_PLUGIN_DIRS`, `claude --plugin-dir` (stdlib only)."""

from __future__ import annotations

import re

from chock_shellparse import commands, is_powershell
from chock_shellparse.parse import _parse

VARIABLE = "CLAUDE_CODE_PLUGIN_DIRS"
_START = r"(?:^|[;&|({\n])\s*"  # a word that starts a command, so a commit message that quotes it is not one
# The assignments the reader does not see as one: PowerShell's `$env:X =`, `setx`, `set X=`, `Set-Item Env:X`, .NET's SetEnvironmentVariable.
_FOREIGN = re.compile(
    rf"\$env:{VARIABLE}\s*\+?=|\bsetenvironmentvariable\W+{VARIABLE}\b"
    rf"|{_START}(?:setx\s+{VARIABLE}\b|set\s+{VARIABLE}=|set-item\s+(?:-\w+\s+)*env:{VARIABLE}\b)",
    re.IGNORECASE,
)
_DECLARERS = frozenset(("declare", "typeset", "readonly", "local"))
_LAUNCHERS = frozenset(("npx", "bunx", "pnpx", "pnpm", "npm", "yarn", "uvx"))


def _sets(env: dict[str, str]) -> bool:
    """Whether an environment holds the variable (Windows reads its name in any case)."""
    return VARIABLE in {name.upper() for name in env}


def _declares(name: str, args: list[str]) -> bool:
    """Whether `declare -x X=v` (or typeset, readonly, local) binds the variable."""
    return name in _DECLARERS and any("=" in a and _sets({a.split("=", 1)[0].rstrip("+"): ""}) for a in args)


def _loads(name: str, args: list[str]) -> bool:
    """Whether a command is Claude Code, or a launcher of it, started with `--plugin-dir`."""
    flagged = any(a == "--plugin-dir" or a.startswith("--plugin-dir=") for a in args)
    return flagged and ("claude" in name or (name in _LAUNCHERS and any("claude" in a for a in args)))


def loads_plugin(raw: str) -> bool:
    """Whether a command line sets `CLAUDE_CODE_PLUGIN_DIRS` or starts Claude Code with `--plugin-dir`, as one command or in a script it runs."""
    if _FOREIGN.search(raw):
        return True
    unfollowed = _parse(raw, {}, ps=is_powershell(raw), depth=0)[1]  # an assignment that no command followed
    return _sets(unfollowed) or any(
        _sets(cmd.env) or _declares(cmd.name, cmd.args) or _loads(cmd.name, cmd.args) for cmd in commands(raw)
    )
