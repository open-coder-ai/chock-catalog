"""A shell command that makes Claude Code load a plugin from a folder: `CLAUDE_CODE_PLUGIN_DIRS`, `claude --plugin-dir` (stdlib only)."""

from __future__ import annotations

import re

from chock_shellparse import commands, is_powershell
from chock_shellparse.parse import _ASSIGN, _WRAPPERS, _base, _crude, _inner, _parse, _Scan, _strip
from pathmatch import expand
from pathtext import scan

VARIABLE = "CLAUDE_CODE_PLUGIN_DIRS"
_DEPTH = 4
# The assignments the reader does not see as one, read at the start of a command (a `{`, `(` or cmd's `@` may come first):
# PowerShell's `$env:X =`, `setx`, `set X=`, `Set-Item Env:X`, .NET's SetEnvironmentVariable.
_FOREIGN = re.compile(
    rf"[{{(\s@]*(?:\$env:{VARIABLE}\s*\+?="
    rf"|(?:\$?\w+\s*=\s*|\[void\])?\[(?:system\.)?environment\]::setenvironmentvariable\W+{VARIABLE}\b"
    rf"|setx\s+{VARIABLE}\b|set\s+{VARIABLE}=|set-item\s+(?:-\w+\s+)*env:{VARIABLE}\b)",
    re.IGNORECASE,
)
_BARE = re.compile(r"\$(?:\{\w+\}|\w+)")  # a word that is one variable: the shell splits what it holds into words
_CALL = re.compile(r"setenvironmentvariable$", re.IGNORECASE)  # the `(` that opens its arguments ends a clause
_DECLARERS = frozenset(("declare", "typeset", "readonly", "local"))
_LAUNCHERS = frozenset(("npx", "bunx", "pnpx", "pnpm", "npm", "yarn", "uvx"))


def _sets(env: dict[str, str]) -> bool:
    """Whether an environment holds the variable (Windows reads its name in any case)."""
    return VARIABLE in {name.upper() for name in env}


def _declares(name: str, args: list[str]) -> bool:
    """Whether `declare -x X=v` (or typeset, readonly, local) binds the variable."""
    return name in _DECLARERS and any("=" in a and _sets({a.split("=", 1)[0].rstrip("+"): ""}) for a in args)


def _loads(name: str, args: list[str], env: dict[str, str]) -> bool:
    """Whether a command is Claude Code, or a launcher of it, started with `--plugin-dir` (a variable the line set to plain text is read)."""
    words = [w for a in args for w in (expand(a, env).split() if _BARE.fullmatch(a) else [expand(a, env)])]
    flagged = any(a == "--plugin-dir" or a.startswith("--plugin-dir=") for a in words)
    return flagged and ("claude" in name or (name in _LAUNCHERS and any("claude" in a for a in words)))


def _unwrapped(words: list[str]) -> list[str]:
    """The words of a command once leading assignments and wrappers (sudo, env, nohup, timeout, ...) are taken off."""
    while words:
        name = _base(words[0])
        if _ASSIGN.match(words[0]):
            words = words[1:]
        elif name in _WRAPPERS:
            words = _strip(name, words[1:])
        else:
            break
    return words


def _foreign(raw: str, depth: int = 0) -> bool:
    """Whether a command, or a script it runs, holds a PowerShell or cmd assignment of the variable at the start of a command.

    A here-document body, a quoted message and an `echo` argument are not commands, so text that only quotes the assignment passes.
    """
    held = ""  # `[Environment]::SetEnvironmentVariable(` ends a clause at the `(`: its arguments are the next one
    for clause in _Scan(raw).run() or _crude(raw):
        words = _unwrapped(clause.words)
        text = f"{held} {' '.join(words)}".strip()
        held = text if _CALL.search(text) else ""
        script = _inner(_base(words[0]), words[1:]) if words else None
        if _FOREIGN.match(text) or (script is not None and depth < _DEPTH and _foreign(script, depth + 1)):
            return True
    return False


def loads_plugin(raw: str) -> bool:
    """Whether a command line sets `CLAUDE_CODE_PLUGIN_DIRS` or starts Claude Code with `--plugin-dir`, as one command or in a script it runs.

    Best effort: the line is read as written and with its `$'..'` words decoded.
    """
    ps = is_powershell(raw)
    if _foreign(raw.replace("`", "") if ps else raw):
        return True
    for text in dict.fromkeys((raw, scan(raw).outer)):  # `$'--plugin-dir'` is `--plugin-dir`
        unfollowed = _parse(text, {}, ps=ps, depth=0)[1]  # an assignment that no command followed
        if _sets(unfollowed) or any(
            _sets(cmd.env) or _declares(cmd.name, cmd.args) or _loads(cmd.name, cmd.args, cmd.env)
            for cmd in commands(text)
        ):
            return True
    return False
