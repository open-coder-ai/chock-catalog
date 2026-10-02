"""Agent CLIs started with their safety checks off, on any line of a surface, shell, workflow or build file.

Lines are joined at backslash continuations and split into statements at unquoted `;`, `|`, `&`; a
quoted argument keeps its words (a flag passed in quotes still counts) but not its separators. Each
statement is read once, so the time grows with the text, not with how many agent names it repeats.
"""

from __future__ import annotations

import re

from devenv.core import Collector, norm

_QUOTED = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'[^'\n]*'")
_CLI = re.compile(
    r"(?i)(?<![\w.@/\\-])(?:[\w@.~-]*[/\\])*(claude(?:-code)?|codex|gemini(?:-cli)?|cursor-agent|copilot|qwen(?:-code)?"
    r"|opencode|amp|aider|goose|crush|auggie|droid|kiro-cli)(?:\.exe|\.cmd)?(?![\w.-])"
)
_FLAGS = re.compile(
    r"(?i)(?<![\w-])(?:--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox"
    r"|--permission-mode[= ]+bypasspermissions|--yolo|--full-auto|--approval-mode[= ]+yolo|--allow-all-tools"
    r"|--allow-all-paths|--yes-always|(?:--sandbox|-s)[= ]+danger-full-access"
    r"|(?:-c|--config)[= ]+(?:approval_policy\W*=\W*never|sandbox_mode\W*=\W*danger-full-access))(?![\w-])"
)
#: Short flags that skip checks only for one CLI.
_SHORT = {
    "gemini": re.compile(r"(?<![\w-])-y(?![\w-])"),
    "cursor-agent": re.compile(r"(?<![\w-])(?:-f|--force)(?![\w-])"),
}


def _logical_lines(lines: list[str]) -> list[tuple[int, str]]:
    """(first line number, text) with backslash continuations joined."""
    out: list[tuple[int, str]] = []
    start, parts = 0, []
    for number, line in enumerate(lines, 1):
        if not parts:
            start = number
        if line.rstrip("\r").endswith("\\"):
            parts.append(line.rstrip("\r")[:-1])
            continue
        out.append((start, " ".join([*parts, line])))
        parts = []
    if parts:
        out.append((start, " ".join(parts)))
    return out


def _unquote(match: re.Match[str]) -> str:
    return re.sub(r"[;&|]", " ", match.group(0)[1:-1])


def spawns(c: Collector) -> None:
    for number, line in _logical_lines(c.lines):
        if line.lstrip().startswith(("#", "//")):
            continue
        for statement in re.split(r"[;&|]", _QUOTED.sub(_unquote, line)):
            found = _CLI.search(statement)
            if not found:
                continue
            rest = statement[found.end() :]
            short = _SHORT.get(found.group(1).lower().removesuffix("-cli"))
            if _FLAGS.search(rest) or (short is not None and short.search(rest)):
                message = "an agent CLI is started with its safety checks off"
                c.add("dev-agent-spawn", f"spawn={norm(statement.strip())}", message, line=number)
