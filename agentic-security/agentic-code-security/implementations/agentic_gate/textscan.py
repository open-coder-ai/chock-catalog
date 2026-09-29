"""Line-level reading for the files with no parser here: YAML, shell, env files, and JS."""

from __future__ import annotations

import re
from collections.abc import Iterator

from agentic_gate import jsscan
from agentic_gate.model import FileText, Hit

_HASH_KINDS = frozenset({"yaml", "toml", "shell", "env", "dockerfile", "python"})


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def uncommented(line: str) -> str:
    """The line up to a `#` comment that is not inside quotes."""
    quote = ""
    for index, ch in enumerate(line):
        if quote:
            quote = "" if ch == quote else quote
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def code_lines(text: FileText) -> Iterator[tuple[int, str]]:
    """(line number, line) with comments removed: `#` for line-oriented configs, `//` for JS."""
    if text.kind == "js":
        source = jsscan.strip_comments(text.text).splitlines()
    elif text.kind in _HASH_KINDS:
        source = [uncommented(line) for line in text.lines]
    else:
        source = text.lines
    yield from enumerate(source, 1)


def find(view: str, pattern: re.Pattern[str], detail: str) -> Iterator[Hit]:
    """A hit for every match of `pattern` in `view`, on the line the match starts."""
    for found in pattern.finditer(view):
        yield Hit(line_of(view, found.start()), detail)


def scan_lines(text: FileText, pattern: re.Pattern[str], detail: str) -> Iterator[Hit]:
    """A hit for every comment-stripped line `pattern` matches."""
    for line_no, line in code_lines(text):
        if pattern.search(line):
            yield Hit(line_no, detail)
