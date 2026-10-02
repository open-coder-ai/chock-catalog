"""A Dockerfile as instructions: parser directives, escape-char continuations, comment lines and heredocs.

Each instruction keeps its logical text (continuation lines joined with a space, every RUN heredoc
body appended line by line) and an offset table, so a match is placed on its physical line and a
rule can tell a form split across lines from one a single-line gate already reads.
"""

from __future__ import annotations

import bisect
import json
import re
from typing import NamedTuple

DIRECTIVE = re.compile(r"#[ \t]*([A-Za-z][A-Za-z0-9_-]*)[ \t]*=[ \t]*(\S*)[ \t]*")
#: A heredoc opens only at the start of an unquoted shell word (`<<WORD`, `<<-WORD`, `3<<"WORD"`), as BuildKit reads it.
HEREDOC = re.compile(r"\d*<<(?!<)(-?)([\"']?)([A-Za-z_][\w.-]*)\2")
KEYWORD = re.compile(r"[ \t]*([A-Za-z]+)(?:[ \t]+|$)")
FLAG = re.compile(r"--([\w-]+)(?:=(\S*))?(?:[ \t]+|$)")
HEREDOC_KEYWORDS = frozenset({"RUN", "COPY", "ADD"})


class Instr(NamedTuple):
    """One instruction. `args` is the text after the keyword and flags; `text` adds heredoc bodies."""

    keyword: str
    flags: dict[str, str]
    args: str
    text: str
    starts: tuple[int, ...]
    lines: tuple[int, ...]
    raw: tuple[str, ...]
    above: str

    @property
    def line(self) -> int:
        return self.lines[0]

    def line_at(self, offset: int) -> int:
        """The physical line holding `offset` of `text`."""
        return self.lines[bisect.bisect_right(self.starts, offset) - 1]

    def exec_form(self) -> list[str] | None:
        """The JSON array form's elements, or None for the shell form."""
        if not self.args.startswith("["):
            return None
        try:
            parsed = json.loads(self.args)
        except ValueError:
            return None
        return parsed if isinstance(parsed, list) and all(isinstance(x, str) for x in parsed) else None


class _Builder:
    def __init__(self, line: int, above: str) -> None:
        self.parts: list[str] = []
        self.size = 0
        self.starts: list[int] = []
        self.lines: list[int] = []
        self.raw: list[str] = []
        self.above = above
        self.first = line

    def add(self, number: int, text: str, sep: str, raw: str) -> None:
        if self.parts:
            self.parts.append(sep)
            self.size += len(sep)
        self.starts.append(self.size)
        self.parts.append(text)
        self.size += len(text)
        self.lines.append(number)
        self.raw.append(raw)

    def text(self) -> str:
        return "".join(self.parts)


def escape_char(lines: list[str]) -> str:
    """The `# escape=` parser directive's character (backslash or backtick); directives end at the first other line."""
    char = "\\"
    seen: set[str] = set()
    for line in lines:
        found = DIRECTIVE.fullmatch(line)
        if not found or found.group(1).lower() in seen:
            break
        seen.add(found.group(1).lower())
        if found.group(1).lower() == "escape" and found.group(2) in ("\\", "`"):
            char = found.group(2)
    return char


def _is_comment(line: str) -> bool:
    return line.lstrip(" \t").startswith("#")


def _continues(line: str, esc: str) -> tuple[str, bool]:
    stripped = line.rstrip(" \t")
    if stripped.endswith(esc):
        return stripped[: -len(esc)], True
    return line, False


def _logical(lines: list[str], index: int, esc: str) -> tuple[list[tuple[int, str, str]], int]:
    """The physical lines of the instruction starting at `index` (comments and blanks inside dropped)."""
    parts: list[tuple[int, str, str]] = []
    while index < len(lines):
        raw = lines[index]
        index += 1
        if parts and (_is_comment(raw) or not raw.strip()):
            continue
        text, more = _continues(raw, esc)
        parts.append((index, text, raw))
        if not more:
            break
    return parts, index


def heredoc_words(text: str) -> list[tuple[bool, str]]:
    """(strip tabs, word) for each heredoc opener: outside quotes, $((...)) and escapes, at a word's start."""
    found: list[tuple[bool, str]] = []
    at, quote = 0, ""
    while at < len(text):
        char = text[at]
        if quote:
            at += 2 if char == "\\" and quote == '"' else 1
            quote = "" if char == quote else quote
            continue
        if text.startswith("$((", at):
            close = text.find("))", at)
            at = len(text) if close < 0 else close + 2
            continue
        opener = HEREDOC.match(text, at) if at == 0 or text[at - 1].isspace() else None
        if opener:
            found.append((opener.group(1) == "-", opener.group(3)))
            at = opener.end()
            continue
        quote = char if char in "\"'" else ""
        at += 2 if char == "\\" else 1
    return found


def _heredocs(lines: list[str], index: int, build: _Builder, keyword: str) -> int:
    """Append each `<<WORD` body to a RUN's text; skip the bodies of COPY and ADD (file contents)."""
    for strip_tabs, word in heredoc_words(build.text()):
        sep = "\n"
        while index < len(lines):
            raw = lines[index]
            index += 1
            body = raw.lstrip("\t") if strip_tabs else raw
            if body == word:
                break
            if keyword == "RUN":
                text, more = _continues(body, "\\")
                build.add(index, text, sep, raw)
                sep = " " if more else "\n"
    return index


def split_flags(rest: str) -> tuple[dict[str, str], str]:
    flags: dict[str, str] = {}
    while found := FLAG.match(rest):
        key = found.group(1).lower()
        flags[key] = f"{flags[key]} {found.group(2) or ''}" if key in flags else found.group(2) or ""
        rest = rest[found.end() :]
    return flags, rest.strip()


def _instruction(parts: list[tuple[int, str, str]], above: str) -> tuple[_Builder, str] | None:
    build = _Builder(parts[0][0], above)
    for number, text, raw in parts:
        build.add(number, text, " ", raw)
    head = KEYWORD.match(build.text())
    return (build, head.group(1).upper()) if head else None


def parse(text: str) -> list[Instr]:
    """Every instruction in order. Never raises: a line it cannot read as an instruction is skipped."""
    lines = text.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    esc = escape_char(lines)
    out: list[Instr] = []
    index, above = 0, ""
    while index < len(lines):
        if _is_comment(lines[index]) or not lines[index].strip():
            above = lines[index] if _is_comment(lines[index]) else ""
            index += 1
            continue
        parts, index = _logical(lines, index, esc)
        made = _instruction(parts, above)
        above = ""
        if made is None:
            continue
        build, keyword = made
        if keyword in HEREDOC_KEYWORDS:
            index = _heredocs(lines, index, build, keyword)
        out.append(_finish(build, keyword))
    return out


def _finish(build: _Builder, keyword: str) -> Instr:
    whole = build.text()
    rest = whole[KEYWORD.match(whole).end() :]  # type: ignore[union-attr]
    flags, args = split_flags(rest.split("\n", 1)[0])
    return Instr(keyword, flags, args, whole, tuple(build.starts), tuple(build.lines), tuple(build.raw), build.above)
