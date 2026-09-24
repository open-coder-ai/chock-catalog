"""Catch clauses as this pack's rules need them: caught types, the caught variable, and the body
both as written and with comments/literals blanked -- built once so every catch/finally rule
shares one lexical parse instead of five slightly different ones."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from chock_security.decision import FileText
from chock_security.source import blank

_CATCH = re.compile(r"\bcatch\s*\(")
_FINALLY = re.compile(r"\bfinally\s*\{")

#: `type name` split on the last whitespace run: exactly the type half and the name half.
_TYPE_AND_NAME = 2


@dataclass(frozen=True)
class CatchClause:
    """One catch clause: where it starts, what it catches, and its body two ways."""

    line_no: int
    types: tuple[str, ...]
    variable: str
    raw_body: str
    code_body: str


def _matching(blanked: str, open_pos: int, opener: str, closer: str) -> int | None:
    depth = 0
    for i in range(open_pos, len(blanked)):
        if blanked[i] == opener:
            depth += 1
        elif blanked[i] == closer:
            depth -= 1
            if depth == 0:
                return i
    return None


def _line_no(blanked: str, pos: int) -> int:
    return blanked.count("\n", 0, pos) + 1


def _parameter(param: str) -> tuple[tuple[str, ...], str] | None:
    """`IOException | SQLException e` -> (("IOException", "SQLException"), "e")."""
    parts = param.strip().rsplit(maxsplit=1)
    if len(parts) != _TYPE_AND_NAME:
        return None
    types = tuple(t.strip() for t in parts[0].split("|") if t.strip())
    return (types, parts[1]) if types else None


def catch_clauses(text: FileText) -> Iterator[CatchClause]:
    """Every catch clause with a body this file's lexical shape lets us read cleanly."""
    blanked = blank(text.text)
    raw = text.text
    for match in _CATCH.finditer(blanked):
        open_paren = match.end() - 1
        close_paren = _matching(blanked, open_paren, "(", ")")
        if close_paren is None:
            continue
        parsed = _parameter(blanked[open_paren + 1 : close_paren])
        if parsed is None:
            continue
        brace = blanked.find("{", close_paren + 1)
        if brace == -1 or blanked[close_paren + 1 : brace].strip():
            continue
        close_brace = _matching(blanked, brace, "{", "}")
        if close_brace is None:
            continue
        types, variable = parsed
        yield CatchClause(
            _line_no(blanked, match.start()),
            types,
            variable,
            raw[brace + 1 : close_brace],
            blanked[brace + 1 : close_brace],
        )


def finally_blocks(text: FileText) -> Iterator[tuple[int, str]]:
    """Every finally block's line number and its body, blanked."""
    blanked = blank(text.text)
    for match in _FINALLY.finditer(blanked):
        brace = match.end() - 1
        close_brace = _matching(blanked, brace, "{", "}")
        if close_brace is not None:
            yield _line_no(blanked, match.start()), blanked[brace + 1 : close_brace]
