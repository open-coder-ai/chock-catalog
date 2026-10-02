"""Markdown block structure for instr_text: fence openers (also inside list items) and table runs."""

from __future__ import annotations

import re
from typing import NamedTuple

#: A fence opener: up to three spaces, then three or more backticks or tildes.
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
#: A fence indented more than this is a fence only inside a list item (else it is indented text or code).
MAX_FENCE_INDENT = 3
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d{1,9}[.)])\s")
#: A table's delimiter row; `|` lines start their own statements only in a run that has one (a soft-wrapped
#: line that happens to start with `|` continues its paragraph, as an autolink `<https://...>` does).
TABLE_DELIMITER = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)*\|?\s*$")


class Fence(NamedTuple):
    """An open fence: its marker, and the quote depth and indent of its opener (a container that ends closes it)."""

    mark: str
    depth: int
    indent: int
    in_list: bool

    def holds(self, line: str, depth: int) -> bool:
        """Whether `line` (at quote depth `depth`) is still inside this fence's container."""
        return depth >= self.depth and not (self.in_list and line.strip() and indent(line) < self.indent)


def opener(line: str, *, in_list: bool) -> re.Match[str] | None:
    """A fence opener: indented 4+ spaces only inside a list item, and a backtick fence's info string holding
    no backtick (else it is a code span)."""
    m = FENCE.match(line)
    if m is None or (indent(line) > MAX_FENCE_INDENT and not in_list):
        return None
    return None if m.group(1)[0] == "`" and "`" in line.strip()[len(m.group(1)) :] else m


def open_fence(line: str, depth: int, *, in_list: bool) -> Fence | None:
    """The fence `line` opens, if any: also one right after a list marker (- ```sh), whose content indent is
    the marker's width. A fence opened in a list item also closes when a line falls below that indent."""
    marker = LIST_ITEM.match(line)
    rest = line[marker.end() :] if marker else line
    m = opener(rest, in_list=in_list or marker is not None)
    if m is None:
        return None
    return Fence(m.group(1), depth, marker.end() if marker else indent(line), in_list or marker is not None)


def listing(line: str, *, in_list: bool) -> bool:
    """Whether a list item's content goes on after `line`: a list marker starts one, a non-blank line back at
    the margin ends it, and a blank or indented line keeps the current state."""
    if not line.strip():
        return in_list
    return bool(LIST_ITEM.match(line)) or (in_list and indent(line) > 0)


def indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def table_rows(lines: list[str]) -> set[int]:
    """Indexes of the lines in a run of `|` lines that holds a delimiter row."""
    rows: set[int] = set()
    n = 0
    while n < len(lines):
        end = n
        while end < len(lines) and lines[end].lstrip().startswith("|"):
            end += 1
        if any(TABLE_DELIMITER.match(lines[k]) for k in range(n, end)):
            rows.update(range(n, end))
        n = max(end, n + 1)
    return rows
