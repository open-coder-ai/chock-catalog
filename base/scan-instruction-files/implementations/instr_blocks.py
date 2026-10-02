"""Markdown block structure for instr_text: list item nesting, fence openers and closers, and table runs.
Indents are columns with tabs expanded to the next multiple of four, as CommonMark counts them."""

from __future__ import annotations

import re
from typing import NamedTuple

#: A fence opener: three or more backticks or tildes, and its info string.
FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)")
#: A fence or closer indented this much or more past its container's content is indented code or text.
CODE_INDENT = 4
#: A list item's marker and the whitespace after it.
LIST_ITEM = re.compile(r"^([ \t]*(?:[-*+]|[0-9]{1,9}[.)]))(?:[ \t]+|$)")
#: A table's delimiter row, matched on the stripped line; possessive, so a long run of spaces is linear.
TABLE_DELIMITER = re.compile(r"\|?[ \t]*+:?-{3,}+:?[ \t]*+(?:\|[ \t]*+:?-{3,}+:?[ \t]*+)*+\|?")


class Fence(NamedTuple):
    """An open fence: its marker, its opener's quote depth, the content indent of the list item holding it
    (0 at top level), whether a list item holds it, its info string, and whether any renderer must read it as
    a fence too (opened at the margin, outside any list, quote or HTML block)."""

    mark: str
    depth: int
    base: int
    in_list: bool
    info: str
    sure: bool = False

    def holds(self, line: str, depth: int) -> bool:
        """Whether `line` (at quote depth `depth`) is still inside this fence's container: a quote that ends
        closes it, and so does a non-blank line below the content indent of the list item that holds it."""
        return depth >= self.depth and not (self.in_list and line.strip() and indent(line) < self.base)

    def closes(self, line: str, depth: int) -> bool:
        """A closing fence: the marker alone, at the opener's quote depth, indented less than CODE_INDENT past
        the container's content."""
        bare = line.strip(" \t")
        return (
            depth == self.depth
            and bare.startswith(self.mark)
            and not bare.strip(self.mark[0])
            and indent(line) - self.base < CODE_INDENT
        )


def columns(text: str) -> int:
    return len(text.expandtabs(4))


def indent(line: str) -> int:
    return columns(line[: len(line) - len(line.lstrip(" \t"))])


def item_indent(line: str) -> int | None:
    """The content indent of the list item `line` starts, else None: the marker and the 1-4 columns after
    it; with five or more (indented code) or nothing after the marker, the marker and one column."""
    m = LIST_ITEM.match(line)
    if m is None:
        return None
    width, gap = columns(m.group(1)), columns(m.group()) - columns(m.group(1))
    return width + 1 if gap > CODE_INDENT or not line[m.end() :].strip() else width + gap


def nest(items: list[int], line: str, *, lazy: bool) -> None:
    """Track the content indents of the open list items: a non-blank line closes every item it is indented
    less than (a lazy continuation of a paragraph closes none), and a list marker opens a new one."""
    if lazy or not line.strip():
        return
    col = indent(line)
    while items and items[-1] > col:
        items.pop()
    if (content := item_indent(line)) is not None:
        items.append(content)


def open_fence(line: str, depth: int, items: list[int]) -> Fence | None:
    """The fence `line` opens, if any, after nest() has seen it: right after a list marker (- ```sh), or
    indented less than CODE_INDENT past the innermost open item's content (the margin at top level). A
    backtick fence whose info string holds a backtick is a code span, not a fence."""
    m = LIST_ITEM.match(line)
    if m is not None:
        if items[-1] != columns(m.group()):  # five or more columns after the marker: indented code
            return None
        line, base = line[m.end() :], items[-1]
    else:
        base = items[-1] if items else 0
        if indent(line) - base >= CODE_INDENT:
            return None
    found = FENCE.match(line)
    if found is None or (found.group(1)[0] == "`" and "`" in found.group(2)):
        return None
    return Fence(found.group(1), depth, base, bool(items), found.group(2).strip())


def table_rows(lines: list[str]) -> set[int]:
    """Indexes of the lines in a run of `|` lines that holds a delimiter row."""
    rows: set[int] = set()
    n = 0
    while n < len(lines):
        end = n
        while end < len(lines) and lines[end].lstrip().startswith("|"):
            end += 1
        if any(TABLE_DELIMITER.fullmatch(lines[k].strip()) for k in range(n, end)):
            rows.update(range(n, end))
        n = max(end, n + 1)
    return rows
