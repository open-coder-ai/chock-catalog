"""The YAML scanner's block scalars: `|` literal and `>` folded, with indentation and chomping indicators."""

from __future__ import annotations

from .yamlpath_cursor import SPACES, Cursor

DIGITS = "123456789"
CHOMPS = "+-"


def block_scalar(cur: Cursor, indent: int) -> tuple[str, str]:
    """(value, kind) of the block scalar whose `|` or `>` is here, for a parent at `indent`; ends at a line start."""
    kind = "literal" if cur.char() == "|" else "folded"
    indent = max(indent, 0)  # a root scalar's text is indented too, as libyaml requires: no column-0 text
    cur.pos += 1
    digit, chomp = _header(cur)
    cur.end_line()
    width = indent + digit if digit else None
    lines, ends = _lines(cur, indent, width)
    last = max((i for i, line in enumerate(lines) if line), default=-1)
    body = "\n".join(lines[: last + 1])
    body = body if kind == "literal" else _folded(lines[: last + 1])
    if chomp == "+":
        return body + "\n" * sum(ends[max(last, 0) :]), kind
    return body + ("\n" if chomp != "-" and last >= 0 and ends[last] else ""), kind


def _header(cur: Cursor) -> tuple[int, str]:
    digit, chomp = 0, ""
    for _ in range(2):
        char = cur.char()
        if char and char in DIGITS and not digit:
            digit = int(char)
        elif char and char in CHOMPS and not chomp:
            chomp = char
        else:
            break
        cur.pos += 1
    return digit, chomp


def _lines(cur: Cursor, indent: int, width: int | None) -> tuple[list[str], list[bool]]:
    """The content lines with their indentation removed ("" when empty), and whether each ends in a break."""
    text = cur.text
    lines: list[str] = []
    ends: list[bool] = []
    deepest_blank = 0
    while cur.pos < len(text):
        end = text.find("\n", cur.pos)
        end = len(text) if end < 0 else end
        spaces = SPACES.match(text, cur.pos).end() - cur.pos
        blank = cur.pos + spaces == end
        if width is None and not blank:
            if spaces <= indent:
                break
            if deepest_blank > spaces:
                msg = "a leading empty line indented more than the first line of text"
                raise cur.error(msg)
            width = spaces
        if not blank and spaces < (width or 0):
            break
        if width is None or (spaces <= width and blank):
            deepest_blank = max(deepest_blank, spaces)
            lines.append("")
        else:
            lines.append(text[cur.pos + width : end])
        ends.append(end < len(text))
        cur.pos = min(end + 1, len(text))
    return lines, ends


def _folded(lines: list[str]) -> str:
    """Join lines as `>` does: a break between two text lines is a space; around indented lines it stays."""
    out: list[str] = []
    empties = 0
    previous = ""
    for line in lines:
        if not line:
            empties += 1
            continue
        if out:
            joined = previous[:1] not in " \t" and line[0] not in " \t"
            out.append(" " if joined and not empties else "\n" * (empties + (not joined)))
        else:
            out.append("\n" * empties)
        out.append(line)
        previous, empties = line, 0
    return "".join(out)
