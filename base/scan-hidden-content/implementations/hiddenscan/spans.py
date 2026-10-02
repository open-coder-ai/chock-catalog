"""Markdown with certain code blanked, and the link text that makes a destination an image's.

A code span is blanked only when it is certain: both backtick runs on one paragraph line, with no
unpaired run earlier in the paragraph (since the last blank line) and no table pipe on the line. Whether
backticks pair across lines depends on where CommonMark ends a paragraph, and an error there would hide a
comment or a URL a renderer passes through; read as text instead, the worst case is a report about code.
"""

from __future__ import annotations

import re

from hiddenscan.blocks import BREAK, CODE, TEXT, classify

TICKS = re.compile(r"(\\*)(`+)")
PIPE = re.compile(r"(?<!\\)\|")
#: A GFM delimiter row; with a header line of as many cells above it, the rows below are a table's, whose
#: cells are inline content of their own: a code span there pairs within its cell.
DELIMITER = re.compile(r"^[ \t]*\|?(?:[ \t]*:?-+:?[ \t]*\|)*[ \t]*:?-+:?[ \t]*\|?[ \t]*$")

#: An inline tag or autolink as CommonMark defines them (6.6, 6.5): an open or closing tag with valid
#: attributes, or a scheme followed by a URL without spaces. Brackets inside one are not link text; any other
#: `<...>`, such as `a < b ... c > d`, is text.
ATTRIBUTE = r"""\s+[A-Za-z_:][\w.:-]*(?:\s*=\s*(?:[^\s"'=<>`]+|'[^'\n]*'|"[^"\n]*"))?"""
INLINE_TAG = rf"<[A-Za-z][A-Za-z0-9-]*(?:{ATTRIBUTE})*\s*/?>|</[A-Za-z][A-Za-z0-9-]*\s*>|<[A-Za-z][A-Za-z0-9.+-]{{1,31}}:[^\s<>]*>"
#: Tokens of link text: an escape, an inline tag or autolink, an image or link opener, a closer followed by a
#: destination, and a blank line (which ends any open link text).
BRACKETS = re.compile(rf"\\.|{INLINE_TAG}|!\[|\[|\]\(|\n[ \t]*\n", re.DOTALL)


def _spans(line: str) -> tuple[str, bool]:
    """The line with its code spans blanked, and whether a backtick run on it found no partner on it (CommonMark
    may then pair it with a later line, so nothing after it is certain)."""
    runs = []
    for m in TICKS.finditer(line):
        start = m.start(2) + len(m.group(1)) % 2  # a backtick after an odd number of backslashes is literal
        if start < m.end(2):
            runs.append((start, m.end(2)))
    following: dict[int, int] = {}
    after = [-1] * len(runs)
    for k in range(len(runs) - 1, -1, -1):  # the next run of each length, found once: linear
        size = runs[k][1] - runs[k][0]
        after[k] = following.get(size, -1)
        following[size] = k
    chars, i = list(line), 0
    while i < len(runs):
        j = after[i]
        if j < 0:
            return "".join(chars), True
        chars[runs[i][0] : runs[j][1]] = " " * (runs[j][1] - runs[i][0])
        i = j + 1
    return "".join(chars), False


def _cells(line: str) -> list[str]:
    cells = PIPE.split(line.strip())
    return cells[1 if cells and not cells[0] else 0 : -1 if len(cells) > 1 and not cells[-1] else None]


def _row(line: str) -> str:
    """A table row with each cell's code spans blanked; an unpaired backtick in a cell is literal."""
    return "|".join(_spans(cell)[0] for cell in PIPE.split(line))


def blank_code(text: str) -> str:
    """Markdown with what is certainly code replaced by spaces, newlines kept: code is shown, not fetched or
    hidden."""
    lines = text.split("\n")
    out: list[str] = []
    kinds = classify(lines)
    unsure = table = before = False  # before: whether anything was unsure before the line above
    for at, (line, kind) in enumerate(zip(lines, kinds, strict=True)):
        if kind == CODE:
            out.append(re.sub(r"[^\n]", " ", line))
            continue
        unsure, table = unsure and kind != BREAK, table and kind == TEXT
        header = lines[at - 1] if at and kinds[at - 1] == TEXT else None
        if kind == TEXT and "|" in line and DELIMITER.match(line) and header is not None:
            table = len(_cells(header)) == len(_cells(line))
            if table and not before:  # the header's backticks are its cells' own after all
                out[-1], unsure = _row(header), False
        before = unsure
        if table:
            out.append(_row(line))
        elif kind == TEXT and not unsure and not PIPE.search(line):
            blanked, unsure = _spans(line)
            out.append(blanked)
        else:
            unsure = unsure or "`" in line
            out.append(line)
    return "\n".join(out)


def tag_view(raw: str, blanked: str) -> str:
    """The raw text with only the '<' of code removed: code shows its tags and comments as text, so they
    open nothing, while the words in code stay countable inside a hidden element or comment."""
    return "".join(" " if r == "<" and b == " " else r for r, b in zip(raw, blanked, strict=True))


def closers(text: str) -> dict[int, bool]:
    """Each `](` outside an escape, inline tag or autolink, mapped to whether it may close an image's text, in
    one forward pass. The stricter reading: a `](` closes an image's text when no opener is open or any open
    opener is an image's, and a bare `]` closes nothing, since a bracket inside inline HTML, an autolink or a
    reference is not one this pass can place."""
    stack: list[bool] = []
    images = 0
    out: dict[int, bool] = {}
    for m in BRACKETS.finditer(text):
        piece = m.group(0)
        if piece in ("![", "["):
            stack.append(piece == "![")
            images += piece == "!["
        elif piece == "](":
            out[m.start()] = not stack or images > 0
            if stack:
                images -= stack.pop()
        elif piece[0] == "\n":
            stack, images = [], 0
        # an escape or an inline tag or autolink: nothing to count
    return out
