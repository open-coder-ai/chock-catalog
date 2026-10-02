"""Code spans blanked within the runs blocks.classify marks out, and the link text that makes an image."""

from __future__ import annotations

import re

from hiddenscan.blocks import BLOCK_START, CODE, SINGLE, TEXT, classify

TICKS = re.compile(r"(\\*)(`+)")
#: A GFM table's delimiter row: after it, each row's cells are runs of their own until a blank line.
TABLE_DELIMITER = re.compile(
    r"^[ \t]*\|?[ \t]*:?-+:?[ \t]*(?:\|[ \t]*:?-+:?[ \t]*)+\|?[ \t]*$|^[ \t]*\|[ \t]*:?-+:?[ \t]*\|?[ \t]*$"
)
CELL = re.compile(r"((?<!\\)\|)")
#: Tokens of link text: an escape, an inline tag or autolink (whose brackets are not link text), an image or
#: link opener, a closer followed by a destination, and a blank line (which ends any open link text).
BRACKETS = re.compile(r"\\.|<[^<>\n]*>|!\[|\[|\]\(|\n[ \t]*\n", re.DOTALL)


def _spaces(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def _blank_spans(segment: str) -> str:
    """Code spans blanked: a backtick run opens one when a later run of the same length closes it. A
    backtick after an odd number of backslashes is literal. Linear: each run finds the next of its length once."""
    runs = []
    for m in TICKS.finditer(segment):
        start = m.start(2) + len(m.group(1)) % 2
        if start < m.end(2):
            runs.append((start, m.end(2)))
    following: dict[int, int] = {}
    after = [-1] * len(runs)
    for i in range(len(runs) - 1, -1, -1):
        size = runs[i][1] - runs[i][0]
        after[i] = following.get(size, -1)
        following[size] = i
    chars, i = list(segment), 0
    while i < len(runs):
        j = after[i]
        if j < 0:
            i += 1
            continue
        start, end = runs[i][0], runs[j][1]
        chars[start:end] = _spaces(segment[start:end])
        i = j + 1
    return "".join(chars)


def blank_code(text: str) -> str:
    """Markdown with fenced blocks and code spans replaced by spaces, newlines kept: code is shown, not fetched.

    Code spans are paired only within one run of paragraph lines: a blank line, an HTML block, a fence, a
    heading or setext underline, a thematic break, a list item or a block quote ends the run, and after a
    GFM table's delimiter row each cell is a run of its own."""
    lines = text.split("\n")
    out: list[str] = []
    segment: list[str] = []

    def flush() -> None:
        if segment:
            out.extend(_blank_spans("\n".join(segment)).split("\n"))
            segment.clear()

    table = False
    for line, kind in zip(lines, classify(lines), strict=True):
        table = table and kind == TEXT
        if kind == TEXT and TABLE_DELIMITER.match(line):
            header = segment.pop() if segment else None
            flush()
            if header is not None:
                out.append("".join(_blank_spans(cell) for cell in CELL.split(header)))
            table = True
            out.append(line)
        elif table:
            out.append("".join(_blank_spans(cell) for cell in CELL.split(line)))
        elif kind == TEXT and SINGLE.match(line):
            flush()
            out.append(_blank_spans(line))
        elif kind == TEXT:
            if BLOCK_START.match(line):
                flush()
            segment.append(line)
        else:
            flush()
            out.append(_spaces(line) if kind == CODE else line)
    flush()
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
