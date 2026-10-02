"""Markdown blocks read the way CommonMark reads them, far enough to blank code and find image link text."""

from __future__ import annotations

import re

#: A fence opens a code block that runs to a closing fence of the same character, at least as long; a
#: backtick fence whose info string holds a backtick is not a fence.
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
#: HTML blocks of types 1-5 run to a line holding their end condition, the spec's literal strings (CommonMark
#: 0.31 section 4.6), across blank lines; types 6 and 7 to a blank line. A type 2 block ends only at "-->": a
#: browser also ends a comment at "--!>", but CommonMark keeps the block raw past it, so ending there would
#: blank as code what a renderer passes through as HTML. Comments themselves are found by markdown.comments.
HTML_ENDS = (
    (
        re.compile(r"^[ \t]*<(?:pre|script|style|textarea)(?=[\s>]|$)", re.IGNORECASE),
        ("</pre>", "</script>", "</style>", "</textarea>"),
    ),
    (re.compile(r"^[ \t]*<!--"), ("-->",)),
    (re.compile(r"^[ \t]*<\?"), ("?>",)),
    (re.compile(r"^[ \t]*<!\[CDATA\["), ("]]>",)),
    (re.compile(r"^[ \t]*<![A-Za-z]"), (">",)),
)
#: Any indentation: inside a list item an HTML block sits at the item's content column; outside one an
#: indented line is code, shown either way, so reading it as HTML only reports more.
HTML_OTHER = re.compile(r"^[ \t]*</?[A-Za-z]")
#: An indented code block starts this far past the margin or the list item's content column; a line indented
#: less than LIST_INDENT after a break ends a list.
CODE_INDENT, LIST_INDENT = 4, 2
#: A list item's marker and the spaces after it, which set the column its content starts at.
LIST_ITEM = re.compile(r"^[ \t]*(?:[-+*]|\d{1,9}[.)])([ \t]+|$)")
#: Lines that start a block of their own, so a code span never pairs backticks across them.
BLOCK_START = re.compile(r"^[ \t]*(?:>|[-+*](?:[ \t]|$)|\d{1,9}[.)](?:[ \t]|$))")
#: Lines that end a run on both sides: an ATX heading, a thematic break, a setext underline.
SINGLE = re.compile(r"^[ \t]*(?:#{1,6}(?:[ \t].*)?|(?:\*[ \t]*){3,}|(?:-[ \t]*){2,}|(?:_[ \t]*){3,}|=+[ \t]*|-[ \t]*)$")
#: A GFM table's delimiter row: after it, each row's cells are runs of their own until a blank line.
TABLE_DELIMITER = re.compile(
    r"^[ \t]*\|?[ \t]*:?-+:?[ \t]*(?:\|[ \t]*:?-+:?[ \t]*)+\|?[ \t]*$|^[ \t]*\|[ \t]*:?-+:?[ \t]*\|?[ \t]*$"
)
CELL = re.compile(r"((?<!\\)\|)")
TICKS = re.compile(r"(\\*)(`+)")
#: Tokens of link text: an escape, an inline tag or autolink (whose brackets are not link text), an image or
#: link opener, a closer followed by a destination, and a blank line (which ends any open link text).
BRACKETS = re.compile(r"\\.|<[^<>\n]*>|!\[|\[|\]\(|\n[ \t]*\n", re.DOTALL)
CODE, HTML, TEXT, BREAK = "code", "html", "text", "break"


def _spaces(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def _ends(line: str, ends: tuple[str, ...], start: int = 0) -> bool:
    lower = line.lower()
    return any(lower.find(end, start) != -1 for end in ends)


def _opens(line: str) -> tuple[str, tuple[str, ...] | str | None]:
    """How a line outside any block opens one: (kind, what ends it)."""
    if not line.strip():
        return BREAK, None
    fence = FENCE.match(line)
    if fence and not (fence.group(1)[0] == "`" and "`" in fence.group(2)):
        return CODE, fence.group(1)
    for start, end in HTML_ENDS:
        if found := start.match(line):
            return HTML, None if _ends(line, end, found.end()) else end
    if HTML_OTHER.match(line):
        return HTML, "blank"
    return TEXT, None


def _width(text: str) -> int:
    """Columns `text` spans, a tab reaching the next multiple of four."""
    width = 0
    for char in text:
        width += 4 - width % 4 if char == "\t" else 1
    return width


def _indent(line: str) -> int:
    return _width(line[: len(line) - len(line.lstrip(" \t"))])


def classify(lines: list[str]) -> list[str]:
    """The kind of each line: code (a fence, an indented code block, or inside one), html (inside an HTML
    block), text or break. A line indented four or more past the open list item's content column (the
    margin, outside a list) after a break is code; less indented, it may open an HTML block."""
    kinds, inside, column, indented = [], None, -1, False
    for line in lines:
        previous = kinds[-1] if kinds else BREAK
        if inside is None and line.strip():
            if item := LIST_ITEM.match(line):
                column = (
                    _width(item.group(0))
                    if len(item.group(1)) <= CODE_INDENT
                    else _width(item.group(0)) - len(item.group(1)) + 1
                )
            elif _indent(line) < LIST_INDENT and previous == BREAK:
                column = -1
            indented = _indent(line) >= max(column, 0) + CODE_INDENT and (previous == BREAK or indented)
        if inside is None and indented:
            kinds.append(CODE if line.strip() else BREAK)
        elif isinstance(inside, str) and inside[0] in "`~":
            closing = re.match(rf"^ {{0,3}}{re.escape(inside[0])}{{{len(inside)},}}[ \t]*$", line)
            inside = None if closing else inside
            kinds.append(CODE)
        elif inside is not None:
            if inside == "blank":
                inside = inside if line.strip() else None
            elif _ends(line, inside):
                inside = None
            kinds.append(HTML if line.strip() or inside is not None else BREAK)
        else:
            kind, inside = _opens(line)
            kinds.append(kind)
    return kinds


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


def image_closers(text: str) -> set[int]:
    """Offsets of each `](` that may close an image's text, in one forward pass with escapes honoured. The
    stricter reading: a `](` counts when no opener is open or any open opener is an image's, and a bare `]`
    closes nothing, since a bracket inside inline HTML, an autolink or a reference is not one this pass can
    place."""
    stack: list[bool] = []
    images = 0
    out: set[int] = set()
    for m in BRACKETS.finditer(text):
        piece = m.group(0)
        if piece in ("![", "["):
            stack.append(piece == "![")
            images += piece == "!["
        elif piece == "](":
            if not stack or images:
                out.add(m.start())
            if stack:
                images -= stack.pop()
        elif piece[0] == "\n":
            stack, images = [], 0
        # an escape or an inline tag or autolink: nothing to count
    return out
