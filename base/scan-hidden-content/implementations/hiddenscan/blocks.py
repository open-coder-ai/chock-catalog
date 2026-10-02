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
#: Tokens of link text: an escape, an image or link opener, a closer followed by a destination, and a
#: blank line (which ends any open link text).
BRACKETS = re.compile(r"\\.|!\[|\[|\]\(|\n[ \t]*\n", re.DOTALL)
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


def classify(lines: list[str]) -> list[str]:
    """The kind of each line: code (a fence or inside one), html (inside an HTML block), text or break."""
    kinds, inside = [], None
    for line in lines:
        if isinstance(inside, str) and inside[0] in "`~":
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
            flush()
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
    return out
