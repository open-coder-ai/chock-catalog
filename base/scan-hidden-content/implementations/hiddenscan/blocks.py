"""Markdown blocks read the way CommonMark reads them, far enough to blank code and find image link text."""

from __future__ import annotations

import re

#: A fence opens a code block that runs to a closing fence of the same character, at least as long; a
#: backtick fence whose info string holds a backtick is not a fence.
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
#: HTML blocks of types 1-5 run to their end marker, across blank lines; types 6 and 7 to a blank line.
HTML_ENDS = (
    (
        re.compile(r"^ {0,3}<(?:pre|script|style|textarea)(?=[\s>]|$)", re.IGNORECASE),
        re.compile(r"</(?:pre|script|style|textarea)>", re.IGNORECASE),
    ),
    (re.compile(r"^ {0,3}<!--"), re.compile(r"-->")),
    (re.compile(r"^ {0,3}<\?"), re.compile(r"\?>")),
    (re.compile(r"^ {0,3}<!\[CDATA\["), re.compile(r"\]\]>")),
    (re.compile(r"^ {0,3}<![A-Za-z]"), re.compile(r">")),
)
HTML_OTHER = re.compile(r"^ {0,3}</?[A-Za-z]")
#: Lines that start a block of their own, so a code span never pairs backticks across them.
BLOCK_START = re.compile(r"^ {0,3}(?:>|[-+*](?:[ \t]|$)|\d{1,9}[.)](?:[ \t]|$))")
#: Lines that are a whole block: an ATX heading or a thematic break.
SINGLE = re.compile(r"^ {0,3}(?:#{1,6}(?:[ \t].*)?|(?:\*[ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$")
TICKS = re.compile(r"(\\*)(`+)")
#: Tokens of link text: an escape, an image or link opener, a closer followed by a destination, a closer,
#: and a blank line (which ends any open link text).
BRACKETS = re.compile(r"\\.|!\[|\[|\]\(|\]|\n[ \t]*\n", re.DOTALL)
CODE, HTML, TEXT, BREAK = "code", "html", "text", "break"


def _spaces(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def _opens(line: str) -> tuple[str, re.Pattern[str] | str | None]:
    """How a line outside any block opens one: (kind, what ends it)."""
    if not line.strip():
        return BREAK, None
    fence = FENCE.match(line)
    if fence and not (fence.group(1)[0] == "`" and "`" in fence.group(2)):
        return CODE, fence.group(1)
    for start, end in HTML_ENDS:
        if found := start.match(line):
            return HTML, None if end.search(line, found.end()) else end
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
            elif inside.search(line):
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
    heading, a thematic break, a list item or a block quote ends the run."""
    lines = text.split("\n")
    out: list[str] = []
    segment: list[str] = []

    def flush() -> None:
        if segment:
            out.extend(_blank_spans("\n".join(segment)).split("\n"))
            segment.clear()

    for line, kind in zip(lines, classify(lines), strict=True):
        if kind == TEXT and SINGLE.match(line):
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
    """Offsets of each `](` that closes an image's text (`![...](`), escapes honoured, in one forward pass.
    A `](` with no opener is counted as an image, the stricter reading."""
    stack: list[bool] = []
    out: set[int] = set()
    for m in BRACKETS.finditer(text):
        piece = m.group(0)
        if piece in ("![", "["):
            stack.append(piece == "![")
        elif piece == "](":
            if not stack or stack.pop():
                out.add(m.start())
        elif piece == "]":
            if stack:
                stack.pop()
        elif piece[0] == "\n":
            stack.clear()
    return out
