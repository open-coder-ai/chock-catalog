"""Markdown with certain code blanked, and the link text that makes a destination an image's.

A code span is blanked only when it is certain: both backtick runs on one paragraph line, with no
unpaired run earlier in the paragraph (since the last blank line). On a line with a pipe it is blanked only
where both readings pair it: as GFM table cells, each pairing its own spans, and as one line, as a renderer
without tables reads it. Whether backticks pair across lines depends on where CommonMark ends a paragraph,
and whether a line is a table row on the renderer; an error there would hide a comment or a URL a renderer
passes through. Read as text instead, the worst case is a report about code.
"""

from __future__ import annotations

import re

from hiddenscan.blocks import BREAK, CODE, HTML, TEXT, classify

TICKS = re.compile(r"(\\*)(`+)")
PIPE = re.compile(r"(?<!\\)\|")
#: An inline tag or autolink as CommonMark defines them (6.6, 6.5): an open or closing tag with valid
#: attributes, or a scheme followed by a URL without spaces. Brackets inside one are not link text; any other
#: `<...>`, such as `a < b ... c > d`, is text.
ATTRIBUTE = r"""\s+[A-Za-z_:][\w.:-]*(?:\s*=\s*(?:[^\s"'=<>`]+|'[^'\n]*'|"[^"\n]*"))?"""
INLINE_TAG = rf"<[A-Za-z][A-Za-z0-9-]*(?:{ATTRIBUTE})*\s*/?>|</[A-Za-z][A-Za-z0-9-]*\s*>|<[A-Za-z][A-Za-z0-9.+-]{{1,31}}:[^\s<>]*>"
#: Tokens of link text: an escape, an inline tag or autolink, an image or link opener, a closer followed by a
#: destination, and a blank line (which ends any open link text).
ESCAPED_LT = re.compile(r"(?<!\\)((?:\\\\)*\\)<")
SWALLOWS = re.compile(r"<(?=[!?]|/[^A-Za-z])")
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


def _row(line: str) -> str:
    """A table row with each cell's code spans blanked; an unpaired backtick in a cell is literal."""
    return "|".join(_spans(cell)[0] for cell in PIPE.split(line))


def _both(line: str, one: str, other: str) -> str:
    return "".join(" " if a == " " and b == " " else c for c, a, b in zip(line, one, other, strict=True))


def blank_code(text: str) -> str:
    """Markdown with what is certainly code replaced by spaces, newlines kept: code is shown, not fetched or
    hidden."""
    lines = text.split("\n")
    out: list[str] = []
    unsure = False
    for line, kind in zip(lines, classify(lines), strict=True):
        if kind == CODE:
            out.append(re.sub(r"[^\n]", " ", line))
            continue
        unsure = unsure and kind != BREAK
        if kind != TEXT or unsure:
            unsure = unsure or "`" in line
            out.append(line)
            continue
        blanked, unsure = _spans(line)
        out.append(_both(line, blanked, _row(line)) if PIPE.search(line) else blanked)
    return "\n".join(out)


def tag_view(raw: str, blanked: str) -> str:
    """The raw text with only the '<' and '>' of code removed: a renderer escapes them, so code opens and
    closes no tag or comment, while the words in code stay countable inside a hidden element or comment."""
    return "".join(" " if r in "<>" and b == " " else r for r, b in zip(raw, blanked, strict=True))


def escaped_view(tags: str) -> str:
    """The tag view with each backslash-escaped '<' removed: outside an HTML block CommonMark shows `\\<` as a
    literal '<', which opens no tag or comment. Inside an HTML block the backslash is literal and the '<'
    opens one, and which lines are in a block is not certain, so the gate reads both views."""
    return ESCAPED_LT.sub(lambda m: m.group(1) + " ", tags)


def closed_view(text: str, view: str) -> str:
    """The view with a '>' opening each line a renderer may open with its own tag: every line outside an HTML
    block, each block's first line, and each line after a blank one (where an HTML block of type 6-7 ends).
    There a renderer writes </p>, <li> and the like, and raw HTML in a paragraph must close within it, so a
    bogus comment, declaration or tag left open above ends there. Which lines those are is not certain, so
    the gate reads this view beside the view as written."""
    raw = text.split("\n")
    lines, kinds = view.split("\n"), classify(raw)
    return "\n".join(
        line if kind == HTML and at and kinds[at - 1] == HTML and raw[at - 1].strip() else ">" + line
        for at, (line, kind) in enumerate(zip(lines, kinds, strict=True))
    )


def flat_view(view: str) -> str:
    """The view with no '<' that opens a comment, a declaration, a processing instruction or a bogus comment:
    in Markdown this reader is not certain which of them a renderer passes through, and each swallows the
    markup after it, so the gate also reads every tag as if none did."""
    return SWALLOWS.sub(" ", view)


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
