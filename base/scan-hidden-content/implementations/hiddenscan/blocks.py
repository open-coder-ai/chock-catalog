"""Markdown lines sorted into those that are certainly code, HTML blocks, paragraph text and breaks.

Only code this reader is certain of is blanked: a fence or an indented code block outside any list item and
block quote. Inside one, deciding what is code means modelling every container rule of CommonMark, and an
error there would hide a comment a renderer passes through; read as text instead, the worst case is a report
about code the reader can see.
"""

from __future__ import annotations

import re

#: A fence opens a code block that runs to a closing fence of the same character, at least as long; a
#: backtick fence whose info string holds a backtick is not a fence.
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
CLOSER = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*$")
FENCE_LIKE = re.compile(r"^[ \t>]*(?:[-+*]|\d{1,9}[.)])?[ \t>]*(?:`{3,}|~{3,})")
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
#: Any indentation: reading a line as an HTML block only keeps it from being blanked.
HTML_OTHER = re.compile(r"^[ \t]*</?([A-Za-z][A-Za-z0-9-]*)")
#: CommonMark's type 6 tag names: a line opening with one starts an HTML block even inside a paragraph.
BLOCK_TAGS = frozenset(
    [
        "address",
        "article",
        "aside",
        "base",
        "basefont",
        "blockquote",
        "body",
        "caption",
        "center",
        "col",
        "colgroup",
        "dd",
        "details",
        "dialog",
        "dir",
        "div",
        "dl",
        "dt",
        "fieldset",
        "figcaption",
        "figure",
        "footer",
        "form",
        "frame",
        "frameset",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "head",
        "header",
        "hr",
        "html",
        "iframe",
        "legend",
        "li",
        "link",
        "main",
        "menu",
        "menuitem",
        "nav",
        "noframes",
        "ol",
        "optgroup",
        "option",
        "p",
        "param",
        "search",
        "section",
        "summary",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "title",
        "tr",
        "track",
        "ul",
    ]
)
#: A line that may open a list item or a block quote. From it until a line indented less than LIST_INDENT
#: after a blank line, no code is certain: an item's content column, lazy continuation and quote nesting
#: decide what is code there.
CONTAINER = re.compile(r"^[ \t]*(?:>|[-+*](?:[ \t]|$)|\d{1,9}[.)](?:[ \t]|$))")
#: Lines that close a paragraph without being one: an ATX heading, a thematic break, a setext underline.
CLOSES_PARAGRAPH = re.compile(
    r"^[ \t]{0,3}(?:#{1,6}(?:[ \t].*)?|(?:\*[ \t]*){3,}|(?:-[ \t]*){2,}|(?:_[ \t]*){3,}|=+[ \t]*|-[ \t]*)$"
)
#: List and block quote markers before a line's content: an HTML block opens after them as well.
MARKERS = re.compile(r"^(?:[ \t]*(?:>|(?:[-+*]|\d{1,9}[.)])(?=[ \t])))*")
CODE_INDENT, LIST_INDENT = 4, 2
CODE, HTML, TEXT, BREAK = "code", "html", "text", "break"


def _ends(line: str, ends: tuple[str, ...], start: int = 0) -> bool:
    lower = line.lower()
    return any(lower.find(end, start) != -1 for end in ends)


def _indent(line: str) -> int:
    width = 0
    for char in line[: len(line) - len(line.lstrip(" \t"))]:
        width += 4 - width % 4 if char == "\t" else 1
    return width


def _html(line: str, *, paragraph: bool) -> tuple[str, ...] | str | None:
    """What ends the HTML block `line` opens ("" when it ends on that line), or None when it opens none."""
    line = line[MARKERS.match(line).end() :]
    for start, end in HTML_ENDS:
        if found := start.match(line):
            return "" if _ends(line, end, found.end()) else end
    # A type 7 block (a tag not on CommonMark's block list) cannot interrupt a paragraph.
    if (tag := HTML_OTHER.match(line)) and (tag.group(1).lower() in BLOCK_TAGS or not paragraph):
        return "blank"
    return None


def _continues(inside: tuple[str, ...] | str, line: str) -> tuple[str, ...] | str | None:
    """What still ends an open block after `line`, or None when the line ended it."""
    if inside == "blank":
        return inside if line.strip() else None
    if isinstance(inside, str):  # a fence: its opening characters
        closing = re.match(rf"^ {{0,3}}{re.escape(inside[0])}{{{len(inside)},}}[ \t]*$", line)
        return None if closing else inside
    return None if _ends(line, inside) else inside


def _closers(lines: list[str]) -> list[dict[str, int]]:
    """For each line, the longest closing fence of each character at or after it, in one backward pass."""
    out: list[dict[str, int]] = [{}] * (len(lines) + 1)
    for at in range(len(lines) - 1, -1, -1):
        out[at] = dict(out[at + 1])
        if found := CLOSER.match(lines[at]):
            run = found.group(1)
            out[at][run[0]] = max(out[at].get(run[0], 0), len(run))
    return out


def _certain_fence(line: str, at: int, closers: list[dict[str, int]]) -> str | None:
    """The opening characters of a fence `line` opens that a later line closes, else None."""
    fence = FENCE.match(line)
    if not fence or (fence.group(1)[0] == "`" and "`" in fence.group(2)):
        return None
    return fence.group(1) if closers[at + 1].get(fence.group(1)[0], 0) >= len(fence.group(1)) else None


def classify(lines: list[str]) -> list[str]:
    """The kind of each line: code (certainly code), html (inside an HTML block), text or break.

    A fence is certain only when a later line closes it and no fence-like line before it was left unread
    (inside a container, or unclosed): after one, which lines pair as fences is no longer certain, so no
    later fence is blanked."""
    kinds: list[str] = []
    inside: tuple[str, ...] | str | None = None
    after: str | None = None  # what is still open when a block opened inside a type 6-7 block ends
    contained = paragraph = indented = doubtful = piped = False
    closers = _closers(lines)
    for at, line in enumerate(lines):
        previous = kinds[-1] if kinds else BREAK
        if inside is not None:
            fence = isinstance(inside, str) and inside[0] in "`~"
            # If the line that opened a type 6-7 block was text after all, a type 1-5 block may open here and
            # run past blank lines: the block is read to its end, then to a blank line.
            if inside == "blank" and isinstance(nested := _html(line, paragraph=False), tuple):
                inside, after = nested, inside
            elif (inside := _continues(inside, line)) is None:
                inside, after = after, None
            kinds.append(CODE if fence else HTML if line.strip() or inside is not None else BREAK)
            continue
        if not line.strip():
            paragraph = False
            kinds.append(BREAK)
            continue
        ends_lists = _indent(line) < LIST_INDENT and previous == BREAK
        # Outside a container, a line indented four or more is code, not a list item or quote it may look like.
        opens = bool(CONTAINER.match(line)) and (contained or _indent(line) < CODE_INDENT)
        contained = opens or (contained and not ends_lists)
        indented = not contained and _indent(line) >= CODE_INDENT and (indented or previous == BREAK)
        fence = None if contained or doubtful or indented else _certain_fence(line, at, closers)
        doubtful = doubtful or (not indented and fence is None and FENCE_LIKE.match(line) is not None)
        if indented:
            kinds.append(CODE)
        elif fence:
            inside, paragraph = fence, False
            kinds.append(CODE)
        # A type 7 line continues a paragraph only when the paragraph is certain: in a container its lines may be
        # code, and whether a tag ends a GFM table is up to the renderer.
        elif (ends := _html(line, paragraph=paragraph and not contained and not piped)) is not None:
            inside, paragraph = ends or None, False
            kinds.append(HTML)
        else:
            piped = (paragraph and piped) or "|" in line
            paragraph = not CLOSES_PARAGRAPH.match(line)
            kinds.append(TEXT)
    return kinds
