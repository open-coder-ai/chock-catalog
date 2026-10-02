"""Markdown blocks read the way CommonMark reads them: which lines are code, HTML, paragraph text or breaks."""

from __future__ import annotations

import re
from dataclasses import dataclass

#: A fence opens a code block that runs to a closing fence of the same character, at least as long; a
#: backtick fence whose info string holds a backtick is not a fence.
FENCE = re.compile(r"(`{3,}|~{3,})(.*)$")
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
HTML_OTHER = re.compile(r"^[ \t]*</?([A-Za-z][A-Za-z0-9-]*)")
#: CommonMark's type 6 tag names: a line opening with one starts an HTML block even inside a paragraph.
BLOCK_TAGS = set(
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
#: An indented code block starts this far past the margin or the list item's content column; a line indented
#: less than LIST_INDENT after a break ends a list.
CODE_INDENT, LIST_INDENT = 4, 2
#: A list item's marker and the spaces after it, which set the column its content starts at.
LIST_ITEM = re.compile(r"^[ \t]*(?:[-+*]|\d{1,9}[.)])([ \t]+|$)")
#: Lines that start a block of their own, so a code span never pairs backticks across them.
BLOCK_START = re.compile(r"^[ \t]*(?:>|[-+*](?:[ \t]|$)|\d{1,9}[.)](?:[ \t]|$))")
#: Lines that end a run on both sides: an ATX heading, a thematic break, a setext underline.
SINGLE = re.compile(r"^[ \t]*(?:#{1,6}(?:[ \t].*)?|(?:\*[ \t]*){3,}|(?:-[ \t]*){2,}|(?:_[ \t]*){3,}|=+[ \t]*|-[ \t]*)$")
CODE, HTML, TEXT, BREAK = "code", "html", "text", "break"


@dataclass(frozen=True)
class Fence:
    """An open fence: its opening characters, and the content column of the list item it sits in (0 outside)."""

    chars: str
    column: int


def _ends(line: str, ends: tuple[str, ...], start: int = 0) -> bool:
    lower = line.lower()
    return any(lower.find(end, start) != -1 for end in ends)


def _opens(line: str, column: int, previous: str) -> tuple[str, tuple[str, ...] | Fence | str | None]:
    """How a line outside any block opens one: (kind, what ends it). `column` is the open list item's content
    column (0 outside a list); `previous` is the kind of the line before."""
    if not line.strip():
        return BREAK, None
    fence = FENCE.match(line.lstrip(" \t"))
    if fence and _indent(line) - column < CODE_INDENT and not (fence.group(1)[0] == "`" and "`" in fence.group(2)):
        return CODE, Fence(fence.group(1), column)
    for start, end in HTML_ENDS:
        if found := start.match(line):
            return HTML, None if _ends(line, end, found.end()) else end
    # A type 7 block (a tag not on CommonMark's block list) cannot interrupt a paragraph.
    if (tag := HTML_OTHER.match(line)) and (tag.group(1).lower() in BLOCK_TAGS or previous != TEXT):
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


def _column(line: str, column: int, previous: str) -> int:
    """The open list item's content column after `line` (-1 when no list is open)."""
    if item := LIST_ITEM.match(line):
        width = _width(item.group(0))
        return width if len(item.group(1)) <= CODE_INDENT else width - len(item.group(1)) + 1
    return -1 if _indent(line) < LIST_INDENT and previous == BREAK else column


def _html_continues(inside: tuple[str, ...] | str, line: str) -> tuple[str, ...] | str | None:
    """What still ends an open HTML block after `line`, or None when the line ended it."""
    if inside == "blank":
        return inside if line.strip() else None
    return None if _ends(line, inside) else inside


def _closes(fence: Fence, line: str) -> bool:
    stripped = line.lstrip(" \t")
    if _indent(line) - fence.column >= CODE_INDENT:
        return False
    return re.fullmatch(rf"{re.escape(fence.chars[0])}{{{len(fence.chars)},}}[ \t]*", stripped) is not None


def classify(lines: list[str]) -> list[str]:
    """The kind of each line: code (a fence, an indented code block, or inside one), html (inside an HTML
    block), text or break. A line indented four or more past the open list item's content column (the
    margin, outside a list) after a break is code; less indented, it may open an HTML block. A fence opened
    inside a list item ends where the item does, at a line indented less than the item's content."""
    kinds: list[str] = []
    inside: tuple[str, ...] | Fence | str | None = None
    column, indented = -1, False
    for line in lines:
        previous = kinds[-1] if kinds else BREAK
        if isinstance(inside, Fence) and line.strip() and inside.column and _indent(line) < inside.column:
            inside = None  # the list item ended, and its fence with it
        if inside is None and line.strip():
            column = _column(line, column, previous)
            indented = _indent(line) >= max(column, 0) + CODE_INDENT and (previous == BREAK or indented)
        if inside is None and indented:
            kinds.append(CODE if line.strip() else BREAK)
        elif isinstance(inside, Fence):
            inside = None if _closes(inside, line) else inside
            kinds.append(CODE)
        elif inside is not None:
            inside = _html_continues(inside, line)
            kinds.append(HTML if line.strip() or inside is not None else BREAK)
        else:
            kind, inside = _opens(line, max(column, 0), previous)
            kinds.append(kind)
    return kinds
