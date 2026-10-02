"""Markdown paragraphs as a renderer writes them: only complete inline HTML passes through raw.

In a paragraph, CommonMark passes raw HTML through only as a complete inline construct (6.6): an open or
closing tag, a comment, a processing instruction, a declaration or a CDATA section, each within the paragraph.
Every other '<' and '>' is text it escapes, so a stray --> or ?> there closes nothing a block above opened.
This reading keeps HTML-block and code lines as the tag view has them and paragraphs as a renderer writes them.
"""

from __future__ import annotations

import bisect
import re

from hiddenscan.blocks import CLOSES_PARAGRAPH, CODE, CONTAINER, TEXT, classify
from hiddenscan.spans import INLINE_TAG

TAG = re.compile(INLINE_TAG)
#: Where each construct starts, and what ends it (None: a tag or autolink, matched by TAG).
OPENERS = (("<!-->", ""), ("<!--->", ""), ("<!--", "-->"), ("<?", "?>"), ("<![CDATA[", "]]>"), ("<!", ">"))
DECLARATION = re.compile(r"<![A-Za-z]")


class _Ends:
    """The positions of each closing string in a paragraph, found once: each lookup is a bisection."""

    def __init__(self, chunk: str) -> None:
        self.at = {end: [m.start() for m in re.finditer(re.escape(end), chunk)] for _, end in OPENERS if end}

    def after(self, end: str, start: int) -> int:
        found = self.at[end]
        k = bisect.bisect_left(found, start)
        return found[k] + len(end) if k < len(found) else -1


def _construct(chunk: str, at: int, ends: _Ends) -> int:
    """The end of the raw HTML construct starting at `at`, or -1 when the '<' there is text."""
    for opener, end in OPENERS:
        if chunk.startswith(opener, at):
            if not end:
                return at + len(opener)
            if opener == "<!" and not DECLARATION.match(chunk, at):
                return -1
            return ends.after(end, at + len(opener))
    found = TAG.match(chunk, at)
    return found.end() if found else -1


def _escape(chunk: str) -> str:
    """A paragraph with every '<' and '>' outside a complete inline construct, or escaped, made a space."""
    ends = _Ends(chunk)
    out = list(chunk)
    i, n = 0, len(chunk)
    while i < n:
        char = chunk[i]
        if char == "\\" and i + 1 < n:
            if chunk[i + 1] in "<>":
                out[i + 1] = " "
            i += 2
        elif char == "<" and (end := _construct(chunk, i, ends)) > 0:
            i = end
        else:
            if char in "<>":
                out[i] = " "
            i += 1
    return "".join(out)


def view(text: str, tags: str) -> str:
    """The tag view with each paragraph as a renderer writes it, newlines and length kept."""
    raw, lines = text.split("\n"), tags.split("\n")
    kinds = classify(raw, least_html=True)
    out: list[str] = []
    para: list[str] = []
    for line, source, kind in zip(lines, raw, kinds, strict=True):
        starts = kind != TEXT or CONTAINER.match(source) or CLOSES_PARAGRAPH.match(source)
        if para and starts:
            out += _escape("\n".join(para)).split("\n")
            para = []
        if kind == CODE:  # code as this reading places it, which a renderer escapes
            out.append(line.replace("<", " ").replace(">", " "))
        elif kind != TEXT:
            out.append(line)
        elif CLOSES_PARAGRAPH.match(source):
            out += _escape(line).split("\n")
        else:
            para.append(line)
    if para:
        out += _escape("\n".join(para)).split("\n")
    return "\n".join(out)
