"""One linear pass over XML text: start, end and empty-element tags and character data, never an XML parser.

Comments are skipped, CDATA is character data, and a DOCTYPE (entity definitions could hide a value), an
unclosed tag, comment or CDATA section, or a quote left open inside a tag raises XmlError. Every character
is visited once, so hostile input cannot make it slower than linear.
"""

from __future__ import annotations

import html
import re
from typing import NamedTuple

ATTR = re.compile(r"""([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")
NAME = re.compile(r"\s*([\w:.-]+)")


class XmlError(ValueError):
    pass


class Token(NamedTuple):
    """kind: start, end, empty (a self-closing tag) or text; name lower-cased; pos is the offset of '<' or the text."""

    kind: str
    name: str
    attrs: dict[str, str]
    text: str
    pos: int


def _attrs(body: str) -> dict[str, str]:
    return {m[1].lower(): html.unescape(m[2] if m[2] is not None else m[3]) for m in ATTR.finditer(body)}


def _tag_end(text: str, start: int) -> int:
    """The offset of the '>' closing the tag opened at `start`; a '>' inside a quoted value does not count."""
    quote = ""
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            quote = "" if char == quote else quote
        elif char in "\"'":
            quote = char
        elif char == ">":
            return index
    msg = "an unclosed tag or quote"
    raise XmlError(msg)


def _special(text: str, start: int, out: list[Token]) -> int:
    """A comment (skipped), CDATA section (text) or DOCTYPE (refused) at `start`; the offset after it."""
    for opener, closer in (("<!--", "-->"), ("<![CDATA[", "]]>")):
        if text.startswith(opener, start):
            end = text.find(closer, start + len(opener))
            if end < 0:
                msg = f"an unclosed {opener}"
                raise XmlError(msg)
            if opener == "<![CDATA[":
                out.append(Token("text", "", {}, text[start + len(opener) : end], start))
            return end + len(closer)
    msg = "a DOCTYPE or other declaration is not read here"
    raise XmlError(msg)


def tokens(text: str) -> list[Token]:
    """Every tag and run of character data, in order; XmlError for what is refused (see the module)."""
    out: list[Token] = []
    index = 0
    while (start := text.find("<", index)) >= 0:
        if start > index:
            out.append(Token("text", "", {}, html.unescape(text[index:start]), index))
        if text.startswith("<!", start):
            index = _special(text, start, out)
            continue
        end = _tag_end(text, start + 1)
        body = text[start + 1 : end]
        index = end + 1
        if body.startswith("?"):
            continue
        closing = body.startswith("/")
        match = NAME.match(body, 1 if closing else 0)
        name = match[1].lower() if match else ""
        kind = "end" if closing else "empty" if body.rstrip().endswith("/") else "start"
        out.append(Token(kind, name, {} if closing else _attrs(body), "", start))
    if index < len(text):
        out.append(Token("text", "", {}, html.unescape(text[index:]), index))
    return out


def element_texts(found: list[Token], names: frozenset[str]) -> list[tuple[str, str, int]]:
    """(element name, its character data joined, offset) for every element named in `names`."""
    out: list[tuple[str, str, int]] = []
    open_: list[tuple[str, int, list[str]]] = []
    for token in found:
        if token.kind == "start" and token.name in names:
            open_.append((token.name, token.pos, []))
        elif token.kind == "text" and open_:
            open_[-1][2].append(token.text)
        elif token.kind == "end" and open_ and token.name == open_[-1][0]:
            name, pos, parts = open_.pop()
            out.append((name, "".join(parts).strip(), pos))
    return out
