"""The YAML scanner's scalars: plain, quoted and block, with YAML 1.2 folding and escapes; tags, anchors, aliases."""

from __future__ import annotations

import re

from .yamlpath_cursor import BLANKS, SPACES, WHITE, Cursor, Props

#: Plain text on one line: stops at `: `, ` #` and the break. Possessive, so it never backtracks.
BLOCK_PLAIN = re.compile(r"(?:[^: \t\n]|:(?=[^ \t\n])| ++(?=[^# \t\n]))*+")
#: The same inside [ ] or { }, where , [ ] { } also end it and `:` before one of them is an indicator.
FLOW_PLAIN = re.compile(r"(?:[^: \t\n,\[\]{}]|:(?=[^ \t\n,\[\]{}])| ++(?=[^# \t\n,\[\]{}]))*+")
SINGLE_RUN = re.compile(r"[^'\n]*+")
DOUBLE_RUN = re.compile(r'[^"\\\n]*+')
#: libyaml's anchor alphabet; YAML 1.2 allows more, which 1.1 loaders split differently, so more is refused.
NAME = re.compile(r"[A-Za-z0-9_-]++")
#: YAML's tag alphabet (URI characters, %-escapes); only the ! and !! handles, since %TAG is not applied.
URI = r"(?:[0-9A-Za-z\-#;/?:@&=+$,_.!~*'()\[\]]|%[0-9A-Fa-f]{2})"
TAG_CHAR = r"(?:[0-9A-Za-z\-#;/?:@&=+$_.~*'()]|%[0-9A-Fa-f]{2})"
TAG = re.compile(rf"!<{URI}++>|!!?{TAG_CHAR}++|!(?=[ \t\n]|$)")
INDICATORS = "-?:,[]{}#&*!|>'\"%@`"
FLOW_INDICATORS = ",[]{}"
ENDS = ("", " ", "\t", "\n")
ESCAPES = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r",
    "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0", "L": "\u2028", "P": "\u2029",
}  # fmt: skip
HEX = {"x": 2, "u": 4, "U": 8}
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def plain_starts(cur: Cursor, *, flow: bool) -> bool:
    """Whether a plain scalar may start here: not an indicator, or `-?:` followed by a safe character."""
    first, second = cur.char(), cur.char(1)
    if flow and first in "?:":
        return False  # YAML 1.1 loaders read `?x` and `:x` in [ ] or { } as a key or value: refused, not guessed
    if first in "-?:":
        return second not in ENDS and not (flow and second in FLOW_INDICATORS)
    return first not in INDICATORS


def plain(cur: Cursor, indent: int, *, flow: bool) -> str:
    """A plain scalar from here, folded over continuation lines indented more than `indent` (any, in flow)."""
    end = plain_line(cur, cur.pos, flow=flow)
    parts = [cur.text[cur.pos : end].rstrip(WHITE)]
    cur.pos = end
    while (more := _continuation(cur, indent, flow=flow)) is not None:
        start, breaks = more
        end = plain_line(cur, start, flow=flow)
        parts += [" " if breaks == 1 else "\n" * (breaks - 1), cur.text[start:end].rstrip(WHITE)]
        cur.pos = end
    return "".join(parts)


def plain_line(cur: Cursor, start: int, *, flow: bool) -> int:
    """Where the plain text from `start` ends on its line; a tab between its words is refused.

    libyaml ends a plain scalar at a tab (and then fails, or in [ ] reads what follows as a new token),
    where YAML 1.2 keeps the tab as text: the two would disagree on what the scalar is.
    """
    end = (FLOW_PLAIN if flow else BLOCK_PLAIN).match(cur.text, start).end()
    after = BLANKS.match(cur.text, end).end()
    if "\t" in cur.text[end:after] and not (after == len(cur.text) or _stops(cur.text, after, flow=flow)):
        msg = "a tab inside a plain scalar"
        raise cur.error(msg, end)
    return end


def _continuation(cur: Cursor, indent: int, *, flow: bool) -> tuple[int, int] | None:
    """Where the scalar's next line of text starts and how many breaks lead there; None when it ends here."""
    text = cur.text
    at = BLANKS.match(text, cur.pos).end()
    breaks = 0
    while at < len(text) and text[at] == "\n":
        breaks += 1
        line = at + 1
        lead = SPACES.match(text, line).end()
        at = BLANKS.match(text, lead).end()
        if at < len(text) and text[at] != "\n":
            deep = flow or lead - line > indent
            return (at, breaks) if deep and not _stops(text, at, flow=flow) else None
    return None


def _stops(text: str, at: int, *, flow: bool) -> bool:
    char, after = text[at], text[at + 1 : at + 2]
    if char in "\n#" or (flow and char in FLOW_INDICATORS):
        return True
    return char == ":" and (after in ENDS or (flow and after in FLOW_INDICATORS))


def single(cur: Cursor) -> str:
    """A single-quoted scalar: '' is a quote; line breaks fold."""
    text, start, at = cur.text, cur.pos, cur.pos + 1
    parts: list[str] = []
    while True:
        end = SINGLE_RUN.match(text, at).end()
        parts.append(text[at:end])
        at = end
        if at >= len(text):
            msg = "an unterminated quoted scalar"
            raise cur.error(msg, start)
        if text[at] == "\n":
            parts[-1] = parts[-1].rstrip(WHITE)
            at = _fold(text, at, parts)
        elif text[at + 1 : at + 2] == "'":
            parts.append("'")
            at += 2
        else:
            cur.pos = at + 1
            return "".join(parts)


def double(cur: Cursor) -> str:
    """A double-quoted scalar: every YAML 1.2 escape, escaped line breaks, folding."""
    text, start, at = cur.text, cur.pos, cur.pos + 1
    parts: list[str] = []
    while True:
        end = DOUBLE_RUN.match(text, at).end()
        parts.append(text[at:end])
        at = end
        if at >= len(text):
            msg = "an unterminated quoted scalar"
            raise cur.error(msg, start)
        if text[at] == '"':
            cur.pos = at + 1
            return "".join(parts)
        if text[at] == "\n":
            parts[-1] = parts[-1].rstrip(WHITE)
            at = _fold(text, at, parts)
        else:
            at = _escape(cur, at, parts)


def _fold(text: str, at: int, parts: list[str]) -> int:
    """Fold the break at `at` and any blank lines after it; return where the next line's text starts."""
    breaks = 0
    while at < len(text) and text[at] == "\n":
        breaks += 1
        at = BLANKS.match(text, at + 1).end()
    parts.append(" " if breaks == 1 else "\n" * (breaks - 1))
    return at


def _escape(cur: Cursor, at: int, parts: list[str]) -> int:
    text, code = cur.text, cur.text[at + 1 : at + 2]
    if code == "\n":
        breaks = 0
        at = BLANKS.match(text, at + 2).end()
        while at < len(text) and text[at] == "\n":
            breaks += 1
            at = BLANKS.match(text, at + 1).end()
        parts.append("\n" * breaks)
        return at
    if code in ESCAPES:
        parts.append(ESCAPES[code])
        return at + 2
    width = HEX.get(code, 0)
    digits = text[at + 2 : at + 2 + width]
    if not width or len(digits) != width or not set(digits) <= HEX_DIGITS:
        msg = f"an invalid escape \\{code}"
        raise cur.error(msg, at)
    value = int(digits, 16)
    if 0xD800 <= value <= 0xDFFF or value > 0x10FFFF:  # noqa: PLR2004 -- the surrogates and the Unicode ceiling
        msg = f"an escape that is not a character: \\{code}{digits}"
        raise cur.error(msg, at)
    parts.append(chr(value))
    return at + 2 + width


def properties(cur: Cursor, *, flow: bool) -> Props:
    """A node's tag and anchor, in either order, each at most once; position of the first."""
    tag = anchor = ""
    first = -1
    while (mark := cur.char()) in ("!", "&"):
        first = cur.pos if first < 0 else first
        if mark == "!":
            if tag:
                msg = "a second tag on one node"
                raise cur.error(msg)
            tag = _tag(cur)
        else:
            if anchor:
                msg = "a second anchor on one node"
                raise cur.error(msg)
            anchor = name(cur)
        # A tag must end at a blank: YAML 1.1 loaders read , [ ] { } as part of it, 1.2 loaders end it there.
        if cur.char() not in ENDS and not (flow and mark == "&" and cur.char() in FLOW_INDICATORS):
            msg = f"unexpected {cur.char()!r} after a tag or anchor"
            raise cur.error(msg)
        cur.skip_blanks()
    return Props(tag, anchor, first)


def _tag(cur: Cursor) -> str:
    found = TAG.match(cur.text, cur.pos)
    if not found:
        msg = "a tag with a character outside YAML's tag alphabet"
        raise cur.error(msg)
    cur.pos = found.end()
    return found.group()


def name(cur: Cursor) -> str:
    """The anchor or alias name after `&` or `*`."""
    found = NAME.match(cur.text, cur.pos + 1)
    end = found.end() if found else cur.pos + 1
    if not found or not (cur.text[end : end + 1] in ENDS or cur.text[end] in FLOW_INDICATORS):
        msg = "an anchor or alias name other than letters, digits, - and _"
        raise cur.error(msg)
    cur.pos = end
    return found.group()
