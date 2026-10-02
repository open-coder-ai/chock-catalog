"""The YAML scanner's flow collections: `[a, b]` and `{k: v}`, nested, spanning lines, with comments."""

from __future__ import annotations

import re

from .yamlpath_cursor import Cursor, Props
from .yamlpath_scalar import double, name, plain, plain_starts, properties, single

#: Blanks, line breaks and comments between flow tokens; a `#` only after a blank or at a line start.
GAP = re.compile(r"(?:[ \t\n]++|(?<=[ \t\n])#[^\n]*+)*+")
Path = tuple[str | int, ...]


def skip_gap(cur: Cursor) -> None:
    cur.pos = GAP.match(cur.text, cur.pos).end()


def flow_node(cur: Cursor, path: Path, props: Props) -> None:
    """Emit the flow node here (collection, quoted, alias or plain) and everything inside it."""
    char, at = cur.char(), cur.pos
    if char == "[":
        _sequence(cur, path, props)
    elif char == "{":
        _mapping(cur, path, props)
    elif char == "*":
        if props.pos >= 0:
            msg = "an alias cannot carry a tag or anchor"
            raise cur.error(msg)
        cur.emit(path, name(cur), "alias", props, at)
    else:
        value, kind = flow_scalar(cur)
        cur.emit(path, value, kind, props, at)


def flow_scalar(cur: Cursor) -> tuple[str, str]:
    char = cur.char()
    if char == "'":
        return single(cur), "single"
    if char == '"':
        return double(cur), "double"
    if not plain_starts(cur, flow=True):
        raise cur.error(f"unexpected {char!r}" if char else "an unterminated flow collection")
    return plain(cur, -1, flow=True), "plain"


def _sequence(cur: Cursor, path: Path, props: Props) -> None:
    cur.emit(path, "", "seq", props, cur.pos)
    cur.enter()
    cur.pos += 1
    index = 0
    while not _closes(cur, "]"):
        entry = properties(cur, flow=True)
        skip_gap(cur)
        if cur.char() in (",", "]"):
            msg = "an empty entry in a flow sequence"
            raise cur.error(msg)
        flow_node(cur, (*path, index), entry)
        skip_gap(cur)
        if cur.char() == ":":
            msg = "a key: value pair inside [ ] is not supported"
            raise cur.error(msg)
        index += 1
        _separator(cur, "]")
    cur.leave()


def _mapping(cur: Cursor, path: Path, props: Props) -> None:
    cur.emit(path, "", "map", props, cur.pos)
    cur.enter()
    cur.pos += 1
    while not _closes(cur, "}"):
        if cur.char() and cur.char() in "!&*[{":
            msg = f"a flow mapping key starting with {cur.char()!r} is not supported"
            raise cur.error(msg)
        at, line = cur.pos, cur.line()
        key, _ = flow_scalar(cur)
        if cur.line() != line:
            msg = "a flow mapping key spanning lines"
            raise cur.error(msg, at)
        skip_gap(cur)
        if cur.char() == ":":
            cur.pos += 1
            skip_gap(cur)
            _value(cur, (*path, key), at)
        else:
            cur.emit((*path, key), "", "plain", Props(), cur.pos)
        _separator(cur, "}")
    cur.leave()


def _value(cur: Cursor, path: Path, at: int) -> None:
    if cur.char() in (",", "}"):
        cur.emit(path, "", "plain", Props(), at)
        return
    props = properties(cur, flow=True)
    skip_gap(cur)
    if cur.char() in (",", "}"):
        cur.emit(path, "", "plain", props, at)
        return
    flow_node(cur, path, props)
    skip_gap(cur)


def _closes(cur: Cursor, close: str) -> bool:
    skip_gap(cur)
    if cur.char() == close:
        cur.pos += 1
        return True
    return False


def _separator(cur: Cursor, close: str) -> None:
    skip_gap(cur)
    if cur.char() == ",":
        cur.pos += 1
    elif cur.char() != close:
        found = cur.char()
        raise cur.error(f"expected , or {close}, not {found!r}" if found else "an unterminated flow collection")
