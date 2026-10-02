"""The YAML scanner's block structure: indentation-scoped mappings and sequences, and what each value holds."""

from __future__ import annotations

from .yamlpath_blockscalar import block_scalar
from .yamlpath_cursor import WHITE, Cursor, Props
from .yamlpath_flow import flow_node
from .yamlpath_scalar import double, plain, plain_line, plain_starts, properties, single

Path = tuple[str | int, ...]
MAP, SEQ, ROOT = "map", "seq", "root"


def document(cur: Cursor) -> None:
    """Emit every node of one document; a document with no content (only `---`) is one empty scalar."""
    found = cur.next_line()
    if found < 0:
        cur.emit((), "", "plain", Props(), len(cur.text))
        return
    cur.pos += found
    value(cur, (), -1, ROOT)
    if cur.next_line() >= 0:
        msg = "content after the document's root node"
        raise cur.error(msg)


def value(cur: Cursor, path: Path, indent: int, context: str) -> None:
    """The node after `key:`, after `-`, or at a document's start; its parent block sits at `indent`."""
    cur.skip_blanks()
    props = properties(cur, flow=False)
    while cur.at_break() or cur.at_comment():
        at = cur.pos
        cur.end_line()
        found = cur.next_line()
        if found < 0 or found < indent or (found == indent and not (context == MAP and _entry(cur, found))):
            cur.emit(path, "", "plain", props, at)
            return None
        cur.pos += found
        if cur.char() not in "!&":
            return _own_line(cur, path, indent, props)
        props = _more(cur, props)
        if not (cur.at_break() or cur.at_comment()) and (_entry(cur, 0) or is_key(cur)):
            msg = "a tag or anchor on the line where a block collection starts (it would name the first key)"
            raise cur.error(msg)
    if context != MAP:
        return _own_line(cur, path, indent, props)
    if _entry(cur, 0) or is_key(cur):
        msg = "a block collection cannot start on the line of its key"
        raise cur.error(msg)
    return _inline(cur, path, indent, props)


def _more(cur: Cursor, props: Props) -> Props:
    """Properties on a line of their own, merged with those already read."""
    more = properties(cur, flow=False)
    if (props.tag and more.tag) or (props.anchor and more.anchor):
        msg = "a second tag or anchor on one node"
        raise cur.error(msg)
    return Props(props.tag or more.tag, props.anchor or more.anchor, props.pos if props.pos >= 0 else more.pos)


def _own_line(cur: Cursor, path: Path, indent: int, props: Props) -> None:
    """A node that may be a block collection: it starts here, at this column."""
    column = cur.col()
    collection = _sequence if _entry(cur, 0) else _mapping if is_key(cur) else None
    if collection is None:
        return _inline(cur, path, indent, props)
    if props.pos >= 0 and cur.line(props.pos) == cur.line():
        msg = "a tag or anchor on the line where a block collection starts (it would name the first key)"
        raise cur.error(msg)
    if "\t" in cur.text[cur.pos - column : cur.pos]:
        msg = "a tab before a block collection (loaders count its width differently)"
        raise cur.error(msg)
    if cur.line() == cur.marker:
        msg = "a block collection on the --- line"
        raise cur.error(msg)
    return collection(cur, path, column, props)


def _inline(cur: Cursor, path: Path, indent: int, props: Props) -> None:
    """A block scalar, flow collection, alias, or quoted or plain scalar; then the end of its line."""
    char, at = cur.char(), cur.pos
    if char in ("|", ">"):
        text, kind = block_scalar(cur, indent)
        cur.emit(path, text, kind, props, at)
        return
    if char in ("[", "{", "*"):
        flow_node(cur, path, props)
    elif char == "'":
        cur.emit(path, single(cur), "single", props, at)
    elif char == '"':
        cur.emit(path, double(cur), "double", props, at)
    elif plain_starts(cur, flow=False):
        cur.emit(path, plain(cur, indent, flow=False), "plain", props, at)
    else:
        msg = f"unexpected {char!r}"
        raise cur.error(msg)
    cur.end_line()


def _entry(cur: Cursor, offset: int) -> bool:
    """Whether a `-` sequence entry indicator is at pos + offset."""
    return cur.char(offset) == "-" and cur.char(offset + 1) in ("", " ", "\t", "\n")


def is_key(cur: Cursor) -> bool:
    """Whether an implicit `key:` (plain or quoted, one line) starts here."""
    saved = cur.pos
    try:
        return _key(cur) is not None
    finally:
        cur.pos = saved


def _key(cur: Cursor) -> str | None:
    """Read `key:` from here, or return None when this is not one. Leaves pos after the colon."""
    char = cur.char()
    if char in ("'", '"'):
        start = cur.line()
        key = single(cur) if char == "'" else double(cur)
        if cur.line() != start:
            return None
        cur.skip_blanks()
    elif plain_starts(cur, flow=False):
        end = plain_line(cur, cur.pos, flow=False)
        key = cur.text[cur.pos : end].rstrip(WHITE)
        cur.pos = end
    else:
        return None
    if cur.char() != ":" or cur.char(1) not in ("", " ", "\t", "\n"):
        return None
    cur.pos += 1
    return key


def _mapping(cur: Cursor, path: Path, column: int, props: Props) -> None:
    cur.emit(path, "", "map", props, cur.pos)
    cur.enter()
    while True:
        key = _key(cur)
        if key is None:
            msg = "expected a mapping key"
            raise cur.error(msg)
        value(cur, (*path, key), column, MAP)
        found = cur.next_line()
        if found < column:
            break
        if found > column:
            msg = "a mapping entry indented deeper than its siblings"
            raise cur.error(msg, cur.pos + found)
        cur.pos += found
    cur.leave()


def _sequence(cur: Cursor, path: Path, column: int, props: Props) -> None:
    cur.emit(path, "", "seq", props, cur.pos)
    cur.enter()
    index = 0
    while True:
        cur.pos += 1
        value(cur, (*path, index), column, SEQ)
        index += 1
        found = cur.next_line()
        if found < column:
            break
        if found > column:
            msg = "a sequence entry indented deeper than its siblings"
            raise cur.error(msg, cur.pos + found)
        if not _entry(cur, found):
            break
        cur.pos += found
    cur.leave()
