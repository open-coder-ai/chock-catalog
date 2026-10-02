"""Read JSONC (JSON with comments and trailing commas) as editor config loaders do, and report what a duplicate hides.

`strip` blanks comments, trailing commas and one leading BOM to spaces, keeping every line break, so
offsets, lines and columns in the result are those of the input. `loads` parses the result with the
stdlib `json` module and keeps the last of duplicate keys, as JSON.parse and jsonc-parser do, while
listing every duplicate with all of its values.

Fail closed: anything the loaders could read differently raises JsoncError rather than guessing.
Limit: a superset of strict JSON. A file read here may be refused by a strict loader (comments or a
trailing comma in a file parsed by JSON.parse alone), and a file a tolerant loader recovers from
(jsonc-parser keeps going after an error) raises here.
"""

from __future__ import annotations

import json
import re
from typing import NamedTuple

LIMIT = 1 << 20
MAX_DEPTH = 256
#: Longer than any config number; a huge integer converts in quadratic time when sys int limits are lifted.
MAX_VALUE = 1000
BOM = "\ufeff"
#: Line breaks TypeScript's scanner ends a `//` comment at, but jsonc-parser and strip-json-comments do not.
AMBIGUOUS_BREAKS = "\u2028\u2029"

_TOKEN = re.compile(
    r'(?P<string>"[^"\\\r\n]*(?:\\[^\r\n][^"\\\r\n]*)*")'
    r'|(?P<open_string>")'
    r"|(?P<line>//[^\r\n]*)"
    r"|(?P<block>/\*)"
    r"|(?P<open>[\[{])"
    r"|(?P<close>[\]}])"
    r"|(?P<comma>,)"
    r"|(?P<space>[ \t\r\n]+)"
    r'|(?P<value>[^"/,\[\]{} \t\r\n]+|/)'
)
_INK = re.compile(r"[^\r\n]")


class JsoncError(ValueError):
    """Text that cannot be read as JSONC; `pos` is an offset into the input (None when unknown), `line`/`col` 1-based."""

    def __init__(self, msg: str, text: str, pos: int | None) -> None:
        self.msg = msg
        self.pos = pos
        self.line, self.col = _line_col(text, pos) if pos is not None else (None, None)
        where = f" at line {self.line} column {self.col}" if pos is not None else ""
        super().__init__(f"{msg}{where}")


class Duplicate(NamedTuple):
    """A key given more than once in one object: its path (key last) and every value in source order."""

    path: tuple[str | int, ...]
    values: tuple[object, ...]


class Document(NamedTuple):
    """The parsed value (the last of duplicate keys kept) and every duplicate key, hidden values included."""

    value: object
    duplicates: tuple[Duplicate, ...]


def strip(text: str, limit: int = LIMIT) -> str:
    """`text` with comments, trailing commas and a leading BOM blanked to spaces; same length and line breaks.

    Raises JsoncError for text over `limit` characters, nesting over MAX_DEPTH, a number or literal over
    MAX_VALUE characters, an unterminated string or block comment, and a `//` comment the loaders end at
    different places. It does not validate JSON: `loads` does.
    """
    if len(text) > limit:
        msg = f"larger than {limit} characters"
        raise JsoncError(msg, text, None)
    blanks: list[tuple[int, int]] = [(0, 1)] if text.startswith(BOM) else []
    pos = len(BOM) if blanks else 0
    depth = 0
    last = ""
    comma: int | None = None
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        kind, end = match.lastgroup, match.end()  # every character matches an alternative
        if kind in {"line", "block", "open_string"}:
            end = _trivia_end(text, kind, pos, end)
            blanks.append((pos, end))
        elif kind != "space":
            if kind == "value" and end - pos > MAX_VALUE:
                msg = f"a number or literal longer than {MAX_VALUE} characters"
                raise JsoncError(msg, text, pos)
            if kind == "close" and comma is not None:
                blanks.append((comma, comma + 1))
            comma = pos if kind == "comma" and last in {"value", "string", "close"} else None
            depth += {"open": 1, "close": -1}.get(kind, 0)
            if depth > MAX_DEPTH:
                msg = f"nested deeper than {MAX_DEPTH}"
                raise JsoncError(msg, text, pos)
            last = kind
        pos = end
    return _blank(text, blanks)


def loads(text: str, limit: int = LIMIT) -> Document:
    """Parse JSONC: the last of duplicate keys wins in `value`, and `duplicates` lists each one with all its values.

    Raises JsoncError for anything `strip` refuses, invalid JSON, and NaN/Infinity.
    """
    clean = strip(text, limit)
    found: dict[int, tuple[dict[str, object], list[tuple[str, tuple[object, ...]]]]] = {}

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        obj: dict[str, object] = {}
        seen: dict[str, list[object]] = {}
        for key, val in items:
            seen.setdefault(key, []).append(val)
            obj[key] = val
        repeated = [(key, tuple(vals)) for key, vals in seen.items() if len(vals) > 1]
        if repeated:
            found[id(obj)] = (obj, repeated)
        return obj

    try:
        value = json.loads(clean, object_pairs_hook=pairs, parse_constant=_refuse_constant)
    except json.JSONDecodeError as exc:
        raise JsoncError(exc.msg, text, exc.pos) from None
    except ValueError as exc:
        raise JsoncError(str(exc), text, None) from None
    duplicates: list[Duplicate] = []
    if found:
        _walk(value, [], found, duplicates)
    return Document(value, tuple(duplicates))


def _trivia_end(text: str, kind: str, start: int, end: int) -> int:
    """Where a comment starting at `start` ends; an unterminated one, or one the loaders end differently, raises."""
    if kind == "open_string":
        msg = "unterminated string"
        raise JsoncError(msg, text, start)
    if kind == "block":
        end = text.find("*/", start + 2) + 2
        if end == 1:
            msg = "unterminated block comment"
            raise JsoncError(msg, text, start)
        return end
    for i, char in enumerate(text[start:end], start):
        if char in AMBIGUOUS_BREAKS:
            msg = f"U+{ord(char):04X} in a // comment ends it for some loaders only"
            raise JsoncError(msg, text, i)
    if text.startswith("\r", end) and not text.startswith("\r\n", end):
        msg = "a // comment ended by a lone CR ends there for some loaders only"
        raise JsoncError(msg, text, end)
    return end


def _blank(text: str, spans: list[tuple[int, int]]) -> str:
    """`text` with every span's characters but CR and LF replaced by spaces."""
    out: list[str] = []
    pos = 0
    for start, end in sorted(spans):
        out += [text[pos:start], _INK.sub(" ", text[start:end])]
        pos = end
    out.append(text[pos:])
    return "".join(out)


def _refuse_constant(name: str) -> object:
    """NaN and Infinity are Python's extension, not JSON; JSON.parse and jsonc-parser refuse them."""
    msg = f"{name} is not JSON"
    raise ValueError(msg)


def _walk(
    node: object,
    path: list[str | int],
    found: dict[int, tuple[dict[str, object], list[tuple[str, tuple[object, ...]]]]],
    out: list[Duplicate],
) -> None:
    """Append each duplicate under `node`, in document order, descending into the values a duplicate hides."""
    if isinstance(node, dict):
        hidden = dict(found[id(node)][1]) if id(node) in found else {}
        for key, val in node.items():
            path.append(key)
            if key in hidden:
                out.append(Duplicate(tuple(path), hidden[key]))
                for earlier in hidden[key][:-1]:
                    _walk(earlier, path, found, out)
            _walk(val, path, found, out)
            path.pop()
    elif isinstance(node, list):
        for i, val in enumerate(node):
            path.append(i)
            _walk(val, path, found, out)
            path.pop()


def _line_col(text: str, pos: int) -> tuple[int, int]:
    """1-based line and column of offset `pos`, with CRLF, CR and LF each one line break."""
    head = text[:pos]
    line = head.count("\n") + head.count("\r") - head.count("\r\n") + 1
    start = max(head.rfind("\n"), head.rfind("\r")) + 1
    return line, pos - start + 1
