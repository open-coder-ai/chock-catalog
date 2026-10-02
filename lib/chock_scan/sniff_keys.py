"""The top-level keys of YAML or JSON text, read line by line without a YAML parser, for the content sniffer.

A unit is the root mapping of one YAML document, or one mapping item of a root sequence (an Ansible
play), or the root object of JSON text. Keys this reader cannot name (an explicit `?` key, an
alias of an anchor that is not one simple scalar on its line) are counted as opaque, so the
sniffer can stay suspicious of them.
"""

from __future__ import annotations

import json
import re
from typing import NamedTuple

BOM = "\ufeff"
#: YAML's line breaks (1.1 adds NEL, LS and PS); str.splitlines would also split at \v, \f and \x1c-\x1e.
LINES = re.compile("\r\n|[\r\n\x85\u2028\u2029]")
DOC_MARK = re.compile(r"(?:---|\.\.\.)(?:\s|$)")
PROPS = re.compile(r"(?:[!&]\S*+[ \t]++)+")
QUOTED = re.compile(r"""("(?:[^"\\]|\\.)*+"|'(?:[^']|'')*+')[ \t]*:""")
ALIAS = re.compile(r"\*([^\s,\[\]{}]+)")
SCALAR = r"""("(?:[^"\\\n]|\\.)*+"|'(?:[^'\n]|'')*+'|[^\s,\[\]{}#'"|>!&*](?:[^\s,\[\]{}#:]|:(?=[^\s,\[\]{}]))*+)"""
ANCHOR = re.compile(r"&([^\s,\[\]{}&]++)")
#: The scalar an anchor names, when it is one whole simple scalar (tags dropped); else the anchor is unknown.
ANCHORED = re.compile(r"[ \t]++(?:![^\s]*+[ \t]++)*+" + SCALAR + r"(?=[ \t]*+(?:[,\]}:#]|$))")
LOOSE = re.compile(
    r"""(?<![^\s{,\[/])("(?:[^"\\\n]|\\.)*+"|'(?:[^'\n]|'')*+'|[^\s"'{}\[\],:#][^\s"'{}\[\],:]*+)[ \t]*:"""
)
#: A JSON-style key whose colon may sit on a later line (`"key"` newline `: value`).
SPLIT_KEY = re.compile(r"""(?<![^\s{,\[/])("(?:[^"\\\n]|\\.)*+")\s*+:""")
ESCAPE = re.compile(r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)", re.DOTALL)
SIMPLE = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r", "e": "\x1b"}
SIMPLE |= {"N": "\x85", "_": "\xa0", "L": "\u2028", "P": "\u2029"}
MAX_CODE = 0x10FFFF
INDICATORS = frozenset("-?:,[]{}#&*!|>'\"%@`")


class Unit(NamedTuple):
    """One mapping's keys; `opaque` counts keys this reader could not name."""

    keys: frozenset[str]
    opaque: int


def units(text: str) -> list[Unit]:
    """The mappings whose keys say what a YAML or JSON file is, in document order."""
    body = text.strip()
    if body[:1] in ("{", "["):
        found, rest = _json_units(body)
        if found is not None and not rest.strip():
            return found
    else:
        found = None
    out: list[Unit] = found or []
    for document in _documents(text):
        out += _Reader().read(document)
    return out


def loose_keys(text: str) -> set[str]:
    """Every key-like token anywhere outside a full-line comment, at any depth, quoted or not."""
    keys: set[str] = set()
    for line in LINES.split(text):
        if not line.lstrip().startswith("#"):
            keys.update(unquote(m.group(1)) for m in LOOSE.finditer(line))
    keys.update(unquote(m.group(1)) for m in SPLIT_KEY.finditer(text))
    return keys


def unquote(token: str) -> str:
    """The value of a plain, single- or double-quoted YAML scalar (JSON strings are double-quoted ones)."""
    if token[:1] == "'":
        return token[1:-1].replace("''", "'")
    if token[:1] == '"':
        return ESCAPE.sub(_escape, token[1:-1])
    return token


def _escape(match: re.Match[str]) -> str:
    code = match.group(1)
    if len(code) > 1:
        value = int(code[1:], 16)
        return chr(value) if value <= MAX_CODE else match.group(0)
    return SIMPLE.get(code, code)


def _json_units(body: str) -> tuple[list[Unit] | None, str]:
    """The root object (or each object in a root array) of leading JSON, and the text after it; None if not JSON."""
    try:
        value, end = json.JSONDecoder().raw_decode(body)
    except (ValueError, RecursionError):
        return None, body
    items = value if isinstance(value, list) else [value]
    return [Unit(frozenset(item), 0) for item in items if isinstance(item, dict)], body[end:]


def _documents(text: str) -> list[list[str]]:
    """The lines of each YAML document, split at `---` and `...` markers, a leading BOM dropped."""
    documents: list[list[str]] = [[]]
    for line in LINES.split(text):
        if DOC_MARK.match(line := line.removeprefix(BOM)):
            documents.append([])
        else:
            documents[-1].append(line)
    return documents


class _Keys:
    """The keys of one unit while it is read."""

    def __init__(self) -> None:
        self.names: set[str] = set()
        self.opaque = 0


class _Reader:
    """Collects the keys at the root indentation of one document, and of each root sequence item."""

    def __init__(self) -> None:
        self.anchors: dict[str, str | None] = {}
        self.units: list[_Keys] = []
        self.root: int | None = None
        self.mapping: _Keys | None = None
        self.item: _Keys | None = None
        self.item_col: int | None = None

    def read(self, lines: list[str]) -> list[Unit]:
        for line in lines:
            body = line.lstrip(" ")
            content = body.lstrip(" \t")
            if content and content[0] != "#" and not (self.root is None and body[0] == "%"):
                self._line(len(line) - len(body), body)
            if "&" in line:
                for anchor in ANCHOR.finditer(line):
                    scalar = ANCHORED.match(line, anchor.end())
                    self.anchors[anchor.group(1)] = unquote(scalar.group(1)) if scalar else None
        return [Unit(frozenset(keys.names), keys.opaque) for keys in self.units]

    def _line(self, col: int, body: str) -> None:
        if self.root is None or col < self.root:
            self.root, self.mapping, self.item = col, None, None
        if col == self.root and body[0] == "-" and body[1:2] in ("", " ", "\t"):
            rest = body[1:].lstrip(" \t")
            self.item = _Keys()
            self.units.append(self.item)
            self.item_col = col + len(body) - len(rest) if rest else None
            if rest:
                self._key(self.item, rest)
        elif col == self.root:
            if self.mapping is None:
                self.mapping = _Keys()
                self.units.append(self.mapping)
            self.item = None
            self._key(self.mapping, body)
        elif self.item is not None and self.item_col in (None, col):
            self.item_col = col
            self._key(self.item, body)

    def _key(self, unit: _Keys, text: str) -> None:
        if props := PROPS.match(text):
            text = text[props.end() :]
        if text[:1] == "?" and text[1:2] in ("", " ", "\t"):
            unit.opaque += 1
        elif alias := ALIAS.match(text):
            self._alias(unit, alias.group(1), text[alias.end() :].lstrip(" \t"))
        elif quoted := QUOTED.match(text):
            unit.names.add(unquote(quoted.group(1)))
        elif (end := _plain_end(text)) > 0:
            unit.names.add(text[:end].rstrip(" \t"))

    def _alias(self, unit: _Keys, name: str, rest: str) -> None:
        if not (name.endswith(":") or rest[:1] == ":"):
            return
        for candidate in (name, name.rstrip(":")):
            if (value := self.anchors.get(candidate)) is not None:
                unit.names.add(value)
                return
        unit.opaque += 1


def _plain_end(text: str) -> int:
    """Where a plain implicit key ends (its `: ` separator), or -1 when the line holds no such key."""
    if not text or (text[0] in INDICATORS and not (text[0] in "-?:" and text[1:2] not in ("", " ", "\t"))):
        return -1
    comment = min((i for i in (text.find(" #"), text.find("\t#")) if i >= 0), default=len(text))
    colon = text.find(":")
    while 0 <= colon < comment:
        if colon + 1 == len(text) or text[colon + 1] in " \t":
            return colon
        colon = text.find(":", colon + 1)
    return -1
