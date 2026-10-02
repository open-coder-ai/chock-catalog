"""The JSON syntax of HCL (`*.tf.json`, `*.pkr.json`) read into chock_scan.hcl Blocks, with lines.

Top-level keys are block types whose label count comes from a table (TERRAFORM or PACKER); an
unknown one raises HclError. Inside a body, whether a key is an argument or a nested block depends
on the provider schema this scanner does not have, so every key is an Attribute and a key whose
value is an object (or a list of objects) is also a nested Block (`provisioner`, `dynamic`,
`backend`, `source`, `post-processor` take one label, the rest none). String values are templates:
one that interpolates is COMPUTED. A duplicate key anywhere raises HclError rather than letting the
last one win; `"//"` keys are comments, skipped as Terraform skips them.
"""

from __future__ import annotations

import bisect
import json
import re
from collections.abc import Callable
from json import decoder, scanner
from typing import NamedTuple

from .hcl import Attribute, Block
from .hcl_lex import BOM, MAX_CHARS, MAX_DEPTH, HclError, template

TERRAFORM = {
    "resource": 2, "data": 2, "ephemeral": 2, "module": 1, "provider": 1, "variable": 1, "output": 1,
    "check": 1, "terraform": 0, "locals": 0, "moved": 0, "import": 0, "removed": 0,
}  # fmt: skip
PACKER = {"source": 2, "data": 2, "build": 0, "variable": 1, "variables": 0, "local": 1, "locals": 0, "packer": 0}
NESTED = {"provisioner": 1, "dynamic": 1, "backend": 1, "source": 1, "post-processor": 1}
COMMENT = "//"
JSON_WS = " \t\n\r"
Scan = Callable[[str, int], tuple[object, int]]


class _Pairs(list):
    """A JSON object, as its (key, _Node) pairs in source order."""


class _Node(NamedTuple):
    value: object
    start: int
    end: int


def parse_json(text: str, block_types: dict[str, int] = TERRAFORM) -> Block:
    """The file as a root Block (type "", line 1) holding the top-level blocks; HclError if it cannot be read."""
    if len(text) > MAX_CHARS:
        msg = f"larger than {MAX_CHARS} characters"
        raise HclError(msg, 1)
    return _Reader(text.removeprefix(BOM), block_types).root()


class _Reader:
    def __init__(self, text: str, block_types: dict[str, int]) -> None:
        self.text = text
        self.types = block_types
        self.newlines = [m.start() for m in re.finditer("\n", text)]

    def line(self, pos: int) -> int:
        return bisect.bisect_left(self.newlines, pos) + 1

    def root(self) -> Block:
        node = self.load()
        if not isinstance(node.value, _Pairs):
            msg = "a Terraform/Packer JSON file is one object"
            raise HclError(msg, self.line(node.start))
        blocks: list[Block] = []
        for key, child in self.pairs(node):
            if key not in self.types:
                msg = f"unknown top-level block type {key!r}"
                raise HclError(msg, self.line(child.start))
            blocks += self.blocks(key, child, self.types[key], (), 1, strict=True)
        return Block("", (), 1, (), tuple(blocks))

    def load(self) -> _Node:
        dec = json.JSONDecoder(object_pairs_hook=_Pairs, parse_constant=_no_constant)
        dec.parse_object = _located_object
        dec.parse_array = _located_array
        scan = _located(scanner.py_make_scanner(dec))
        start = len(self.text) - len(self.text.lstrip(JSON_WS))
        try:
            node, _ = scan(self.text, start)
        except StopIteration:
            msg = "expected a JSON value"
            raise HclError(msg, self.line(start)) from None
        except json.JSONDecodeError as exc:
            raise HclError(exc.msg, exc.lineno) from None
        except RecursionError:
            msg = "JSON nested too deep"
            raise HclError(msg, 1) from None
        except ValueError as exc:
            raise HclError(str(exc), 1) from None
        if self.text[node.end :].strip(JSON_WS):
            msg = "extra data after the JSON value"
            raise HclError(msg, self.line(node.end))
        return node

    def pairs(self, node: _Node) -> list[tuple[str, _Node]]:
        """An object's pairs without `//` comments; a duplicate key raises."""
        seen: set[str] = set()
        out = []
        for key, child in node.value:
            if key in seen:
                msg = f"duplicate key {key!r}"
                raise HclError(msg, self.line(child.start))
            seen.add(key)
            if key != COMMENT:
                out.append((key, child))
        return out

    def blocks(  # noqa: PLR0913 -- the label walk carries its position
        self, kind: str, node: _Node, labels: int, have: tuple[str, ...], depth: int, *, strict: bool
    ) -> list[Block]:
        """The blocks a property spells: `labels` levels of objects keyed by label, then a body or list of bodies."""
        value = node.value
        if isinstance(value, list) and not isinstance(value, _Pairs) and value:
            items = [self.blocks(kind, item, labels, have, depth, strict=strict) for item in value]
            if all(items) or strict:
                return [b for found in items for b in found]
            return []
        if not isinstance(value, _Pairs):
            if strict:
                msg = f"{kind}: expected an object, found {type(value).__name__}"
                raise HclError(msg, self.line(node.start))
            return []
        if labels:
            found: list[Block] = []
            for label, child in self.pairs(node):
                found += self.blocks(kind, child, labels - 1, (*have, label), depth + 1, strict=strict)
            return found
        return [self.body(kind, have, node, depth)]

    def body(self, kind: str, labels: tuple[str, ...], node: _Node, depth: int) -> Block:
        attributes: list[Attribute] = []
        blocks: list[Block] = []
        for key, child in self.pairs(node):
            text = self.text[child.start : child.end]
            attributes.append(Attribute(key, text, self.line(child.start), self.value(child, depth + 1)))
            blocks += self.blocks(key, child, NESTED.get(key, 0), (), depth + 1, strict=False)
        return Block(kind, labels, self.line(node.start), tuple(attributes), tuple(blocks))

    def value(self, node: _Node, depth: int) -> object:
        value = node.value
        if depth > MAX_DEPTH:
            msg = f"JSON nested deeper than {MAX_DEPTH}"
            raise HclError(msg, self.line(node.start))
        if isinstance(value, _Pairs):
            return {key: self.value(child, depth + 1) for key, child in self.pairs(node)}
        if isinstance(value, list):
            return tuple(self.value(item, depth + 1) for item in value)
        if isinstance(value, str):
            try:
                return template(value)
            except HclError as exc:
                msg = f"bad template in a string: {exc}"
                raise HclError(msg, self.line(node.start)) from None
        return value


def _located(scan: Scan) -> Callable[[str, int], tuple[_Node, int]]:
    """json's scanner, with each value it returns wrapped in a _Node carrying its source offsets."""

    def located(text: str, idx: int) -> tuple[_Node, int]:
        value, end = scan(text, idx)
        return _Node(value, idx, end), end

    return located


def _located_object(s_and_end: tuple[str, int], strict: bool, scan_once: Scan, *hooks: object) -> tuple[object, int]:  # noqa: FBT001 -- json's callback signature
    return decoder.JSONObject(s_and_end, strict, _located(scan_once), *hooks)


def _located_array(s_and_end: tuple[str, int], scan_once: Scan) -> tuple[object, int]:
    return decoder.JSONArray(s_and_end, _located(scan_once))


def _no_constant(name: str) -> object:
    msg = f"{name} is not JSON"
    raise ValueError(msg)
