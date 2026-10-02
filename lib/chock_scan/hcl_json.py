"""The JSON syntax of HCL (`*.tf.json`, `*.pkr.json`) read into chock_scan.hcl Blocks, with lines, as HCL's json package reads it.

A body is an object, an array of objects (merged into one body, as HCL merges them) or null (empty).
Top-level keys are block types whose label count comes from Schema.top; an unknown one raises
HclError. Inside a body, whether a key is an argument or a nested block depends on the provider
schema this scanner does not have, so every key is an Attribute, and a key whose value can be read
as blocks is also nested Blocks: labelled as Schema.nested says (`parent/key` overrides `key`), or
with no labels when the value does not fit that shape (the data stays reachable either way). String
values and the keys of object values are templates: one that interpolates is COMPUTED, as is an
object with such a key. A duplicate key raises HclError rather than letting the last one win; `"//"`
keys in a body are comments, skipped as HCL skips them (elsewhere they are ordinary keys).
"""

from __future__ import annotations

import bisect
import json
import re
from collections.abc import Callable
from json import decoder, scanner
from typing import NamedTuple

from .hcl import COMPUTED, Attribute, Block
from .hcl_lex import BOM, MAX_CHARS, MAX_DEPTH, HclError, template


class Schema(NamedTuple):
    top: dict[str, int]  # top-level block type -> label count; any other top-level key raises
    nested: dict[str, int]  # nested block type (or "parent/type") -> label count; any other: none


TERRAFORM = Schema(
    {
        "resource": 2, "data": 2, "ephemeral": 2, "module": 1, "provider": 1, "variable": 1, "output": 1,
        "check": 1, "terraform": 0, "locals": 0, "moved": 0, "import": 0, "removed": 0,
    },
    {"provisioner": 1, "dynamic": 1, "terraform/backend": 1, "terraform/provider_meta": 1, "check/data": 2},
)  # fmt: skip
PACKER = Schema(
    {"source": 2, "data": 2, "build": 0, "variable": 1, "variables": 0, "local": 1, "locals": 0, "packer": 0},
    {"provisioner": 1, "error-cleanup-provisioner": 1, "post-processor": 1, "dynamic": 1, "build/source": 1},
)
COMMENT = "//"
JSON_WS = " \t\n\r"
Scan = Callable[[str, int], tuple[object, int]]
Pairs = list[tuple[str, "_Node"]]


class _ShapeError(HclError):
    """The value does not have the shape asked for (an object, labels): `fits` reads this as "not blocks"."""


class _Pairs(list):
    """A JSON object, as its (key, _Node) pairs in source order."""


class _Node(NamedTuple):
    value: object
    start: int
    end: int


def parse_json(text: str, schema: Schema = TERRAFORM) -> Block:
    """The file as a root Block (type "", line 1) holding the top-level blocks; HclError if it cannot be read."""
    if len(text) > MAX_CHARS:
        msg = f"larger than {MAX_CHARS} characters"
        raise HclError(msg, 1)
    return _Reader(text.removeprefix(BOM), schema).root()


class _Reader:
    def __init__(self, text: str, schema: Schema) -> None:
        self.text = text
        self.schema = schema
        self.newlines = [m.start() for m in re.finditer("\n", text)]
        self.values: dict[int, object] = {}  # id(node) -> value: each subtree is read once, not once per level

    def line(self, pos: int) -> int:
        return bisect.bisect_left(self.newlines, pos) + 1

    def fail(self, message: str, node: _Node) -> HclError:
        return HclError(message, self.line(node.start))

    def root(self) -> Block:
        blocks: list[Block] = []
        node = self.load()
        if node.value is None:
            msg = "a JSON configuration is an object (or an array of objects), not null"
            raise self.fail(msg, node)
        for key, child in self.merged(node, "the file", body=False):
            if key == COMMENT:
                continue
            if key not in self.schema.top:
                msg = f"unknown top-level block type {key!r}"
                raise self.fail(msg, child)
            blocks += self.blocks(key, child, self.schema.top[key], (), 1)
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

    def objects(self, node: _Node, what: str) -> list[_Node]:
        """An object, or an array of objects, as the objects; null is none; anything else raises."""
        value = node.value
        items = (
            [node] if isinstance(value, _Pairs) else [] if value is None else value if isinstance(value, list) else None
        )
        if items is None or not all(isinstance(item.value, _Pairs) for item in items):
            msg = f"{what}: expected an object or an array of objects"
            raise _ShapeError(msg, self.line(node.start))
        return items

    def merged(self, node: _Node, what: str, *, body: bool) -> Pairs:
        """The pairs of every object `node` holds, in order, as HCL merges them; in a body, `//` keys are comments.

        A key may repeat: HCL reads a repeated block type as more blocks, and only refuses a repeated
        argument, which the reader of a body decides (see `body`).
        """
        return [(k, c) for obj in self.objects(node, what) for k, c in obj.value if not (body and k == COMMENT)]

    def body_pairs(self, node: _Node) -> Pairs:
        return self.merged(node, "a body", body=True)

    def blocks(self, kind: str, node: _Node, labels: int, have: tuple[str, ...], depth: int) -> list[Block]:
        """The blocks a property spells: `labels` levels of objects keyed by label, then a body or array of bodies."""
        if labels:
            pairs = self.merged(node, f"{kind} labels", body=False)
            if not pairs:
                msg = f"{kind}: missing block label"
                raise _ShapeError(msg, self.line(node.start))
            found: list[Block] = []
            for label, child in pairs:
                found += self.blocks(kind, child, labels - 1, (*have, label), depth + 1)
            return found
        value = node.value
        if value is None:
            return []
        if not isinstance(value, list) or isinstance(value, _Pairs):
            return [self.body(kind, have, node, depth)]
        return [self.body(kind, have, item, depth) for item in value]

    def body(self, kind: str, labels: tuple[str, ...], node: _Node, depth: int) -> Block:
        """A block; a key repeated across merged objects must be blocks each time (an argument set twice raises)."""
        groups: dict[str, list[_Node]] = {}
        for name, child in self.body_pairs(node):
            groups.setdefault(name, []).append(child)
        attributes: list[Attribute] = []
        shapes: dict[int, int | None] = {}
        for name, children in groups.items():
            first = children[0]
            shapes |= {id(child): self.shape(kind, name, child) for child in children}
            if len(children) > 1 and any(shapes[id(child)] is None for child in children):
                msg = f"duplicate key {name!r} (an argument set twice)"
                raise self.fail(msg, children[1])
            value = self.value(first, depth + 1) if len(children) == 1 else COMPUTED
            attributes.append(Attribute(name, self.text[first.start : first.end], self.line(first.start), value))
        blocks: list[Block] = []
        for name, child in self.body_pairs(node):  # in file order, as HCL gives blocks
            if (labels_of := shapes[id(child)]) is not None:
                blocks += self.blocks(name, child, labels_of, (), depth + 1)
        return Block(kind, labels, self.line(node.start), tuple(attributes), tuple(blocks))

    def shape(self, parent: str, kind: str, node: _Node) -> int | None:
        """How many labels a body key's value reads as blocks with: the schema's count, else none, else None."""
        if node.value is None:
            return 0
        if not isinstance(node.value, list):
            return None
        nested = self.schema.nested
        return next(
            (n for n in dict.fromkeys((nested.get(f"{parent}/{kind}", nested.get(kind, 0)), 0)) if self.fits(node, n)),
            None,
        )

    def fits(self, node: _Node, labels: int) -> bool:
        """Whether `node` reads as blocks with `labels` labels; checks only the label levels and body tops."""
        try:
            if labels:
                pairs = self.merged(node, "labels", body=False)
                return bool(pairs) and all(self.fits(child, labels - 1) for _, child in pairs)
            value = node.value
            for item in value if isinstance(value, list) and not isinstance(value, _Pairs) else [node]:
                self.body_pairs(item)
        except _ShapeError:
            return False
        return True

    def value(self, node: _Node, depth: int) -> object:
        if depth > MAX_DEPTH:
            msg = f"JSON nested deeper than {MAX_DEPTH}"
            raise self.fail(msg, node)
        if id(node) not in self.values:
            self.values[id(node)] = self.read(node, depth)
        return self.values[id(node)]

    def read(self, node: _Node, depth: int) -> object:
        value = node.value
        if isinstance(value, _Pairs):
            pairs = list(value)
            if len({key for key, _ in pairs}) < len(pairs):
                msg = "duplicate key in an object"
                raise self.fail(msg, node)
            keys = [self.string(key) for key, _ in pairs]
            values = [self.value(child, depth + 1) for _, child in pairs]
            if COMPUTED in keys or len(set(keys)) < len(keys):
                return COMPUTED
            return dict(zip(keys, values, strict=True))
        if isinstance(value, list):
            return tuple(self.value(item, depth + 1) for item in value)
        if isinstance(value, str):
            return self.string(value)
        return value

    def string(self, text: str) -> object:
        """A JSON string as Terraform evaluates it: a template; one HCL cannot evaluate is COMPUTED too."""
        try:
            return template(text)
        except HclError:
            return COMPUTED


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
