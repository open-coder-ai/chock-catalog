"""Random Terraform JSON with the blocks and values a correct scanner must read back, as HCL's json package reads it (seeded).

It writes the shapes HCL merges or skips: `//` comment keys in bodies (skipped) and in object values
(kept), template keys in object values (`$${` unescaped), a body split across an array of objects
(merged), nested block lists holding null (an empty block), and label levels written as arrays.
"""

from __future__ import annotations

import json
import random

from chock_scan.hclgen import REF, ident, text

COMMENT = "//"


def json_document(seed: int) -> tuple[str, dict]:
    """The file, and the resource blocks it must read as: {(type, name): (attributes, nested [(type, attributes)])}."""
    rng = random.Random(seed)  # noqa: S311 -- reproducible test data, not a secret
    items: list[dict] = []
    model: dict = {}
    for _ in range(rng.randrange(1, 4)):
        kind, name = ident(rng), ident(rng)
        if (kind, name) in model:
            continue
        written, attrs, nested = _body(rng)
        if rng.random() < 0.3 and len(written) > 1:
            keys = list(written)
            cut = rng.randrange(1, len(keys))
            leaf: object = [[{k: written[k] for k in keys[:cut]}, {k: written[k] for k in keys[cut:]}]]
        else:
            leaf = written if rng.random() < 0.7 else [written]
        items.append({kind: {name: leaf}})
        model[kind, name] = (attrs, nested)
    resource: object = items
    if rng.random() < 0.7:
        joined: dict = {}
        for item in items:
            for kind, names in item.items():
                joined.setdefault(kind, {}).update(names)
        resource = joined
    doc = {COMMENT: "comment", "resource": resource} if rng.random() < 0.3 else {"resource": resource}
    return json.dumps(doc, indent=rng.choice([None, 1, 2]), ensure_ascii=rng.random() < 0.5), model


def _body(rng: random.Random) -> tuple[dict, dict, list]:
    """(what the body holds, its expected attributes, its expected nested blocks)."""
    written: dict = {}
    attrs: dict = {}
    nested: list = []
    for _ in range(rng.randrange(1, 5)):
        key = ident(rng)
        if key in written:
            continue
        pick = rng.randrange(6)
        if pick == 0:
            written[COMMENT] = text(rng)
            continue
        if pick == 1:
            obj = {COMMENT: "kept", "$${k}": 1, "a": _escape(t := text(rng))}
            written[key], attrs[key] = obj, {COMMENT: "kept", "${k}": 1, "a": t}
            nested.append((key, {"$${k}": 1, "a": t}))
        elif pick == 2:
            stmts = [{"actions": ["*"]}, None, {"resources": [_escape(t := text(rng))]}]
            written[key], attrs[key] = stmts, ({"actions": ("*",)}, None, {"resources": (t,)})
            nested += [(key, {"actions": ("*",)}), (key, {}), (key, {"resources": (t,)})]
        else:
            written[key], attrs[key] = _scalar(rng)
    return written, attrs, nested


def _scalar(rng: random.Random) -> tuple[object, object]:
    """(what the file holds, what the scanner must read): templates escaped, one reference left COMPUTED."""
    pick = rng.randrange(5)
    if pick == 0:
        value = text(rng)
        return _escape(value), value
    if pick == 1:
        return (value := rng.randrange(-5, 5000)), value
    if pick == 2:
        return (value := rng.choice([True, False, None])), value
    if pick == 3:
        items = [text(rng) for _ in range(rng.randrange(3))]
        return [_escape(v) for v in items], tuple(items)
    return "${var." + ident(rng) + "}", REF


def _escape(value: str) -> str:
    return value.replace("${", "$${").replace("%{", "%%{")
