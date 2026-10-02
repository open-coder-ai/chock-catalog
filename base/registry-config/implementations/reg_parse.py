"""Structured reads shared by the readers: YAML key paths, TOML, JSON and INI-style lines, each failing closed."""

from __future__ import annotations

import json
import re
import tomllib

from chock_scan.jsonc import JsoncError, loads
from chock_scan.yamlpath import ParseError, scan, unknown
from reg_core import UNREADABLE, Ctx, add, digest

INDIRECT = "reg-indirect"
SCALARS = frozenset({"plain", "single", "double", "literal", "folded"})
#: An INI line's value ends at an unquoted ';' or '#', as npm's ini reader ends it.
INI_LINE = re.compile(r"^\s*([^=]*?)\s*(?:=\s*(.*?))?\s*$")
INI_COMMENT = re.compile(r"(?<!\\)[;#]")


def refuse(ctx: Ctx, what: str, exc: Exception) -> None:
    """A registry config that cannot be read cannot be judged: one finding keyed by the whole text."""
    line = next((n for n in (getattr(exc, "lineno", None), getattr(exc, "line", None)) if isinstance(n, int)), 1)
    add(
        ctx,
        UNREADABLE,
        line,
        (what, digest(ctx.text)),
        f"cannot read this {what}: {(str(exc).splitlines() or [type(exc).__name__])[0][:120]}",
    )


def yaml_scalars(ctx: Ctx) -> list[tuple[tuple[str, ...], str, int]] | None:
    """(lower-cased path, value, line) of every scalar; None (and a finding) when the YAML cannot be read.

    An alias, merge key or duplicate key anywhere means a loader may see a value no node shows: that
    asks a person (reg-indirect) rather than trusting what was, or was not, found."""
    try:
        nodes = scan(ctx.text)
    except ParseError as exc:
        refuse(ctx, "YAML file", exc)
        return None
    if unknown(nodes, ()):
        add(
            ctx,
            INDIRECT,
            1,
            ("yaml", digest(ctx.text)),
            "an alias, merge key or repeated key hides what a loader reads",
        )
    return [
        (tuple(str(p).lower() for p in node.path), node.value, node.line)
        for node in nodes
        if node.kind in SCALARS or node.kind in ("map", "seq")
    ]


def toml(ctx: Ctx) -> dict | None:
    """The TOML document; None (and a finding) when it is not valid TOML."""
    try:
        return tomllib.loads(ctx.text)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        refuse(ctx, "TOML file", exc)
        return None


def json_doc(ctx: Ctx) -> object | None:
    """The JSON (with comments) document; None (and a finding) when unreadable. A repeated key asks."""
    try:
        doc = loads(ctx.text)
    except JsoncError as exc:
        refuse(ctx, "JSON file", exc)
        return None
    if doc.duplicates:
        add(ctx, INDIRECT, 1, ("json", digest(ctx.text)), "a repeated key hides a value some loaders read")
    return doc.value


def unquote(text: str) -> str:
    """A quoted value as npm's ini and Yarn read it: double quotes JSON-decoded (escapes resolved), single
    quotes stripped; anything else as written."""
    text = text.strip()
    if len(text) > 1 and text[0] == text[-1] == '"':
        try:
            decoded = json.loads(text)
        except ValueError:
            return text[1:-1]
        return decoded if isinstance(decoded, str) else text[1:-1]
    if len(text) > 1 and text[0] == text[-1] == "'":
        return text[1:-1]
    return text


def ini_value(raw: str | None) -> str:
    """An INI value as npm reads it: quoted text whole, otherwise cut at an unescaped comment mark.
    A key with no '=' reads as true."""
    if raw is None:
        return "true"
    text = raw.strip()
    if len(text) > 1 and text[0] == text[-1] and text[0] in "\"'":
        return unquote(text)
    return INI_COMMENT.split(text, maxsplit=1)[0].strip()


def ini_pairs(ctx: Ctx) -> list[tuple[str, str, str, int]]:
    """(section, lower-cased key, value, line) for every key line; comment and blank lines skipped."""
    out: list[tuple[str, str, str, int]] = []
    section = ""
    for number, raw in enumerate(ctx.lines, 1):
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        match = INI_LINE.match(line)
        key = unquote(match[1]).lower() if match else ""
        if key:
            out.append((section, key, ini_value(match[2]), number))
    return out


def walk(value: object, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], object]]:
    """(lower-cased path, leaf) for every leaf of a parsed TOML or JSON document, lists by index."""
    if isinstance(value, dict):
        return [item for k, v in value.items() for item in walk(v, (*path, str(k).lower()))]
    if isinstance(value, list):
        return [item for i, v in enumerate(value) for item in walk(v, (*path, str(i)))]
    return [(path, value)]
