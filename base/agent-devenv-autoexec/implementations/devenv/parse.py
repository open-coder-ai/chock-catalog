"""Read JSONC, TOML and YAML the way the tools do, or refuse: a config this gate cannot read is not judged clean."""

from __future__ import annotations

import re
import tomllib

from chock_scan import jsonc, yamlpath


class UnreadableError(ValueError):
    """A config whose text the gate cannot read with certainty."""


def json_value(text: str) -> object:
    """JSONC (VS Code, devcontainer, agent settings). Duplicate keys refuse: the reader and the tool may differ."""
    try:
        document = jsonc.loads(text)
    except jsonc.JsoncError as exc:
        msg = str(exc)
        raise UnreadableError(msg) from None
    if document.duplicates:
        msg = f"duplicate key {'.'.join(map(str, document.duplicates[0].path))}"
        raise UnreadableError(msg)
    return document.value


def toml_value(text: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        msg = str(exc)
        raise UnreadableError(msg) from None


Leaf = tuple[tuple, str, int]


def yaml_leaves(text: str) -> list[Leaf]:
    """Every scalar of every document as (key path, text, line). Aliases, merge keys and duplicates refuse."""
    try:
        nodes = yamlpath.scan(text)
    except yamlpath.ParseError as exc:
        msg = str(exc)
        raise UnreadableError(msg) from None
    seen: set[tuple[int, tuple]] = set()
    leaves: list[Leaf] = []
    for node in nodes:
        if node.kind == "alias" or yamlpath.MERGE in node.path or (node.doc, node.path) in seen:
            msg = f"line {node.line}: an alias, merge key or repeated key hides what the tool reads"
            raise UnreadableError(msg)
        seen.add((node.doc, node.path))
        if node.kind not in ("map", "seq"):
            leaves.append((node.path, node.value, node.line))
    return leaves


_FRONT = re.compile(r"\A\ufeff?---[ \t]*\r?\n(.*?)^---[ \t]*\r?$", re.DOTALL | re.MULTILINE)


def front_matter(text: str) -> tuple[str, int] | None:
    """A markdown file's YAML front matter and the line it starts on; None when it has none."""
    found = _FRONT.match(text)
    return (found.group(1), 2) if found else None


def under(leaves: list[Leaf], *prefix: object) -> list[Leaf]:
    """The leaves whose path starts with `prefix`; a `None` part matches any one key or index."""
    size = len(prefix)
    return [
        leaf
        for leaf in leaves
        if len(leaf[0]) >= size and all(want is None or want == got for want, got in zip(prefix, leaf[0], strict=False))
    ]
