"""A compose file's services as flat (key path, value, line) entries, with YAML aliases and `<<` merges expanded.

chock_scan.yamlpath reports aliases and merge keys without expanding them; a compose file uses both
(`x-defaults: &d` then `<<: *d`), so a rule that read only the written nodes would miss a
`privileged: true` merged in from an anchor. Here an alias is replaced by its anchor's subtree, a
merge adds the anchor's keys a mapping does not set itself, and an unknown anchor, a cycle or an
expansion past the size limit is UnreadableError, never a partial answer.
"""

from __future__ import annotations

from collections import defaultdict
from typing import NamedTuple

from chock_scan import yamlpath

MERGE = "<<"
MAX_ENTRIES = 50_000
MAX_DEPTH = 32
SERVICE_DEPTH = 2
SCALARS = frozenset({"plain", "single", "double", "literal", "folded"})
NOT_SERVICES = frozenset({"version", "name", "networks", "volumes", "secrets", "configs", "include", "services"})

Key = tuple[str | int, ...]


class Entry(NamedTuple):
    path: Key
    value: str
    line: int
    scalar: bool


class UnreadableError(ValueError):
    """The file cannot be read with certainty (YAML the scanner refuses, or aliases it cannot expand)."""


class _Doc:
    def __init__(self, nodes: list[yamlpath.Node], budget: int) -> None:
        self.budget = budget
        self.children: dict[Key, list[yamlpath.Node]] = defaultdict(list)
        self.targets: dict[int, Key] = {}
        anchors: dict[str, Key] = {}
        for index, node in enumerate(nodes):
            if node.anchor:
                anchors[node.anchor] = node.path
            if node.kind == "alias":
                if node.value not in anchors:
                    msg = f"line {node.line}: alias *{node.value} has no anchor before it"
                    raise UnreadableError(msg)
                self.targets[index] = anchors[node.value]
            if node.path:
                self.children[node.path[:-1]].append(node)
        self.index = {id(node): i for i, node in enumerate(nodes)}
        self.root = {node.path: node for node in nodes}
        self.out: list[Entry] = []

    def target(self, node: yamlpath.Node) -> Key:
        return self.targets[self.index[id(node)]]

    def emit(self, path: Key, node: yamlpath.Node, line: int) -> None:
        if len(self.out) >= self.budget:
            msg = f"more than {MAX_ENTRIES} entries in the file once aliases are expanded"
            raise UnreadableError(msg)
        self.out.append(Entry(path, node.value, line, node.kind in SCALARS))

    def walk(self, src: Key, dst: Key, depth: int, line: int = 0) -> None:
        """Emit the subtree under `src` as if it were written at `dst`."""
        if depth > MAX_DEPTH:
            msg = "aliases nest deeper than the limit, or refer to themselves"
            raise UnreadableError(msg)
        kids = self.children.get(src, [])
        explicit = {kid.path[-1] for kid in kids if kid.path[-1] != MERGE}
        for kid in kids:
            key = kid.path[-1]
            if key == MERGE:
                self.merge(kid, dst, explicit, depth)
            else:
                self.node(kid, (*dst, key), depth, line)

    def node(self, kid: yamlpath.Node, at: Key, depth: int, line: int) -> None:
        if kid.kind == "alias":
            target = self.target(kid)
            self.emit(at, self.root[target], line or kid.line)
            self.walk(target, at, depth + 1, line or kid.line)
        else:
            self.emit(at, kid, line or kid.line)
            self.walk(kid.path, at, depth, line)

    def merge(self, kid: yamlpath.Node, dst: Key, explicit: set[str | int], depth: int) -> None:
        sources = [kid] if kid.kind != "seq" else self.children.get(kid.path, [])
        for source in sources:
            path = self.target(source) if source.kind == "alias" else source.path
            before = len(self.out)
            self.walk(path, dst, depth + 1, kid.line)
            kept = [e for e in self.out[before:] if e.path[len(dst)] not in explicit]
            self.out[before:] = kept


def flatten(text: str) -> list[list[Entry]]:
    """Every document's entries, aliases and merges expanded; UnreadableError when that cannot be done with certainty."""
    try:
        nodes = yamlpath.scan(text)
    except yamlpath.ParseError as exc:
        raise UnreadableError(str(exc)) from exc
    docs: dict[int, list[yamlpath.Node]] = defaultdict(list)
    for node in nodes:
        docs[node.doc].append(node)
    out = []
    for doc_nodes in docs.values():
        doc = _Doc(doc_nodes, MAX_ENTRIES - sum(len(done) for done in out))
        doc.walk((), (), 0)
        out.append(doc.out)
    return out


def services(entries: list[Entry]) -> dict[str, list[Entry]]:
    """Each service's entries, with paths relative to the service. Top-level `services:`, else the v1 layout."""
    found: dict[str, list[Entry]] = defaultdict(list)
    tops = {e.path[0] for e in entries if len(e.path) == 1}
    for entry in entries:
        path = entry.path
        if "services" in tops:
            if len(path) > SERVICE_DEPTH and path[0] == "services":
                found[str(path[1])].append(entry._replace(path=path[2:]))
        elif len(path) > 1 and path[0] not in NOT_SERVICES and not str(path[0]).startswith("x-"):
            found[str(path[0])].append(entry._replace(path=path[1:]))
    return {
        name: rows
        for name, rows in found.items()
        if any(r.path[0] in ("image", "build") for r in rows) or "services" in tops
    }
