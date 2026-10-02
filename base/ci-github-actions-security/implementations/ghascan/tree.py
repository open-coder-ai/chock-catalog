"""One YAML document as GitHub reads it: aliases expanded, merge keys applied, lookups by key path."""

from __future__ import annotations

from typing import NamedTuple

from chock_scan import yamlpath

SCALARS = frozenset({"plain", "single", "double", "literal", "folded"})
MERGE = yamlpath.MERGE
MAX_EXPANDED = 50_000


class UnreadableError(ValueError):
    """The document cannot be read with certainty; the gate reports it rather than judging a guess."""

    def __init__(self, reason: str, line: int = 1) -> None:
        super().__init__(reason)
        self.line = line


class N(NamedTuple):
    """A node after expansion. `merged` marks one a `<<` key supplied, which some loaders ignore."""

    path: tuple[str | int, ...]
    value: str
    line: int
    kind: str
    merged: bool


def documents(text: str) -> list[Tree]:
    """Every document in the stream as a Tree; UnreadableError when the scanner refuses the text."""
    try:
        nodes = yamlpath.scan(text)
    except yamlpath.ParseError as exc:
        raise UnreadableError(exc.reason, exc.line) from None
    docs: dict[int, list[yamlpath.Node]] = {}
    for node in nodes:
        docs.setdefault(node.doc, []).append(node)
    return [Tree(expand(group)) for _, group in sorted(docs.items())]


def expand(nodes: list[yamlpath.Node]) -> list[N]:
    """Replace each alias with a copy of the subtree its anchor named at that point, rebased to the alias."""
    out: list[N] = []
    anchors: dict[str, int] = {}
    for node in nodes:
        if node.kind != "alias":
            if node.anchor:
                anchors[node.anchor] = len(out)
            out.append(N(node.path, node.value, node.line, node.kind, merged=False))
            continue
        if node.value not in anchors:
            msg = f"alias *{node.value} names no anchor before it"
            raise UnreadableError(msg, node.line)
        start = anchors[node.value]
        base = out[start].path
        size = len(base)
        copied = [out[start]]
        copied += [n for n in out[start + 1 :] if n.path[:size] == base and len(n.path) > size]
        out += [N(node.path + n.path[size:], n.value, node.line, n.kind, merged=False) for n in copied]
        if len(out) > MAX_EXPANDED:
            msg = f"aliases expand past {MAX_EXPANDED} nodes"
            raise UnreadableError(msg, node.line)
    return [_merge(n) for n in out]


def _merge(node: N) -> N:
    """A node under `<<` moves to the mapping holding the key (and out of a list of merged aliases)."""
    if MERGE not in node.path:
        return node
    at = node.path.index(MERGE)
    rest = node.path[at + 1 :]
    if rest and isinstance(rest[0], int):
        rest = rest[1:]
    return _merge(N(node.path[:at] + rest, node.value, node.line, node.kind, merged=True))


class Tree:
    """Lookups over one expanded document."""

    def __init__(self, nodes: list[N]) -> None:
        self.nodes = nodes
        self.at: dict[tuple[str | int, ...], list[N]] = {}
        self.kids: dict[tuple[str | int, ...], list[str | int]] = {}
        self._under: dict[tuple[str | int, ...], list[N]] = {}
        for node in nodes:
            self.at.setdefault(node.path, []).append(node)
            if node.path:
                parent, key = node.path[:-1], node.path[-1]
                listed = self.kids.setdefault(parent, [])
                if key not in listed:
                    listed.append(key)

    def values(self, path: tuple[str | int, ...]) -> list[N]:
        """Every scalar at `path`: duplicates and merged copies too, for rules that look for a value."""
        return [n for n in self.at.get(path, []) if n.kind in SCALARS]

    def value(self, path: tuple[str | int, ...]) -> N | None:
        """The scalar a loader keeps at `path` for rules that rely on a setting: the last one written
        there, never a merged copy (a loader without merge keys would not see it); None when absent
        or when the last thing there is a collection."""
        own = [n for n in self.at.get(path, []) if not n.merged]
        return own[-1] if own and own[-1].kind in SCALARS else None

    def text(self, path: tuple[str | int, ...]) -> str | None:
        node = self.value(path)
        return None if node is None else node.value

    def has(self, path: tuple[str | int, ...], *, trusted: bool = False) -> bool:
        """Whether anything sits at `path`; `trusted` counts only what every loader sees."""
        return any(not (trusted and n.merged) for n in self.at.get(path, []))

    def keys(self, path: tuple[str | int, ...]) -> list[str | int]:
        return list(self.kids.get(path, []))

    def line(self, path: tuple[str | int, ...]) -> int:
        """The line where `path` starts, or where its nearest present parent does (1 for the root)."""
        while path and path not in self.at:
            path = path[:-1]
        return self.at[path][0].line if path in self.at else 1

    def under(self, path: tuple[str | int, ...]) -> list[N]:
        """Every scalar at or below `path`."""
        if path not in self._under:
            size = len(path)
            self._under[path] = [n for n in self.nodes if n.path[:size] == path and n.kind in SCALARS]
        return self._under[path]
