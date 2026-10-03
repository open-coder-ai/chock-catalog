"""YAML as plain dicts, lists and strings that remember lines, with aliases and merge keys resolved or refused."""

from __future__ import annotations

from chock_scan import yamlpath

#: A tag that makes a scalar a reference to something else, not text. Any other tag (`!Sub "*"`) keeps its text.
REFERENCE_TAGS = frozenset(
    {
        "!Ref",
        "!GetAtt",
        "!ImportValue",
        "!FindInMap",
        "!Condition",
        "!Select",
        "!Split",
        "!Equals",
        "!Not",
        "!And",
        "!Or",
        "!If",
    }
)
MAX_EXPANDED = 100_000
MERGE = "<<"


class UnreadableError(ValueError):
    """Text that cannot be read with certainty: the gate refuses it rather than judging part of it."""


class Str(str):
    line = 0
    ref = False


class Map(dict):
    line = 0
    keylines: dict


class Seq(list):
    line = 0


class _Alias:
    def __init__(self, target: object, line: int) -> None:
        self.target, self.line = target, line


def docs(text: str) -> tuple[list[object], list[tuple[str, int]]]:
    """(one tree per document, every key a document repeats with its line); UnreadableError or ParseError otherwise."""
    by_doc: dict[int, list[yamlpath.Node]] = {}
    for node in yamlpath.scan(text):
        by_doc.setdefault(node.doc, []).append(node)
    trees, repeats = [], []
    for number in sorted(by_doc):
        built = _Builder()
        for node in by_doc[number]:
            built.add(node)
        budget = [MAX_EXPANDED]
        trees.append(_expand(built.root, budget, ()))
        repeats.extend(built.repeats)
    return trees, repeats


class _Builder:
    def __init__(self) -> None:
        self.root: object = None
        self.at: dict[tuple, object] = {}
        self.anchors: dict[str, object] = {}
        self.repeats: list[tuple[str, int]] = []

    def add(self, node: yamlpath.Node) -> None:
        obj = self._make(node)
        if node.anchor:
            self.anchors[node.anchor] = obj
        self.at[node.path] = obj
        if not node.path:
            self.root = obj
            return
        parent, key = self.at[node.path[:-1]], node.path[-1]
        if isinstance(parent, Map):
            if key in parent:
                self.repeats.append((str(key), node.line))
            parent[key] = obj
            parent.keylines[key] = node.line
        else:
            parent.append(obj)

    def _make(self, node: yamlpath.Node) -> object:
        if node.kind == "alias":
            if node.value not in self.anchors:
                msg = f"line {node.line}: alias *{node.value} has no anchor before it"
                raise UnreadableError(msg)
            return _Alias(self.anchors[node.value], node.line)
        made: Map | Seq | Str
        if node.kind == "map":
            made = Map()
            made.keylines = {}
        elif node.kind == "seq":
            made = Seq()
        else:
            made = Str(node.value)
            made.ref = node.tag in REFERENCE_TAGS
        made.line = node.line
        return made


def _expand(node: object, budget: list[int], active: tuple[int, ...]) -> object:
    """A copy of `node` with every alias replaced by a copy of what it names and merge keys applied."""
    budget[0] -= 1
    if budget[0] < 0:
        msg = "aliases expand to more than the gate reads"
        raise UnreadableError(msg)
    if isinstance(node, _Alias):
        if id(node.target) in active:
            msg = f"line {node.line}: an alias refers to its own anchor"
            raise UnreadableError(msg)
        return _expand(node.target, budget, (*active, id(node.target)))
    if isinstance(node, Map):
        return _merge(node, budget, active)
    if isinstance(node, Seq):
        out = Seq(_expand(v, budget, active) for v in node)
        out.line = node.line
        return out
    return node


def _merge(node: Map, budget: list[int], active: tuple[int, ...]) -> Map:
    out = Map()
    out.line, out.keylines = node.line, dict(node.keylines)
    merged = []
    for key, value in node.items():
        if key == MERGE:
            sources = _expand(value, budget, active)
            merged = [sources] if isinstance(sources, Map) else list(sources) if isinstance(sources, Seq) else [None]
            if not all(isinstance(m, Map) for m in merged):
                msg = f"line {node.keylines[key]}: a merge key that does not name a mapping"
                raise UnreadableError(msg)
        else:
            out[key] = _expand(value, budget, active)
    for source in merged:
        for key, value in source.items():
            if key not in out:
                out[key] = value
                out.keylines[key] = source.keylines.get(key, node.line)
    return out
