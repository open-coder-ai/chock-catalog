"""Key paths of a YAML stream for script gates: every node with its path, text and line, or a ParseError.

Reads: block and flow collections; plain, quoted and block scalars, folded and unescaped as YAML 1.2
loaders do; multi-document streams (`---`, `...`, %YAML); CRLF, lone CR and a leading BOM. A node's
line is where it starts (its tag or anchor, a block scalar's `|`/`>`, an empty value's key line).
Reports, never resolves: tags as written (`!Ref`, `!!str`), anchors on their node, every duplicate
key, values as text. Aliases and merge keys are NOT refused (compose and Kubernetes files use them)
and NOT expanded: an alias is an `alias` node and `<<` a path segment, so a loader can see a key here
that no node shows. indirect() lists them; a gate judging a path must treat one at or under it as
unknown. Refuses with ParseError, never a partial result, where it cannot read the text with
certainty or where YAML 1.1 and 1.2 loaders split it differently: tabs in indentation, inside plain
scalars or before a block collection; explicit `?` keys; keys that are collections, aliases or span
lines; a tag or anchor before an implicit key; a block collection on the `---` line; `key: value`
inside [ ]; %TAG and reserved directives; tags outside the `!`/`!!` handles and tag alphabet; anchor
names outside [A-Za-z0-9_-]; NEL/LS/PS and control characters; input past the size, depth or node
limits.
"""

from __future__ import annotations

from .yamlpath_block import document
from .yamlpath_cursor import MAX_CHARS, MAX_DEPTH, MAX_NODES, Cursor, Node, ParseError, documents, prepare

__all__ = ["MAX_CHARS", "MAX_DEPTH", "MAX_NODES", "MERGE", "Node", "ParseError", "indirect", "scan"]
MERGE = "<<"


def scan(
    text: str, *, max_chars: int = MAX_CHARS, max_depth: int = MAX_DEPTH, max_nodes: int = MAX_NODES
) -> list[Node]:
    """Every node of every document, in order; ParseError (with .line) when any part cannot be read.

    ValueError instead means a caller error: a limit that is not an int, below 1, or a depth above
    MAX_DEPTH (deeper nesting would exhaust the interpreter's stack before the limit is reached).
    """
    _check("max_chars", max_chars, None)
    _check("max_depth", max_depth, MAX_DEPTH)
    _check("max_nodes", max_nodes, None)
    out: list[Node] = []
    for doc, (first, body, explicit) in enumerate(documents(prepare(text, max_chars))):
        cur = Cursor(body, first, doc, out, (max_depth, max_nodes))
        cur.marker = first if explicit else 0
        document(cur)
    return out


def indirect(nodes: list[Node]) -> list[Node]:
    """The aliases and the nodes under a merge key: where a loader may hold keys no node shows."""
    return [n for n in nodes if n.kind == "alias" or MERGE in n.path]


def _check(label: str, limit: int, ceiling: int | None) -> None:
    if type(limit) is not int or limit < 1 or (ceiling is not None and limit > ceiling):
        msg = f"{label} must be an int from 1{f' to {ceiling}' if ceiling else ''}, not {limit!r}"
        raise ValueError(msg)
