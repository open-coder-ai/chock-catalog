"""Key paths of a YAML stream for script gates: every node with its path, text and line, or a ParseError.

Reads: block and flow collections; plain, quoted and block scalars, folded and unescaped as YAML 1.2
loaders do; multi-document streams (`---`, `...`, directives); CRLF, lone CR and a leading BOM. A node's
line is where it starts (its tag or anchor, a block scalar's `|`/`>`, an empty value's key line).
Reports, never resolves: tags as written (`!Ref`, `!!str`), anchors on their node, aliases as `alias`
nodes (so a merge key `<<` is a path segment, not a merge), every duplicate key, values as text.
Refuses with ParseError, never a partial result, wherever YAML 1.1 and 1.2 loaders read the text
differently or this scanner cannot be sure: tabs in indentation or inside plain scalars, explicit `?`
keys, keys that are collections, aliases or span lines, a tag or anchor before an implicit key,
`key: value` inside [ ], tags outside the `!`/`!!` handles and tag alphabet, anchor names outside
[A-Za-z0-9_-], NEL/LS/PS and control characters, and input past the size, depth or node limits.
"""

from __future__ import annotations

from .yamlpath_block import document
from .yamlpath_cursor import MAX_CHARS, MAX_DEPTH, MAX_NODES, Cursor, Node, ParseError, documents, prepare

__all__ = ["MAX_CHARS", "MAX_DEPTH", "MAX_NODES", "Node", "ParseError", "scan"]


def scan(
    text: str, *, max_chars: int = MAX_CHARS, max_depth: int = MAX_DEPTH, max_nodes: int = MAX_NODES
) -> list[Node]:
    """Every node of every document, in order; ParseError (with .line) when any part cannot be read."""
    out: list[Node] = []
    for doc, (first, body) in enumerate(documents(prepare(text, max_chars))):
        document(Cursor(body, first, doc, out, (max_depth, max_nodes)))
    return out
