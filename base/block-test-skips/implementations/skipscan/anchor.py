"""What a Python skip is keyed by: its table row, decorator or statement, its owner, and the guards above it."""

from __future__ import annotations

import ast

CONTAINERS = (ast.List, ast.Tuple, ast.Set)
DECORATED = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def span(lines: list[str], node: ast.AST) -> str:
    """The whole lines a node covers, whitespace-normalized."""
    end = getattr(node, "end_lineno", None) or node.lineno
    return " ".join(" ".join(lines[node.lineno - 1 : end]).split())


def segment(lines: list[str], node: ast.AST) -> str:
    """A node's own source, sliced from the split lines by its UTF-8 column offsets (no re-split per node)."""
    first, last = node.lineno - 1, (node.end_lineno or node.lineno) - 1
    parts = [line.encode() for line in lines[first : last + 1]]
    if first == last:
        raw = parts[0][node.col_offset : node.end_col_offset]
    else:
        raw = b"\n".join([parts[0][node.col_offset :], *parts[1:-1], parts[-1][: node.end_col_offset]])
    return " ".join(raw.decode(errors="replace").split())


def _owner(holder: ast.AST, lines: list[str]) -> str:
    """What a table belongs to: an assignment's targets, or a decorator's callee and leading plain arguments."""
    if isinstance(holder, ast.Assign):
        return " = ".join(segment(lines, target) for target in holder.targets)
    if isinstance(holder, ast.AnnAssign | ast.AugAssign):
        return segment(lines, holder.target)
    if isinstance(holder, ast.Call):
        leading = [segment(lines, arg) for arg in holder.args if not isinstance(arg, CONTAINERS)]
        return f"{segment(lines, holder.func)}({', '.join(leading)})"
    return type(holder).__name__


def anchor(node: ast.AST, parents: dict[int, ast.AST], lines: list[str]) -> tuple[int, str]:
    """(identity, key text) of what holds a skip, behind the conditions that guard it.

    Inside a table the row is the outermost element of the outermost list, named with what owns the
    table (`A =`, `pytestmark =`, `parametrize('x')`): adding a case beside it leaves it old, moving
    it to another row or table makes it new. Otherwise the decorator or statement in full, so widening
    a multi-line `skipif(...)`, or the `if` around a `pytest.skip()`, makes it new.
    """
    guards: list[str] = []
    found: tuple[int, str] | None = None
    row: ast.AST | None = None
    child, parent = node, parents.get(id(node))
    while parent is not None:
        if found is None and isinstance(parent, CONTAINERS) and child in parent.elts:
            row = child
        holder: ast.AST | None = None
        if found is None and isinstance(parent, DECORATED) and child in parent.decorator_list:
            holder, text = child, span(lines, child)
        elif found is None and isinstance(parent, ast.stmt):
            holder = parent
            text = span(lines, parent) if not hasattr(parent, "body") else " ".join(lines[parent.lineno - 1].split())
        if holder is not None:
            if row is not None:
                holder = holder if isinstance(holder, ast.stmt | ast.Call) else parent
                text = f"{_owner(holder, lines)} :: {segment(lines, row)}"
            found = (id(row if row is not None else holder), text)
        if isinstance(parent, ast.If | ast.While) and child is not parent.test:
            # A skip moved into the `else` inverts its condition, so the branch is part of the key.
            branch = "else of " if child in parent.orelse else ""
            guards.insert(0, branch + span(lines, parent.test))
        child, parent = parent, parents.get(id(parent))
    identity, text = found or (id(node), "")  # every expression sits in a statement; `or` is a guard only
    return identity, " => ".join([*guards, text])
