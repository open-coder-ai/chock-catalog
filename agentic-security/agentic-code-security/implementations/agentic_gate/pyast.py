"""Python source through `ast`, the way the rules read it: parsed once, calls and keywords by name."""

from __future__ import annotations

import ast
from collections.abc import Iterator
from functools import lru_cache

from agentic_gate.model import FileText

_CACHE_SIZE = 256


@lru_cache(maxsize=_CACHE_SIZE)
def _parse(text: str) -> ast.Module | None:
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None


def tree(text: FileText) -> ast.Module | None:
    """The file's syntax tree, or None when it does not parse: a rule then has nothing to judge."""
    return _parse(text.text)


def calls(text: FileText) -> Iterator[ast.Call]:
    parsed = tree(text)
    if parsed is not None:
        yield from (node for node in ast.walk(parsed) if isinstance(node, ast.Call))


def dotted(node: ast.AST) -> str:
    """`a.b.c` for a name or attribute chain, and '' for anything else."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = dotted(node.value)
        return f"{head}.{node.attr}" if head else ""
    return ""


def callee(call: ast.Call) -> str:
    """The dotted name a call goes to: `subprocess.run`, `LocalCommandLineCodeExecutor`."""
    return dotted(call.func)


def terminal(call: ast.Call) -> str:
    """The last segment of the callee, so `x.y.PythonREPLTool` and `PythonREPLTool` agree."""
    return callee(call).rsplit(".", 1)[-1]


def keyword(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def spreads(call: ast.Call) -> bool:
    """A `**kwargs` in the call: what it passes is not known here."""
    return any(kw.arg is None for kw in call.keywords)


def is_const(node: ast.expr | None, value: str | None) -> bool:
    """Whether the node is the string literal or None `value`."""
    return isinstance(node, ast.Constant) and type(node.value) is type(value) and node.value == value


def is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def string_of(node: ast.expr | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def dict_items(node: ast.Dict) -> Iterator[tuple[str, ast.expr]]:
    """The literal-keyed entries of a dict display."""
    for key, value in zip(node.keys, node.values, strict=True):
        name = string_of(key)
        if name is not None:
            yield name, value


def settings(text: FileText, name: str) -> Iterator[tuple[int, ast.expr]]:
    """Every place `name` is set to a value: as a keyword argument or as a literal dict key."""
    parsed = tree(text)
    if parsed is None:
        return
    for node in ast.walk(parsed):
        if isinstance(node, ast.keyword) and node.arg == name:
            yield node.value.lineno, node.value
        elif isinstance(node, ast.Dict):
            yield from ((value.lineno, value) for key, value in dict_items(node) if key == name)


def is_str(node: ast.expr) -> bool:
    return isinstance(node, ast.JoinedStr) or string_of(node) is not None


def builds_string(node: ast.expr, names: set[str]) -> bool:
    """Whether the expression assembles a string from parts: f-string, %, .format() or +."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return string_of(node.left) is not None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return (
            is_str(node.left) != is_str(node.right)
            or builds_string(node.left, names)
            or builds_string(node.right, names)
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return string_of(node.func.value) is not None
    return isinstance(node, ast.Name) and node.id in names


def identifiers(node: ast.AST) -> set[str]:
    """Every variable and attribute name an expression mentions."""
    return {
        sub.id if isinstance(sub, ast.Name) else sub.attr
        for sub in ast.walk(node)
        if isinstance(sub, ast.Name | ast.Attribute)
    }


def assigned_false(text: FileText, attr: str) -> Iterator[int]:
    """Lines of an assignment `x.<attr> = False`, for a setting made after construction."""
    parsed = tree(text)
    for node in ast.walk(parsed) if parsed else ():
        if isinstance(node, ast.Assign) and is_false(node.value) and any(_sets(t, attr) for t in node.targets):
            yield node.lineno


def _sets(target: ast.expr, attr: str) -> bool:
    return isinstance(target, ast.Attribute) and target.attr == attr
