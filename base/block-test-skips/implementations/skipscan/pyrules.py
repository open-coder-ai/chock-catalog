"""Python skips from the syntax tree: markers, runtime skips, imported aliases and collection hooks."""

from __future__ import annotations

import ast
import re

from skipscan import CONFIG, SKIP

PYTEST_STOPS = frozenset({"skip", "xfail", "importorskip"})
UNITTEST_STOPS = frozenset({"skip", "skipIf", "skipUnless", "expectedFailure"})
MARKS = frozenset({"skip", "skipif", "xfail"})
ANYWHERE = frozenset({"skipTest", "SkipTest"})
BY_NAME = PYTEST_STOPS | UNITTEST_STOPS | MARKS | ANYWHERE
COLLECT = frozenset({"collect_ignore", "collect_ignore_glob"})
DROPPERS = frozenset({"remove", "pop", "clear"})
HOOK_ARGS = frozenset({"self", "config", "session"})
#: Used only when the file does not parse: the same names, matched as text.
FALLBACK = re.compile(
    r"\bpytest\.(?:skip|xfail|importorskip)\b|\bmark\.(?:skip|skipif|xfail)\b|\bunittest\.(?:skip\w*|expectedFailure)\b"
    r"|\b(?:skipTest|SkipTest)\b|\bcollect_ignore|\bpytest_(?:collection_modifyitems|ignore_collect)\b"
)

Hit = tuple[int, str, str | None]


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _aliases(tree: ast.AST) -> dict[str, str]:
    """Local name -> what it was imported as (`import pytest as pt`, `from unittest import skip`)."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                names[local] = alias.name if alias.asname else local
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _canonical(node: ast.AST, aliases: dict[str, str]) -> str | None:
    dotted = _dotted(node)
    if dotted is None:
        return None
    head, _, rest = dotted.partition(".")
    full = aliases.get(head, head)
    return f"{full}.{rest}" if rest else full


def is_skip_name(name: str) -> bool:
    """A pytest or unittest name whose use skips, deselects or expects a test to fail."""
    parts = name.split(".")
    last = parts[-1]
    if last in ANYWHERE or (len(parts) > 1 and parts[-2] == "mark" and last in MARKS):
        return True
    if parts[0] in ("pytest", "_pytest"):
        return len(parts) > 1 and last in PYTEST_STOPS
    return parts[0] == "unittest" and len(parts) > 1 and last in UNITTEST_STOPS


def _strict_xfail(call: ast.Call, aliases: dict[str, str]) -> bool:
    """`mark.xfail(strict=True)` without `run=False`: an unexpected pass fails, so nothing is hidden."""
    name = _canonical(call.func, aliases) or ""
    if not name.endswith("mark.xfail"):
        return False
    words = {kw.arg: kw.value for kw in call.keywords}
    strict = words.get("strict")
    run = words.get("run")
    is_true = isinstance(strict, ast.Constant) and strict.value is True
    runs = run is None or (isinstance(run, ast.Constant) and run.value is True)
    return is_true and runs


def _is_getattr_skip(node: ast.AST) -> bool:
    """`getattr(pytest.mark, "skip")` and the like: a skip name reached by string."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr"):
        return False
    named = node.args[1] if len(node.args) > 1 else None
    return isinstance(named, ast.Constant) and named.value in BY_NAME


def _marker_hits(tree: ast.AST, aliases: dict[str, str]) -> list[Hit]:
    exempt = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call) and _strict_xfail(node, aliases)}
    hits: list[Hit] = []
    for node in ast.walk(tree):
        if _is_getattr_skip(node) or (isinstance(node, ast.Attribute) and node.attr in ANYWHERE):
            # `skipTest` and `SkipTest` skip whatever owns them: `super().skipTest(...)` has no dotted name.
            hits.append((node.lineno, SKIP, None))
        elif isinstance(node, ast.Attribute | ast.Name) and id(node) not in exempt:
            name = _canonical(node, aliases)
            if name and is_skip_name(name):
                hits.append((node.lineno, SKIP, None))
    return hits


def _collect_hits(tree: ast.AST) -> list[Hit]:
    """`collect_ignore` entries, one per string, so adding a path to the list is new."""
    hits: list[Hit] = []
    for stmt in ast.walk(tree):
        if not isinstance(stmt, ast.Assign | ast.AugAssign | ast.AnnAssign | ast.Expr):
            continue
        inner = list(ast.walk(stmt))
        if not any(isinstance(node, ast.Name) and node.id in COLLECT for node in inner):
            continue
        values = [node for node in inner if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        hits += [(node.lineno, CONFIG, f"collect_ignore|{node.value}") for node in values]
        if not values:
            hits.append((stmt.lineno, CONFIG, None))
    return hits


def _drops(node: ast.AST, params: set[str]) -> bool:
    """A statement in the collection hook that removes items or reports them deselected."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        owner = node.func.value
        named = isinstance(owner, ast.Name) and owner.id in params
        return node.func.attr == "pytest_deselected" or (named and node.func.attr in DROPPERS)
    targets: list[ast.AST] = []
    if isinstance(node, ast.Assign | ast.Delete):
        targets = list(node.targets)
    elif isinstance(node, ast.AugAssign):
        targets = [node.target]
    return any(isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id in params for t in targets)


def _hook_hits(tree: ast.AST) -> list[Hit]:
    """Collection hooks that drop tests: `pytest_ignore_collect`, and deselection in `..._modifyitems`."""
    hits: list[Hit] = []
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if func.name == "pytest_ignore_collect":
            hits.append((func.lineno, CONFIG, None))
        elif func.name == "pytest_collection_modifyitems":
            every = func.args.posonlyargs + func.args.args + func.args.kwonlyargs
            params = {arg.arg for arg in every} - HOOK_ARGS
            hits += [(node.lineno, CONFIG, None) for node in ast.walk(func) if _drops(node, params)]
    return hits


def python_hits(text: str) -> list[Hit]:
    """Every skip, deselection and collection change in a Python test file; by text when it does not parse."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return [
            (number, SKIP, None)
            for number, line in enumerate(text.splitlines(), 1)
            if not line.lstrip().startswith("#") and FALLBACK.search(line)
        ]
    return _marker_hits(tree, _aliases(tree)) + _collect_hits(tree) + _hook_hits(tree)
