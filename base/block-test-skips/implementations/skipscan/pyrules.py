"""Python skips from the syntax tree: markers, runtime skips, imported aliases and collection hooks."""

from __future__ import annotations

import ast
import re

from skipscan import CONFIG, SKIP
from skipscan.scan import PY_BREAK, split_lines

PYTEST_STOPS = frozenset({"skip", "xfail", "importorskip", "Skipped", "XFailed"})
UNITTEST_STOPS = frozenset({"skip", "skipIf", "skipUnless", "expectedFailure"})
MARKS = frozenset({"skip", "skipif", "xfail"})
ANYWHERE = frozenset({"skipTest", "SkipTest"})
BY_NAME = PYTEST_STOPS | UNITTEST_STOPS | MARKS | ANYWHERE
STAR = {"pytest": PYTEST_STOPS, "unittest": UNITTEST_STOPS | {"SkipTest"}}
COLLECT = frozenset({"collect_ignore", "collect_ignore_glob"})
DROPPERS = frozenset({"remove", "pop", "clear"})
HOOK_ARGS = frozenset({"self", "config", "session"})
#: Command-line options a conftest can set in code: `config.option.keyword = "not x"` deselects.
OPTIONS = frozenset({"keyword", "deselect", "ignore", "ignore_glob", "markexpr"})
#: Source encodings that keep `pytest.skip` spelled as itself; any other could hide it from this reading.
PLAIN_CODINGS = frozenset({"utf-8", "utf8", "utf-8-sig", "ascii", "us-ascii", "latin-1", "latin1", "iso-8859-1"})
CODING = re.compile(r"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
#: Used only when the file does not parse: the same names, matched as text.
FALLBACK = re.compile(
    r"\bpytest\.(?:skip|xfail|importorskip)\b|\bmark\.(?:skip|skipif|xfail)\b|\bunittest\.(?:skip\w*|expectedFailure)\b"
    r"|\b(?:skipTest|SkipTest|Skipped|XFailed)\b|\bcollect_ignore|\bpytest_(?:collection_modifyitems|ignore_collect)\b"
    r"|\boption\.(?:keyword|deselect|ignore|markexpr)\b"
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


def _canonical(node: ast.AST, aliases: dict[str, str]) -> str | None:
    dotted = _dotted(node)
    if dotted is None:
        return None
    head, _, rest = dotted.partition(".")
    full = aliases.get(head, head)
    return f"{full}.{rest}" if rest else full


def _aliases(tree: ast.AST) -> dict[str, str]:
    """Local name -> what it stands for: imports (`as` and `*` included), then plain `m = pytest.mark` names."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                names[local] = alias.name if alias.asname else local
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    names.update({name: f"{node.module}.{name}" for name in STAR.get(node.module, ())})
                else:
                    names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            value = _canonical(node.value, names)
            if value and value.split(".")[0] in ("pytest", "_pytest", "unittest"):
                names[node.targets[0].id] = value
    return names


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
    """`mark.xfail(strict=True)` without `run=False`: the spec (HP07) judges only non-strict xfail.

    A strict xfail still reports a failing test as xfailed; what it adds is that the run fails once the
    test passes, so the marker cannot outlive the bug it names.
    """
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


def _is_marker(node: ast.AST, aliases: dict[str, str], exempt: set[int]) -> bool:
    if _is_getattr_skip(node) or (isinstance(node, ast.Attribute) and node.attr in ANYWHERE):
        # `skipTest` and `SkipTest` skip whatever owns them: `super().skipTest(...)` has no dotted name.
        return True
    if not isinstance(node, ast.Attribute | ast.Name) or id(node) in exempt:
        return False
    name = _canonical(node, aliases)
    return bool(name and is_skip_name(name))


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


def _sets_option(node: ast.AST) -> bool:
    """`setattr(config.option, "keyword", ...)`: the option assignment reached by string."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setattr"):
        return False
    owner = _dotted(node.args[0]) if node.args else None
    named = node.args[1] if len(node.args) > 1 else None
    return bool(owner and owner.endswith("option")) and isinstance(named, ast.Constant) and named.value in OPTIONS


def _hook_hits(tree: ast.AST) -> list[Hit]:
    """Collection hooks and options that drop tests: `pytest_ignore_collect`, `..._modifyitems`, `option.*`."""
    hits: list[Hit] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and node.attr in OPTIONS
            and (_dotted(node) or "").endswith(".option." + node.attr)
        ):
            hits.append((node.lineno, CONFIG, None))
        if _sets_option(node):
            hits.append((node.lineno, CONFIG, None))
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if node.name == "pytest_ignore_collect":
            hits.append((node.lineno, CONFIG, None))
        elif node.name == "pytest_collection_modifyitems":
            every = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
            params = {arg.arg for arg in every} - HOOK_ARGS
            hits += [(inner.lineno, CONFIG, None) for inner in ast.walk(node) if _drops(inner, params)]
    return hits


def _span(lines: list[str], node: ast.AST) -> str:
    """The whole lines a node covers, whitespace-normalized."""
    end = getattr(node, "end_lineno", None) or node.lineno
    return " ".join(" ".join(lines[node.lineno - 1 : end]).split())


def _anchor(node: ast.AST, parents: dict[int, ast.AST], lines: list[str], source: str) -> str:
    """What a skip is keyed by: its list element, decorator or statement in full, behind the conditions guarding it.

    Widening a multi-line `skipif(...)`, or the `if` around a `pytest.skip()`, changes the key, so it is new;
    a case added beside a `pytest.param(..., marks=...)` in a table leaves that element's key alone.
    """
    guards: list[str] = []
    text = ""
    child, parent = node, parents.get(id(node))
    while parent is not None:
        decorated = isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
        if not text and decorated and child in parent.decorator_list:
            text = _span(lines, child)
        if not text and isinstance(parent, ast.List | ast.Tuple | ast.Set) and child in parent.elts:
            text = " ".join((ast.get_source_segment(source, child) or _span(lines, child)).split())
        if not text and isinstance(parent, ast.stmt):
            simple = not hasattr(parent, "body")
            text = _span(lines, parent) if simple else " ".join(lines[parent.lineno - 1].split())
        if isinstance(parent, ast.If | ast.While) and child is not parent.test:
            # A skip moved into the `else` inverts its condition, so the branch is part of the key.
            branch = "else of " if child in parent.orelse else ""
            guards.insert(0, branch + _span(lines, parent.test))
        child, parent = parent, parents.get(id(parent))
    return " => ".join([*guards, text])


def _coding_hit(text: str) -> list[Hit]:
    for number, line in enumerate(split_lines(text, PY_BREAK)[:2], 1):
        found = CODING.match(line)
        if found and found.group(1).lower().replace("_", "-") not in PLAIN_CODINGS:
            return [(number, SKIP, f"coding|{found.group(1)}")]
    return []


def python_hits(text: str) -> list[Hit]:
    """Every skip, deselection and collection change in a Python test file; by text when it does not parse."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return [
            (number, SKIP, None)
            for number, line in enumerate(split_lines(text, PY_BREAK), 1)
            if not line.lstrip().startswith("#") and FALLBACK.search(line)
        ]
    aliases = _aliases(tree)
    exempt = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call) and _strict_xfail(node, aliases)}
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    lines = split_lines(text, PY_BREAK)
    markers = [
        (node.lineno, SKIP, _anchor(node, parents, lines, text))
        for node in ast.walk(tree)
        if _is_marker(node, aliases, exempt)
    ]
    return _coding_hit(text) + markers + _collect_hits(tree) + _hook_hits(tree)
