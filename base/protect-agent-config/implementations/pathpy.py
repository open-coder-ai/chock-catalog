"""Whether a Python script fed on standard input or given by `-c` provably writes no file: a small read-only subset, read with `ast` (stdlib only)."""

from __future__ import annotations

import ast
import re

# `python3 -I -`: only flags that change no file and run no other code; `-` (or nothing) reads the script from stdin.
_FLAGS = re.compile(r"-[IEsSBuqOP]+")
# -I is required: it ignores PYTHON* variables and user site-packages and keeps the working directory off sys.path.
_ISOLATED = re.compile(r"-[EsSBuqOP]*I[EsSBuqOP]*")
_MODULES = {"json": frozenset(("load", "loads", "dumps"))}
_BANNED = frozenset(
    (
        *("exec", "eval", "compile", "getattr", "setattr", "delattr", "globals", "locals", "vars"),
        *("breakpoint", "help", "input", "memoryview"),
    )
)
_OPEN_KEYS = frozenset(("mode", "encoding", "errors", "newline", "buffering"))
_OPEN_POSITIONAL = 2  # open(file, mode): buffering and the rest go by keyword, opener never
_READ_MODE = re.compile(r"[rbt]*")
_CODE = re.compile(r"-([IEsSBuqOP]*)c")  # `-c`, `-Ic`: the letters before c are flags too
_EXPANDS = re.compile(r"[$`]")  # a `-c` word the shell may expand: the code Python gets is not the text shown


def _isolated(flags: list[str]) -> bool:
    """Whether the flags are all `-IEsSBuqOP...`, with -I among them."""
    return all(_FLAGS.fullmatch(a) for a in flags) and any(_ISOLATED.fullmatch(a) for a in flags)


def _python(name: str) -> bool:
    return name.rsplit("/", 1)[-1].startswith("python")


def _open(call: ast.Call) -> bool:
    """`open(path)`, `open(path, 'r'|'rb'|'rt')`, with only encoding, errors, newline or buffering besides."""
    if len(call.args) > _OPEN_POSITIONAL or any(isinstance(a, ast.Starred) for a in call.args):
        return False
    if any(k.arg not in _OPEN_KEYS for k in call.keywords):  # `**kw` has arg None
        return False
    modes = [*call.args[1:2], *(k.value for k in call.keywords if k.arg == "mode")]
    return all(
        isinstance(m, ast.Constant) and isinstance(m.value, str) and _READ_MODE.fullmatch(m.value) for m in modes
    )


def _imports(tree: ast.Module) -> dict[str, frozenset[str]] | None:
    """Each module name the script binds and the attributes it may use, or None when it imports anything else."""
    modules: dict[str, frozenset[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, ast.Import):
            if any(a.name not in _MODULES for a in node.names):
                return None
            modules.update({a.asname or a.name: _MODULES[a.name] for a in node.names})
            continue
        allowed = _MODULES.get(node.module or "") if not node.level else None
        if allowed is None or any(a.name not in allowed for a in node.names):
            return None
    return modules


def _names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    return [node.arg] if isinstance(node, ast.keyword) and node.arg else []


def _node(node: ast.AST, modules: dict[str, frozenset[str]], calls: set[int]) -> bool:
    """Whether one node stays inside the read-only subset."""
    if any(n.startswith("_") or n in _BANNED for n in _names(node)):
        return False
    if isinstance(node, ast.Name):
        if node.id in modules and not isinstance(node.ctx, ast.Load):
            return False  # a module name rebound
        return node.id != "open" or id(node) in calls  # `f = open` hides the mode a later call passes
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
        return _open(node)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in modules:
        return node.attr in modules[node.value.id]
    return True


def read_only(name: str, args: list[str], scripts: list[str]) -> bool:
    """Whether `python [flags] [-]` fed these scripts on stdin can open files only for reading and import nothing but json.

    The subset: builtins without exec, eval, getattr and the like; no name or attribute starting with `_`; `open` only
    called, in a read mode; no import but json (load, loads, dumps); and always -I. Anything else is not read-only.
    """
    if not scripts or not _python(name):
        return False
    return _isolated(args[:-1] if args[-1:] == ["-"] else args) and _subset(scripts)


def _subset(scripts: list[str]) -> bool:
    """Whether every script parses and stays inside the read-only subset."""
    try:
        trees = [ast.parse(s) for s in scripts]
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    for tree in trees:
        modules = _imports(tree)
        if modules is None:
            return False
        calls = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        if not all(_node(n, modules, calls) for n in ast.walk(tree)):
            return False
    return True


def _opened(tree: ast.Module) -> set[str]:
    """The literal paths a read-only script passes straight to `open()`."""
    return {
        n.args[0].value
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "open"
        and n.args
        and isinstance(n.args[0], ast.Constant)
        and isinstance(n.args[0].value, str)
    }


def judged(name: str, args: list[str], scripts: list[str]) -> list[str]:
    """The script text the guard judges: a read-only script without the quoted paths it only opens to read; any other as given.

    Every other string stays: a read-only script that merely names a protected path (`print('.mcp.json')`) is judged as before.
    """
    return [_strip(s) for s in scripts] if read_only(name, args, scripts) else scripts


def _strip(script: str) -> str:
    """A read-only script without the quoted paths it only opens to read."""
    for path in _opened(ast.parse(script)):
        script = script.replace(f"'{path}'", "''").replace(f'"{path}"', '""')
    return script


def inline(name: str, args: list[str]) -> list[str] | None:
    """`python -I [flags] -c CODE`, CODE last and inside the read-only subset: the arguments with CODE judged as `judged`
    judges a script. None for any other command; CODE holding `$` or a backquote is never read-only."""
    found = _CODE.fullmatch(args[-2]) if len(args) > 1 and _python(name) else None
    if found is None or _EXPANDS.search(args[-1]):
        return None
    flags = [*args[:-2], *([f"-{found.group(1)}"] if found.group(1) else [])]
    return [*args[:-1], _strip(args[-1])] if _isolated(flags) and _subset([args[-1]]) else None
