"""setup.py, conftest.py, sitecustomize/usercustomize and .pth files, read from the syntax tree where Python runs them."""

from __future__ import annotations

import ast
import hashlib
import re

from lifecycle import ASK, BLOCK, Hit, digest, norm
from lifecycle.signals import danger

#: setuptools/distutils commands an override replaces; a subclass of one is a hook on build or install.
COMMANDS = {
    "install", "develop", "egg_info", "build", "build_py", "build_ext", "build_clib", "build_scripts", "sdist",
    "bdist", "bdist_wheel", "bdist_egg", "install_lib", "install_scripts", "install_data", "install_egg_info",
    "easy_install", "editable_wheel", "dist_info",
}  # fmt: skip
#: Modules whose use at import time is fetch-exec class: network, decoding, code objects.
NETWORK = (
    "urllib.request", "urllib2", "requests", "httpx", "urllib3", "http.client", "socket", "aiohttp", "ftplib",
    "pycurl", "smtplib", "xmlrpc.client",
)  # fmt: skip
NOT_NETWORK = {"socket.gethostname"}
DECODING = re.compile(
    r"(?:^|\.)(?:b(?:16|32|64|85)decode|\w*b64decode|decodebytes|a2b_\w+|unhexlify|decompress)$"
    r"|^(?:marshal\.loads?|pickle\.loads?|codecs\.decode)$"
)
EXEC_BUILTINS = {"exec", "eval", "compile", "__import__"}
#: Process launches: ask on their own, block when their arguments carry a fetch signal.
PROCESS = re.compile(r"^(?:subprocess\.\w+|os\.(?:system|popen|exec\w*|spawn\w*|posix_spawn\w*)|pty\.spawn)$")
PTH_IMPORT = re.compile(r"^import[ \t]")
#: Lookups that pick the code to run from a string: unresolvable here, so asked about.
DYNAMIC = {
    "importlib.import_module",
    "importlib.__import__",
    "importlib.util.module_from_spec",
    "runpy.run_path",
    "runpy.run_module",
}
#: pytest calls these hooks of a conftest at start-up, before any test.
PYTEST_HOOKS = (
    "pytest_configure",
    "pytest_sessionstart",
    "pytest_load_initial_conftests",
    "pytest_collection",
    "pytest_plugin_registered",
    "pytest_addoption",
    "pytest_cmdline",
)


def _aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> dotted origin for every import in the module (`from os import system as s`).

    A star import is recorded under `*<module>`, so a bare call can be resolved against it.
    """
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                names[alias.asname or top] = alias.name if alias.asname else top
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                key = f"*{node.module}" if alias.name == "*" else alias.asname or alias.name
                names[key] = f"{node.module}.{alias.name}"
    return names


def _dotted(node: ast.AST, names: dict[str, str]) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(names.get(node.id, node.id))
        return ".".join(reversed(parts))
    return ""


def _matches(dotted: str, prefixes: tuple[str, ...]) -> bool:
    return any(dotted == p or dotted.startswith(p + ".") for p in prefixes)


def _resolve(call: ast.Call, names: dict[str, str]) -> str:
    """The callee's dotted origin; a bare name a star import may have brought in resolves against it."""
    dotted = _dotted(call.func, names)
    if isinstance(call.func, ast.Name) and call.func.id not in names:
        for key, origin in names.items():
            candidate = f"{origin.removesuffix('.*')}.{call.func.id}"
            if key.startswith("*") and _verdict(candidate):
                return candidate
    return dotted


def _verdict(dotted: str) -> tuple[str, str] | None:
    if dotted.removeprefix("builtins.") in EXEC_BUILTINS:
        return BLOCK, f"calls {dotted}"
    if _matches(dotted, NETWORK) and dotted not in NOT_NETWORK:
        return BLOCK, f"reaches the network ({dotted})"
    if DECODING.search(dotted):
        return BLOCK, f"decodes data ({dotted})"
    if PROCESS.match(dotted):
        return ASK, f"starts a process ({dotted})"
    if dotted in DYNAMIC:
        return ASK, f"resolves code by name at run time ({dotted})"
    return None


def classify_call(call: ast.Call, names: dict[str, str], source: str) -> tuple[str, str] | None:
    """(level, why) for a call that reaches the network, decodes, builds code, starts a process or looks one up."""
    dotted = _resolve(call, names)
    verdict = _verdict(dotted)
    if dotted == "getattr" and call.args:
        target = _dotted(call.args[0], names)
        if target.split(".")[0] in {origin.split(".")[0] for origin in names.values()}:
            verdict = ASK, f"looks up an attribute of {target} by name"
    if verdict and verdict[0] == ASK and (why := danger(ast.get_source_segment(source, call) or "")):
        return BLOCK, f"runs code that {why}"
    return verdict


def _local_functions(tree: ast.Module) -> dict[str, list[ast.AST]]:
    """Every function the module defines, by name; all definitions of a name, since any of them may be the live one."""
    found: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.setdefault(node.name, []).append(node)
    return found


def _import_time(tree: ast.Module, hooks: tuple[str, ...] = ()) -> list[ast.AST]:
    """What runs when the module is imported, over-approximated: module and class bodies, every lambda
    body, and the body of each local function whose name the running code mentions at all (called,
    passed to `atexit.register`, aliased `k = f`), followed through a worklist so each body is read once;
    functions named with a `hooks` prefix (pytest start-up hooks) run too.
    """
    local = _local_functions(tree)
    started = {name for name in local if hooks and name.startswith(hooks)}
    stack: list[ast.AST] = [*tree.body, *(stmt for name in started for fn in local[name] for stmt in fn.body)]
    found: list[ast.AST] = []
    while stack:
        node = stack.pop()
        found.append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack.extend([*node.decorator_list, *node.args.defaults, *filter(None, node.args.kw_defaults)])
            continue
        if isinstance(node, ast.Name) and node.id in local and node.id not in started:
            started.add(node.id)
            stack.extend(stmt for fn in local[node.id] for stmt in fn.body)
        stack.extend(ast.iter_child_nodes(node))
    return found


def _calls(nodes: list[ast.AST], names: dict[str, str], source: str, rule: str) -> list[Hit]:
    hits = []
    for node in nodes:
        if isinstance(node, ast.Call) and (verdict := classify_call(node, names, source)):
            text = norm(ast.get_source_segment(source, node) or ast.dump(node))
            hits.append(Hit(node.lineno, rule, "import-time", text, verdict[0], verdict[1]))
    return hits


def _parse(path: str, text: str, level: str) -> tuple[ast.Module | None, list[Hit]]:
    """The tree, or None with a hit: an install script that does not parse is refused, test code is asked about."""
    try:
        return ast.parse(text), []
    except (SyntaxError, ValueError) as exc:
        name = path.rsplit("/", 1)[-1]
        return None, [Hit(getattr(exc, "lineno", None) or 1, "python-unparseable", name, "", level, "does not parse")]


def _cmd_classes(tree: ast.Module, names: dict[str, str], source: str) -> list[Hit]:
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = {_dotted(b, names).rsplit(".", 1)[-1] for b in node.bases}
            if bases & COMMANDS:
                inner = [n for n in ast.walk(node) if isinstance(n, ast.Call)]
                verdicts = [v for n in inner if (v := classify_call(n, names, source))]
                level, why = next((v for v in verdicts if v[0] == BLOCK), (ASK, "overrides a setuptools command"))
                body = hashlib.sha256(ast.dump(node).encode()).hexdigest()[:16]
                hits.append(Hit(node.lineno, "setup-cmdclass", f"class {node.name}", body, level, why))
        elif isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "cmdclass":
                    value = norm(ast.get_source_segment(source, keyword.value) or ast.dump(keyword.value))
                    hits.append(
                        Hit(
                            keyword.value.lineno,
                            "setup-cmdclass",
                            "cmdclass",
                            value,
                            ASK,
                            "setup() replaces build or install commands (cmdclass)",
                        )
                    )
    return hits


def setup_py(path: str, text: str) -> list[Hit]:
    tree, hits = _parse(path, text, BLOCK)
    if tree is None:
        return hits
    names = _aliases(tree)
    return _cmd_classes(tree, names, text) + _calls(_import_time(tree), names, text, "setup-import-time")


def conftest_py(path: str, text: str) -> list[Hit]:
    tree, hits = _parse(path, text, ASK)
    if tree is None:
        return hits
    return _calls(_import_time(tree, PYTEST_HOOKS), _aliases(tree), text, "conftest-import-time")


def customize_py(path: str, text: str) -> list[Hit]:
    """sitecustomize/usercustomize run in every interpreter start; any new or changed one is asked about."""
    name = path.rsplit("/", 1)[-1]
    why = danger(text)
    key = digest(text)
    return [Hit(1, "python-startup-file", name, key, BLOCK if why else ASK, why or "runs at every interpreter start")]


def pth(text: str) -> list[Hit]:
    """A .pth line that starts with `import` is executed by site.py at every interpreter start."""
    return [
        Hit(number, "pth-import", ".pth", norm(line), BLOCK, "executes at every interpreter start")
        for number, line in enumerate(text.splitlines(), 1)
        if PTH_IMPORT.match(line)
    ]
