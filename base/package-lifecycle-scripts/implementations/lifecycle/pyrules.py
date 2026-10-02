"""setup.py, conftest.py, sitecustomize/usercustomize and .pth files, read from the syntax tree where Python runs them."""

from __future__ import annotations

import ast
import hashlib
import re

from lifecycle import ASK, BLOCK, Hit, norm
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


def _aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> dotted origin for every import in the module (`from os import system as s`)."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
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


def classify_call(call: ast.Call, names: dict[str, str], source: str) -> tuple[str, str] | None:
    """(level, why) for a call that reaches the network, decodes, builds code or starts a process."""
    dotted = _dotted(call.func, names)
    if dotted.removeprefix("builtins.") in EXEC_BUILTINS:
        return BLOCK, f"calls {dotted}"
    if _matches(dotted, NETWORK) and dotted not in NOT_NETWORK:
        return BLOCK, f"reaches the network ({dotted})"
    if DECODING.search(dotted):
        return BLOCK, f"decodes data ({dotted})"
    if PROCESS.match(dotted):
        text = ast.get_source_segment(source, call) or ""
        why = danger(text)
        return (BLOCK, f"starts a process that {why}") if why else (ASK, f"starts a process ({dotted})")
    return None


def _import_time(tree: ast.Module) -> list[ast.AST]:
    """Module-level statements and what they contain, minus function and class bodies (those run later)."""
    found: list[ast.AST] = []
    stack: list[ast.AST] = list(tree.body)
    while stack:
        node = stack.pop()
        found.append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            stack.extend(node.decorator_list if not isinstance(node, ast.Lambda) else [])
            continue
        if isinstance(node, ast.ClassDef):
            stack.extend([*node.decorator_list, *node.bases, *node.keywords])
            continue
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
    return _calls(_import_time(tree), _aliases(tree), text, "conftest-import-time")


def customize_py(path: str, text: str) -> list[Hit]:
    """sitecustomize/usercustomize run in every interpreter start; any new or changed one is asked about."""
    name = path.rsplit("/", 1)[-1]
    why = danger(text)
    digest = hashlib.sha256(norm(text).encode()).hexdigest()[:16]
    return [
        Hit(1, "python-startup-file", name, digest, BLOCK if why else ASK, why or "runs at every interpreter start")
    ]


def pth(text: str) -> list[Hit]:
    """A .pth line that starts with `import` is executed by site.py at every interpreter start."""
    return [
        Hit(number, "pth-import", ".pth", norm(line), BLOCK, "executes at every interpreter start")
        for number, line in enumerate(text.splitlines(), 1)
        if PTH_IMPORT.match(line)
    ]
