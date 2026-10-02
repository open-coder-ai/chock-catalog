"""Which lib/ modules a file imports, so a declared module list never ships a copy that fails at import.

Only static imports are read (`import`, `from ... import`, at any depth); importlib and __import__
are not followed, so lib/ modules use static imports only.
"""

from __future__ import annotations

import ast
from pathlib import Path

INIT = "__init__"
Need = tuple[str, str]


def imports(path: Path, pkg: str | None, pkgs: dict[str, Path]) -> set[Need]:
    """The lib modules a file imports, as (package, module); (package, __init__) for the package itself.

    `pkg` is the lib package the file belongs to (for relative imports), or None for a guard script.
    """
    needs: set[Need] = set()
    for node in ast.walk(ast.parse(path.read_bytes(), filename=str(path))):
        if isinstance(node, ast.ImportFrom):
            if node.level > (1 if pkg else 0):
                msg = f"{path.name}: a relative import beyond its package (packages here are flat)"
                raise ValueError(msg)
            target = node.module or ""
            if node.level:
                target = f"{pkg}.{target}" if target else str(pkg)
            needs |= resolve(target, [a.name for a in node.names], pkgs)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                needs |= resolve(alias.name, [], pkgs)
    return needs


def resolve(dotted: str, names: list[str], pkgs: dict[str, Path]) -> set[Need]:
    head, _, rest = dotted.partition(".")
    if head not in pkgs:
        return set()
    module = rest.split(".")[0] if rest else INIT
    needs = {(head, INIT), (head, module)}
    if module == INIT:
        needs |= {(head, n) for n in names if n.isidentifier() and (pkgs[head] / f"{n}.py").is_file()}
    return needs


def unlisted(label: str, needs: set[Need], have: set[Need], policy: str) -> list[str]:
    return [f"{policy}: {label} imports {p}.{m}, which is not listed for it" for p, m in sorted(needs - have)]


def closure_problems(policy: str, used: dict[str, list[str]], pkgs: dict[str, Path], guards: list[Path]) -> list[str]:
    """Every lib module a declared module or the policy's own scripts import must be declared too."""
    have = {(pkg, m) for pkg, modules in used.items() for m in [INIT, *modules]}
    sources = [(f"{pkg}.{m}", pkgs[pkg] / f"{m}.py", pkg) for pkg, m in sorted(have)]
    sources += [(guard.name, guard, None) for guard in guards]
    found = []
    for label, path, pkg in sources:
        try:
            needs = imports(path, pkg, pkgs)
        except (SyntaxError, ValueError) as exc:
            found.append(f"{policy}: {label}: cannot be read for imports ({exc})")
            continue
        found += unlisted(label, needs, have, policy)
    return found
