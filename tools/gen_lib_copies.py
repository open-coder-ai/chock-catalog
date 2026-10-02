#!/usr/bin/env python3
"""Copy the shared modules under lib/ into every policy that declares them in lib/consumers.yaml.

    python tools/gen_lib_copies.py           # write each declared copy, remove what is not declared
    python tools/gen_lib_copies.py --check   # write nothing; fail on any copy that differs from lib/

A plugin ships a policy's `implementations/` folder whole and nothing beside it, so a helper a
guard imports must sit in that folder. lib/<package>/ is the one place it is edited; each copy
is generated, and `--check` (run by check_registry.py and the tests) fails on any drift.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import sys
from pathlib import Path

import yaml
from trees import ROOT, TREES

LIB = "lib"
CONSUMERS = "lib/consumers.yaml"
INIT = "__init__"
Decls = dict[str, dict[str, list[str]]]
Need = tuple[str, str]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def packages(root: Path) -> dict[str, Path]:
    """Every package under lib/: a directory holding an __init__.py."""
    lib = root / LIB
    return {p.name: p for p in sorted(lib.iterdir()) if (p / f"{INIT}.py").is_file()} if lib.is_dir() else {}


def package_problems(pkgs: dict[str, Path], root: Path) -> list[str]:
    """A package is a real folder of flat .py files: anything else would be shipped by nobody."""
    lib = root / LIB
    dirs = sorted(p for p in lib.iterdir() if p.is_dir()) if lib.is_dir() else []
    found = [f"{LIB}/{p.name}: a folder with no __init__.py" for p in dirs if p.name not in pkgs]
    for name, pkg in pkgs.items():
        if not name.isidentifier() or pkg.is_symlink():
            found.append(f"{LIB}/{name}: not a Python package name, or a symlink")
        for entry in sorted(pkg.iterdir()):
            if entry.name == "__pycache__":
                continue
            if entry.is_symlink() or not entry.is_file() or entry.suffix != ".py":
                found.append(f"{LIB}/{name}/{entry.name}: a package holds only .py files, no symlinks or subfolders")
    return found


def load(root: Path, pkgs: dict[str, Path]) -> tuple[Decls, list[str]]:
    """lib/consumers.yaml as {policy path: {package: [module, ...]}}, and what is wrong with it."""
    path = root / CONSUMERS
    if not path.is_file():
        return {}, [f"{CONSUMERS}: missing"]
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return {}, [f"{CONSUMERS}: not YAML ({exc})"]
    if raw is None:
        return {}, []
    if not isinstance(raw, dict):
        return {}, [f"{CONSUMERS}: must map policy paths to {{package: [module, ...]}}"]
    decls: Decls = {}
    found: list[str] = []
    for policy, used in raw.items():
        found += policy_problems(root, policy)
        if not isinstance(used, dict) or not used:
            found.append(f"{CONSUMERS}: {policy}: must map packages to module lists")
            continue
        decls[str(policy)] = {}
        for pkg, modules in used.items():
            problem = module_problems(pkgs, pkg, modules)
            if problem:
                found.append(f"{CONSUMERS}: {policy}: {problem}")
            else:
                decls[str(policy)][pkg] = modules
    return decls, found


def policy_problems(root: Path, policy: object) -> list[str]:
    tree, _, pid = str(policy).partition("/")
    folder = root / str(policy)
    if tree not in TREES or not pid or "/" in pid or not (folder / "manifest.yaml").is_file():
        return [f"{CONSUMERS}: {policy}: not a policy folder (<tree>/<id> in {', '.join(TREES)})"]
    if folder.is_symlink():
        return [f"{CONSUMERS}: {policy}: a symlink, not a policy folder"]
    return []


def module_problems(pkgs: dict[str, Path], pkg: object, modules: object) -> str | None:
    if pkg not in pkgs:
        return f"{pkg}: no such package under {LIB}/"
    if not isinstance(modules, list) or not all(isinstance(m, str) for m in modules):
        return f"{pkg}: must list module names"
    if len(set(modules)) != len(modules):
        return f"{pkg}: lists a module twice"
    absent = [m for m in modules if m == INIT or not (pkgs[str(pkg)] / f"{m}.py").is_file()]
    return f"{pkg}: no module {', '.join(absent)} (its __init__.py always ships)" if absent else None


def imports(path: Path, pkg: str, pkgs: dict[str, Path]) -> set[Need]:
    """The lib modules one module imports, as (package, module); (package, __init__) for the package."""
    needs: set[Need] = set()
    for node in ast.walk(ast.parse(path.read_bytes(), filename=str(path))):
        if isinstance(node, ast.ImportFrom):
            if node.level > 1:
                msg = f"{path.name}: imports beyond its package (packages here are flat)"
                raise ValueError(msg)
            target = node.module or ""
            if node.level:
                target = f"{pkg}.{target}" if target else pkg
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
        needs |= {(head, n) for n in names if (pkgs[head] / f"{n}.py").is_file()}
    return needs


def closure_problems(policy: str, used: dict[str, list[str]], pkgs: dict[str, Path]) -> list[str]:
    """Every module a declared module imports must be declared too, or the copy fails at import."""
    have = {(pkg, m) for pkg, modules in used.items() for m in [INIT, *modules]}
    found = []
    for pkg, module in sorted(have):
        try:
            needs = imports(pkgs[pkg] / f"{module}.py", pkg, pkgs)
        except (SyntaxError, ValueError) as exc:
            found.append(f"{LIB}/{pkg}/{module}.py: {exc}")
            continue
        found += [
            f"{CONSUMERS}: {policy}: {pkg}.{module} imports {p}.{m}, which is not listed for it"
            for p, m in sorted(needs - have)
        ]
    return found


def expected(root: Path, decls: Decls, pkgs: dict[str, Path]) -> dict[Path, Path]:
    """Each copy path, mapped to the lib file it must equal."""
    return {
        root / policy / "implementations" / pkg / f"{m}.py": pkgs[pkg] / f"{m}.py"
        for policy, used in decls.items()
        for pkg, modules in used.items()
        for m in [INIT, *modules]
    }


def copy_dirs(root: Path, pkgs: dict[str, Path]) -> list[Path]:
    """Every `implementations/<lib package>/` folder in a published tree, declared or not."""
    return sorted(d for tree in TREES for pkg in pkgs for d in (root / tree).glob(f"*/implementations/{pkg}"))


def structure(root: Path) -> tuple[dict[Path, Path], list[str]]:
    """What the copies must be, and every problem that stops working that out."""
    pkgs = packages(root)
    found = package_problems(pkgs, root)
    decls, more = load(root, pkgs)
    found += more
    for policy, used in decls.items():
        found += closure_problems(policy, used, pkgs)
    want = expected(root, decls, pkgs)
    declared = {p.parent for p in want}
    found += [
        f"{d.relative_to(root).as_posix()}: a lib copy no entry in {CONSUMERS} declares"
        for d in copy_dirs(root, pkgs)
        if d not in declared
    ]
    found += [
        f"{d.relative_to(root).as_posix()}: a symlink; a copy is a real folder"
        for d in sorted(declared)
        if d.is_symlink()
    ]
    return want, found


def drift(root: Path, want: dict[Path, Path]) -> list[str]:
    """Copies that are missing, differ from lib/, or hold a file lib/ does not have."""
    found = []
    for dest, src in sorted(want.items()):
        rel = dest.relative_to(root).as_posix()
        if dest.is_symlink() or not dest.is_file():
            found.append(f"{rel}: missing (copy of {src.relative_to(root).as_posix()})")
        elif digest(dest) != digest(src):
            found.append(f"{rel}: differs from {src.relative_to(root).as_posix()}")
    found += [f"{p.relative_to(root).as_posix()}: not in {LIB}/ (remove it, or add it there)" for p in extras(want)]
    return found


def extras(want: dict[Path, Path]) -> list[Path]:
    dirs = {p.parent for p in want}
    return sorted(p for d in dirs if d.is_dir() for p in d.iterdir() if p.name != "__pycache__" and p not in want)


def problems(root: Path = ROOT) -> list[str]:
    want, found = structure(root)
    return found or drift(root, want)


def write(root: Path = ROOT) -> tuple[list[str], list[str]]:
    """Make every copy equal lib/; return (paths changed, problems that stopped it)."""
    want, found = structure(root)
    if found:
        return [], found
    changed = []
    for dest, src in sorted(want.items()):
        if dest.is_dir() and not dest.is_symlink():
            return changed, [f"{dest.relative_to(root).as_posix()}: a folder where a lib copy goes; remove it by hand"]
        if dest.is_file() and not dest.is_symlink() and digest(dest) == digest(src):
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.unlink(missing_ok=True)
        dest.write_bytes(src.read_bytes())
        changed.append(dest.relative_to(root).as_posix())
    for extra in extras(want):
        if extra.is_dir() and not extra.is_symlink():
            return changed, [f"{extra.relative_to(root).as_posix()}: a folder inside a lib copy; remove it by hand"]
        extra.unlink()
        changed.append(f"{extra.relative_to(root).as_posix()} (removed)")
    return changed, []


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true", help="write nothing; fail on drift")
    args = parser.parse_args(argv)
    if args.check:
        found = problems(root)
    else:
        changed, found = write(root)
        print("\n".join(f"wrote {path}" for path in changed) or "lib copies already current")
    for problem in found:
        print(f"  {problem}", file=sys.stderr)
    if found:
        print(
            f"lib copies: {len(found)} problem(s); edit {LIB}/ and run python tools/gen_lib_copies.py", file=sys.stderr
        )
        return 1
    if args.check:
        print("every lib copy matches its source")
    return 0


if __name__ == "__main__":
    sys.exit(main())
