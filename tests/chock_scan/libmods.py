"""Load a chock_scan module from lib/ and from every copy a policy ships, so a test runs against each of them."""

from __future__ import annotations

import ast
import importlib.util
import random
import sys
from pathlib import Path
from types import ModuleType

from trees import ROOT, TREES

LIB = ROOT / "lib" / "chock_scan"


def sources(module: str) -> list[Path]:
    """lib/chock_scan plus every policy's implementations/chock_scan that ships `module`."""
    copies = {p.parent for tree in TREES for p in (ROOT / tree).glob(f"*/implementations/chock_scan/{module}.py")}
    return sorted({LIB} | copies)


def ids(paths: list[Path]) -> list[str]:
    """Readable test ids: the package path relative to the repository."""
    return [p.relative_to(ROOT).as_posix() for p in paths]


def load(package: Path, module: str) -> ModuleType:
    """Import package/module.py under a name unique to its location."""
    name = f"{module}_" + package.relative_to(ROOT).as_posix().replace("/", "_").replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, package / f"{module}.py")
    assert spec is not None
    assert spec.loader is not None
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[name] = loaded  # dataclass/NamedTuple machinery resolves the module by name
    spec.loader.exec_module(loaded)
    return loaded


def stdlib_only(module: str) -> bool:
    """True when lib/chock_scan/<module>.py imports nothing outside the standard library."""
    tree = ast.parse((LIB / f"{module}.py").read_text(encoding="utf-8"))
    names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    return bool(names) and {n.split(".")[0] for n in names} <= set(sys.stdlib_module_names)


def rng(seed: int) -> random.Random:
    """A reproducible generator: a failure reproduces from its seed (hypothesis is not a dev dependency)."""
    return random.Random(seed)  # noqa: S311 -- reproducible test data, not a secret
