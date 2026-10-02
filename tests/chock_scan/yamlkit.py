"""The yamlpath scanner from lib/ and from every policy that ships a copy, each loaded under its own name."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from trees import ROOT, TREES

SOURCES = sorted(
    {ROOT / "lib" / "chock_scan"}
    | {p.parent for tree in TREES for p in (ROOT / tree).glob("*/implementations/chock_scan/yamlpath.py")}
)
IDS = [s.relative_to(ROOT).as_posix() for s in SOURCES]


def load(package: Path) -> ModuleType:
    """The yamlpath module of the chock_scan package at `package`."""
    name = "yamlpath_" + package.relative_to(ROOT).as_posix().replace("/", "_").replace("-", "_")
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, package / "__init__.py", submodule_search_locations=[str(package)]
        )
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return importlib.import_module(f"{name}.yamlpath")


def triples(yp: ModuleType, text: str) -> list[tuple]:
    """(path, value, kind) of every node, the shape most tests compare."""
    return [(n.path, n.value, n.kind) for n in yp.scan(text)]


def value_at(yp: ModuleType, text: str, path: tuple) -> str:
    """The one node at `path`."""
    found = [n for n in yp.scan(text) if n.path == path]
    assert len(found) == 1, found
    return found[0].value
