"""Load chock_scan's host modules from lib/ and from every copy a policy ships, as one namespace each."""

from __future__ import annotations

import functools
import importlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from trees import ROOT, TREES

MODULES = ("idn", "hosts", "urls", "hostmatch")
FIXTURES = Path(__file__).parent / "fixtures" / "hosts"
SOURCES = sorted(
    {ROOT / "lib" / "chock_scan"}
    | {p.parent for tree in TREES for p in (ROOT / tree).glob("*/implementations/chock_scan/hosts.py")}
)


@functools.cache
def load(package: Path) -> SimpleNamespace:
    """The package's host modules (those the copy ships) under a name unique to this source folder."""
    name = "hostkit_" + package.relative_to(ROOT).as_posix().replace("/", "_").replace("-", "_")
    spec = importlib.util.spec_from_file_location(
        name, package / "__init__.py", submodule_search_locations=[str(package)]
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    shipped = [m for m in MODULES if (package / f"{m}.py").is_file()]
    return SimpleNamespace(**{m: importlib.import_module(f"{name}.{m}") for m in shipped})


def sources(module: str) -> list[Any]:
    """pytest params: every source folder that ships `module`, labelled by its path."""
    return [pytest.param(p, id=p.relative_to(ROOT).as_posix()) for p in SOURCES if (p / f"{module}.py").is_file()]


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))
