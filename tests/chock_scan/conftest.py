"""Fixtures for the chock_scan tests: each module is loaded from lib/ and from every copy a policy ships."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from chock_scan.yamlkit import IDS, SOURCES
from chock_scan.yamlkit import load as load_yamlpath
from trees import ROOT, TREES

JSONC_SOURCES = sorted(
    {ROOT / "lib" / "chock_scan"}
    | {p.parent for tree in TREES for p in (ROOT / tree).glob("*/implementations/chock_scan/jsonc.py")}
)


def load(package: Path, module: str) -> ModuleType:
    name = f"{module}_" + package.relative_to(ROOT).as_posix().replace("/", "_").replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, package / f"{module}.py")
    assert spec is not None
    assert spec.loader is not None
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


@pytest.fixture(params=SOURCES, ids=IDS)
def yp(request: pytest.FixtureRequest) -> ModuleType:
    return load_yamlpath(request.param)


@pytest.fixture(params=JSONC_SOURCES, ids=[s.relative_to(ROOT).as_posix() for s in JSONC_SOURCES])
def jsonc(request: pytest.FixtureRequest) -> ModuleType:
    return load(request.param, "jsonc")
