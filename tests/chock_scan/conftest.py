"""Fixtures for the chock_scan tests: each runs against lib/ and every copy a policy ships."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from chock_scan.hclload import IDS as HCL_IDS
from chock_scan.hclload import SOURCES as HCL_SOURCES
from chock_scan.hclload import load as load_hcl
from chock_scan.yamlkit import IDS, SOURCES, load
from trees import ROOT, TREES


@pytest.fixture(params=SOURCES, ids=IDS)
def yp(request: pytest.FixtureRequest) -> ModuleType:
    """The yamlpath module, from lib/ and from every copy a policy ships."""
    return load(request.param)


JSONC_SOURCES = sorted(
    {ROOT / "lib" / "chock_scan"}
    | {p.parent for tree in TREES for p in (ROOT / tree).glob("*/implementations/chock_scan/jsonc.py")}
)


def load_module(package: Path, module: str) -> ModuleType:
    name = f"{module}_" + package.relative_to(ROOT).as_posix().replace("/", "_").replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, package / f"{module}.py")
    assert spec is not None
    assert spec.loader is not None
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


@pytest.fixture(params=JSONC_SOURCES, ids=[s.relative_to(ROOT).as_posix() for s in JSONC_SOURCES])
def jsonc(request: pytest.FixtureRequest) -> ModuleType:
    """The jsonc module, from lib/ and from every copy a policy ships."""
    return load_module(request.param, "jsonc")


def sources(module: str) -> list[Path]:
    """lib/chock_scan and every shipped chock_scan folder holding `module`."""
    copies = {p.parent for tree in TREES for p in (ROOT / tree).glob(f"*/implementations/chock_scan/{module}.py")}
    return sorted({ROOT / "lib" / "chock_scan"} | copies)


def load_package(package: Path, module: str) -> ModuleType:
    """`module` imported from `package` as a package of its own, so relative imports resolve inside it."""
    name = "chock_scan_" + package.relative_to(ROOT).as_posix().replace("/", "_").replace("-", "_")
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, package / "__init__.py", submodule_search_locations=[str(package)]
        )
        assert spec is not None
        assert spec.loader is not None
        sys.modules[name] = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sys.modules[name])
    return importlib.import_module(f"{name}.{module}")


SNIFF = sources("sniff")


@pytest.fixture(params=SNIFF, ids=[s.relative_to(ROOT).as_posix() for s in SNIFF])
def sn(request: pytest.FixtureRequest) -> ModuleType:
    """The sniff module, from lib/ and from every copy a policy ships."""
    return load_package(request.param, "sniff")


@pytest.fixture(params=SNIFF, ids=[s.relative_to(ROOT).as_posix() for s in SNIFF])
def sk(request: pytest.FixtureRequest) -> ModuleType:
    """The sniff_keys module, from lib/ and from every copy a policy ships."""
    return load_package(request.param, "sniff_keys")


@pytest.fixture(params=HCL_SOURCES, ids=HCL_IDS)
def m(request: pytest.FixtureRequest) -> SimpleNamespace:
    """chock_scan's HCL modules, from lib/ and from every copy a policy ships."""
    return load_hcl(request.param)
