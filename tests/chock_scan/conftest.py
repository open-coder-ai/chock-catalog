"""Load chock_scan modules from lib/ and from every copy a policy ships, each under its own package name."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest
from chock_scan.yamlkit import IDS, SOURCES
from chock_scan.yamlkit import load as load_yamlpath
from trees import ROOT, TREES


def sources(module: str) -> list[Path]:
    """lib/chock_scan and every shipped chock_scan folder holding `module`."""
    copies = {p.parent for tree in TREES for p in (ROOT / tree).glob(f"*/implementations/chock_scan/{module}.py")}
    return sorted({ROOT / "lib" / "chock_scan"} | copies)


def load(package: Path, module: str) -> ModuleType:
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


def ids(paths: list[Path]) -> list[str]:
    return [s.relative_to(ROOT).as_posix() for s in paths]


JSONC = sources("jsonc")
SNIFF = sources("sniff")


@pytest.fixture(params=SOURCES, ids=IDS)
def yp(request: pytest.FixtureRequest) -> ModuleType:
    return load_yamlpath(request.param)


@pytest.fixture(params=JSONC, ids=ids(JSONC))
def jsonc(request: pytest.FixtureRequest) -> ModuleType:
    return load(request.param, "jsonc")


@pytest.fixture(params=SNIFF, ids=ids(SNIFF))
def sn(request: pytest.FixtureRequest) -> ModuleType:
    return load(request.param, "sniff")


@pytest.fixture(params=SNIFF, ids=ids(SNIFF))
def sk(request: pytest.FixtureRequest) -> ModuleType:
    return load(request.param, "sniff_keys")
