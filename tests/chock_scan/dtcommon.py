"""Shared by the data_table tests: the module from lib/ and every copy a policy ships, and table builders."""

from __future__ import annotations

import importlib.util
import json
import random
import sys
from pathlib import Path
from types import ModuleType

from trees import ROOT, TREES

SOURCES = sorted(
    {ROOT / "lib" / "chock_scan"}
    | {p.parent for tree in TREES for p in (ROOT / tree).glob("*/implementations/chock_scan/data_table.py")}
)
IDS = [s.relative_to(ROOT).as_posix() for s in SOURCES]
CORPUS = Path(__file__).parent / "data_tables"


def load_module(package: Path) -> ModuleType:
    """`<package>.data_table`, imported as a package so its relative import of safe_read resolves."""
    name = "dt_" + package.relative_to(ROOT).as_posix().replace("/", "_").replace("-", "_")
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, package / "__init__.py", submodule_search_locations=[str(package)]
        )
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return importlib.import_module(f"{name}.data_table")


def table(**overrides: object) -> dict:
    """A valid curated table with one payload key, `rows`; an override of None drops the key."""
    doc: dict = {"schema": 1, "kind": "curated", "as_of": "2026-01-15", "source": "https://example.org/x"}
    doc["rows"] = ["a", "b"]
    doc.update(overrides)
    return {k: v for k, v in doc.items() if v is not None}


def write(path: Path, doc: object) -> Path:
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    return path


def rng(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311 -- reproducible test data, not a secret
