"""Load chock_scan's HCL modules as a package from lib/ and from every copy a policy ships (byte-equal to lib/)."""

from __future__ import annotations

import importlib
import importlib.util
import random
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

from trees import ROOT, TREES

SOURCES = sorted(
    {ROOT / "lib" / "chock_scan"}
    | {p.parent for tree in TREES for p in (ROOT / tree).glob("*/implementations/chock_scan/hcl.py")}
)
IDS = [s.relative_to(ROOT).as_posix() for s in SOURCES]
CORPUS = ROOT / "tests" / "chock_scan" / "corpus" / "hcl"


def load(package: Path) -> SimpleNamespace:
    """hcl, hcl_lex and hcl_json imported from `package` under a name of their own."""
    name = "hcl_" + package.relative_to(ROOT).as_posix().replace("/", "_").replace("-", "_")
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, package / "__init__.py", submodule_search_locations=[str(package)]
        )
        assert spec is not None
        assert spec.loader is not None
        module: ModuleType = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return SimpleNamespace(**{m: importlib.import_module(f"{name}.{m}") for m in ("hcl", "hcl_lex", "hcl_json")})


def rng(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311 -- reproducible test data, not a secret
