"""Load verify-dependency-exists' gate and readers in-process, past tests/chock_scan, which shadows the shipped copy."""

from __future__ import annotations

import contextlib
import importlib
import sys
from collections.abc import Iterator
from functools import cache
from types import ModuleType, SimpleNamespace

from policies import scriptkit

POLICY = "verify-dependency-exists"
NAME = "dependency-manifests.py"
READERS = (
    "dart", "dotnet", "elixir", "families", "golang", "gradle", "lockfiles", "maven", "node", "norm", "php",
    "pyreq", "pytoml", "ruby", "rust", "swift", "xmlsafe",
)  # fmt: skip


@contextlib.contextmanager
def shipped_copy() -> Iterator[None]:
    """`chock_scan` and `depnames` resolve to the policy's own copies inside the block, and the test package after."""
    here = str(scriptkit.script_path(POLICY, NAME).parent)
    held = {k: sys.modules.pop(k) for k in list(sys.modules) if k.split(".")[0] == "chock_scan"}
    sys.path.insert(0, here)
    try:
        yield
    finally:
        while here in sys.path:
            sys.path.remove(here)
        for key in [k for k in sys.modules if k.split(".")[0] == "chock_scan"]:
            del sys.modules[key]
        sys.modules.update(held)


@cache
def load() -> tuple[ModuleType, SimpleNamespace]:
    """(the gate script as a module, every depnames reader module by name)."""
    with shipped_copy():
        gate = scriptkit.load(POLICY, NAME)
        readers = {name: importlib.import_module(f"depnames.{name}") for name in READERS}
    return gate, SimpleNamespace(**readers)
