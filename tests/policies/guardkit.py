"""Load a shipped Python command guard, or its chock_shellparse copy, without one policy's import shadowing another's."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from trees import ROOT

SHELLPARSE = "chock_shellparse"


def impl_dir(policy: str) -> Path:
    return ROOT / "base" / policy / "implementations"


def policies_with_shellparse() -> list[str]:
    """Every policy that ships a chock_shellparse copy."""
    return sorted(
        p.parent.parent.parent.name for p in (ROOT / "base").glob(f"*/implementations/{SHELLPARSE}/__init__.py")
    )


def _forget() -> dict[str, ModuleType]:
    return {name: sys.modules.pop(name) for name in list(sys.modules) if name.split(".")[0] == SHELLPARSE}


def load_guard(policy: str, name: str | None = None) -> ModuleType:
    """Import `base/<policy>/implementations/<name or policy>.py`, resolving chock_shellparse beside it."""
    directory = impl_dir(policy)
    path = directory / f"{name or policy}.py"
    saved = _forget()
    sys.path.insert(0, str(directory))
    try:
        spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(directory))
        _forget()
        sys.modules.update(saved)
    return module


def load_shellparse(policy: str) -> ModuleType:
    """The chock_shellparse package a policy ships, under a name of its own."""
    package = impl_dir(policy) / SHELLPARSE
    name = f"shellparse_{policy.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(
        name, package / "__init__.py", submodule_search_locations=[str(package)]
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
