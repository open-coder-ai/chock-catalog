"""Load package-lifecycle-scripts' gate in-process without its `chock_scan` meeting tests/chock_scan (same name)."""

from __future__ import annotations

import sys
from types import ModuleType

from policies import scriptkit

POLICY = "package-lifecycle-scripts"
NAME = "package-lifecycle-scripts-gate.py"
PACKAGES = ("chock_scan", "lifecycle")


def _ours(name: str) -> bool:
    return any(name == p or name.startswith(p + ".") for p in PACKAGES)


def load_gate() -> ModuleType:
    """The gate module, bound to its own shipped copies; sys.path and sys.modules are left as found."""
    path, saved = list(sys.path), {k: v for k, v in sys.modules.items() if _ours(k)}
    for name in saved:
        del sys.modules[name]
    try:
        return scriptkit.load(POLICY, NAME)
    finally:
        for name in [k for k in sys.modules if _ours(k)]:
            del sys.modules[name]
        sys.modules.update(saved)
        sys.path[:] = path
