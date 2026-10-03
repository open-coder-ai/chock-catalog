"""Load compromised-package-ioc's gate and readers in-process, beside tests/chock_scan rather than over it."""

from __future__ import annotations

import importlib
import sys
from types import ModuleType

from policies import scriptkit
from trees import ROOT

POLICY = "compromised-package-ioc"
GATE = "compromised-package-ioc-gate.py"
IMPL = ROOT / "base" / POLICY / "implementations"


def _load() -> tuple[ModuleType, ModuleType, ModuleType, ModuleType, ModuleType, ModuleType]:
    """The gate, table, npm, python, others and route modules, importing the policy's own chock_scan copy.

    tests/ is on sys.path with a `chock_scan` package of its own, so any `chock_scan` already imported
    is set aside while the policy's modules bind theirs, then put back.
    """
    saved = {k: sys.modules.pop(k) for k in list(sys.modules) if k == "chock_scan" or k.startswith("chock_scan.")}
    sys.path.insert(0, str(IMPL))
    try:
        mods = [importlib.import_module(f"iocscan.{m}") for m in ("table", "npm", "python", "others", "route")]
        gate = scriptkit.load(POLICY, GATE)
    finally:
        while str(IMPL) in sys.path:  # the gate puts its own folder first too
            sys.path.remove(str(IMPL))
        for k in [k for k in sys.modules if k == "chock_scan" or k.startswith("chock_scan.")]:
            sys.modules[f"_ioc_{k}"] = sys.modules.pop(k)
        sys.modules.update(saved)
    table_mod, npm_mod, python_mod, others_mod, route_mod = mods
    return gate, table_mod, npm_mod, python_mod, others_mod, route_mod


gate, table, npm, python, others, route = _load()
iocscan = sys.modules["iocscan"]
TABLE = table.load()


def keys(writes: dict, event: str = "commit") -> list[str]:
    """The finding keys the gate reports for `writes` against the shipped table."""
    return [f["key"] for f in gate.findings({"event": event, "writes": writes}, TABLE)]
