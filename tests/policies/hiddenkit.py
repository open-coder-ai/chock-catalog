"""Load scan-hidden-content's gate and readers in-process, beside tests/chock_scan rather than over it."""

from __future__ import annotations

import importlib
import sys
from types import ModuleType

from policies import scriptkit
from trees import ROOT

POLICY = "scan-hidden-content"
GATE = "scan-hidden-content-gate.py"
IMPL = ROOT / "base" / POLICY / "implementations"
READERS = ("blocks", "spans", "colours", "css", "word", "markup", "markdown", "links", "vocab")


def _load() -> tuple[ModuleType, dict[str, ModuleType]]:
    """The gate and its reader modules, bound to the policy's own chock_scan copy.

    tests/ is on sys.path with a `chock_scan` package of its own, so any `chock_scan` already imported
    is set aside while the policy's modules bind theirs, then put back.
    """
    owned = [k for k in sys.modules if k == "chock_scan" or k.startswith("chock_scan.")]
    saved = {k: sys.modules.pop(k) for k in owned}
    try:
        gate = scriptkit.load(POLICY, GATE)
        readers = {name: importlib.import_module(f"hiddenscan.{name}") for name in READERS}
    finally:
        while str(IMPL) in sys.path:  # the gate puts its own folder first
            sys.path.remove(str(IMPL))
        for k in [k for k in sys.modules if k == "chock_scan" or k.startswith("chock_scan.")]:
            sys.modules[f"_hidden_{k}"] = sys.modules.pop(k)
        sys.modules.update(saved)
    return gate, readers


gate, readers = _load()
