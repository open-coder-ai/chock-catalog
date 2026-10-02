"""Import scan-secret-files' modules as its gate does, without leaking its chock_scan copy into other tests.

tests/chock_scan is a package named chock_scan too, so the policy's absolute imports would resolve
to it; each load swaps the name out and puts sys.path and sys.modules back afterwards.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from types import ModuleType

from trees import ROOT

IMPL = ROOT / "base" / "scan-secret-files" / "implementations"
GATE = "scan-secret-files-gate.py"


def _copy(name: str) -> bool:
    return name == "chock_scan" or name.startswith("chock_scan.")


def load(name: str) -> ModuleType:
    """A module of the policy (`sbf_judge`), or the gate script itself for GATE."""
    saved_path = list(sys.path)
    saved = {key: sys.modules.pop(key) for key in [key for key in sys.modules if _copy(key)]}
    sys.path.insert(0, str(IMPL))
    try:
        if name != GATE:
            return importlib.import_module(name)
        spec = importlib.util.spec_from_file_location("scan_secret_files_gate", IMPL / GATE)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for key in [key for key in sys.modules if _copy(key)]:
            del sys.modules[key]
        sys.modules.update(saved)
        sys.path[:] = saved_path
