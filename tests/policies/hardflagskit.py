"""Shared loader for the hardening-flags tests."""

from __future__ import annotations

import sys

from policies import scriptkit

NAME = "hardening-flags-gate.py"


_LOADED: list[object] = []


def load_gate() -> object:
    """Import the gate once, with its own shipped chock_scan copy: tests/chock_scan shadows that name in a full run."""
    if _LOADED:
        return _LOADED[0]
    saved = {k: v for k, v in sys.modules.items() if k == "chock_scan" or k.startswith("chock_scan.")}
    for key in saved:
        del sys.modules[key]
    try:
        _LOADED.append(scriptkit.load("hardening-flags", NAME))
        return _LOADED[0]
    finally:
        for key in [k for k in sys.modules if k == "chock_scan" or k.startswith("chock_scan.")]:
            del sys.modules[key]
        sys.modules.update(saved)
