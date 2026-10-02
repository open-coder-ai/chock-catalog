"""Shared setup for the guard-deletion tests: the shipped modules on sys.path and a few builders."""

from __future__ import annotations

import contextlib
import sys
from collections.abc import Iterator
from pathlib import Path

from trees import ROOT

IMPL = ROOT / "base" / "guard-deletion" / "implementations"


@contextlib.contextmanager
def shipped() -> Iterator[None]:
    """Import with the policy's own `chock_scan` copy, which tests/chock_scan (a package of the same name) would shadow."""
    saved = {
        k: sys.modules.pop(k) for k in [k for k in sys.modules if k == "chock_scan" or k.startswith("chock_scan.")]
    }
    sys.path.insert(0, str(IMPL))
    try:
        yield
    finally:
        sys.path.remove(str(IMPL))
        for k in [k for k in sys.modules if k == "chock_scan" or k.startswith("chock_scan.")]:
            del sys.modules[k]
        sys.modules.update(saved)


with shipped():
    from chock_scan import data_table
    from diffshape import changes, hunks, judge, scope, shapes

TABLE = shapes.load(IMPL / "data" / "shapes.json")
SCOPE = scope.load(IMPL / "data" / "scope.json")


def no_waiver(_hunk: hunks.Hunk, _involved: list[str], _rule: str) -> bool:
    return False


def verdict(removed: list[str], added: list[str], waived=no_waiver) -> list[tuple[str, str]]:
    """(rule, family) pairs the hunk draws."""
    hunk = hunks.Hunk("src/app.py", 1, tuple(removed), tuple(added))
    return [(f.rule, f.family) for f in judge.judge_hunk(hunk, TABLE, waived)]


def patch(path: str, removed: list[str], added: list[str], start: int = 1) -> str:
    """A -U0 patch of one file."""
    head = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -{start},{len(removed)} +{start},{len(added)} @@\n"
    return head + "".join(f"-{ln}\n" for ln in removed) + "".join(f"+{ln}\n" for ln in added)


__all__ = [
    "IMPL",
    "SCOPE",
    "TABLE",
    "Path",
    "data_table",
    "shipped",
    "changes",
    "hunks",
    "judge",
    "no_waiver",
    "patch",
    "scope",
    "shapes",
    "verdict",
]
