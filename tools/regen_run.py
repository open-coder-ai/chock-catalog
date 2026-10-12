"""How tools/regen_all.py runs a step: no shell where Windows needs one, output any console can print."""

from __future__ import annotations

import filecmp
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

from trees import ROOT

PY = sys.executable
#: An argv (no shell, so cmd.exe and bash agree), a function returning (rc, output), or a bash script
#: for the steps that only run on POSIX (the staged adopter).
Cmd = list[str] | Callable[[], tuple[int, str]] | str
#: Children print UTF-8 whatever the console's code page; `run` decodes it as UTF-8.
CHILD_ENV = os.environ | {"PYTHONIOENCODING": "utf-8"}
FIGURES = ROOT / "docs" / "figures"


class Result(NamedTuple):
    label: str
    rc: int
    secs: float
    out: str


def _capture(cmd: list[str] | str, cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=isinstance(cmd, str),
        env=CHILD_ENV,
        check=False,
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def run(label: str, cmd: Cmd, cwd: Path = ROOT) -> Result:
    start = time.monotonic()
    rc, out = cmd() if callable(cmd) else _capture(cmd, cwd)
    return Result(label, rc, time.monotonic() - start, out)


def say(text: str) -> None:
    """Print what the console's encoding can show (cp1252 has no U+FFFD); never raise on it."""
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    print(text.encode(encoding, errors="replace").decode(encoding, errors="replace"))


def report(result: Result) -> int:
    say(f"  {'ok  ' if result.rc == 0 else 'FAIL'} {result.secs:6.1f}s  {result.label}")
    if result.rc:
        say("\n".join("        " + line for line in result.out.splitlines()[-25:]))
    return result.rc


def render_figures(figures: Path = FIGURES) -> tuple[int, str]:
    """Run each make_*.py in `figures` (make_social writes to the working directory); stop at a failure."""
    outs = []
    for script in sorted(figures.glob("make_*.py")):
        rc, out = _capture([PY, script.name], figures)
        outs.append(out)
        if rc:
            return rc, "\n".join(outs)
    return 0, "\n".join(outs)


def differing(left: Path, right: Path) -> list[str]:
    """Files that differ, or exist on one side only, between two trees (__pycache__ ignored)."""
    cmp = filecmp.dircmp(left, right, ignore=["__pycache__"])
    found = [f"{left / name}" for name in cmp.diff_files + cmp.left_only + cmp.right_only + cmp.funny_files]
    return found + [f for sub in cmp.common_dirs for f in differing(left / sub, right / sub)]


def figures_check(scratch: Path, root: Path = ROOT) -> Callable[[], tuple[int, str]]:
    """Re-render the figures in a copy and compare: --check-only writes nothing in the tree."""

    def check() -> tuple[int, str]:
        copy = scratch / "figures" / "docs" / "figures"
        shutil.copytree(root / "docs" / "figures", copy, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy2(root / "registry.yaml", scratch / "figures" / "registry.yaml")
        rc, out = render_figures(copy)
        if rc:
            return rc, out
        stale = differing(root / "docs" / "figures", copy)
        return int(bool(stale)), "\n".join(f"stale: {path}" for path in stale)

    return check
