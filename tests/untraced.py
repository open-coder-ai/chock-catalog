"""Run code in a child process outside the coverage tracer, which slows a python loop several times over."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMPORT_PATHS = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pytest"]["ini_options"][
    "pythonpath"
]


def clean_env() -> dict[str, str]:
    """This process's environment without the variables that make a child process measured for coverage."""
    return {k: v for k, v in os.environ.items() if not k.startswith(("COV", "COVERAGE"))}


def run(code: str, *args: str, timeout: int = 300) -> list[float]:
    """The JSON list `code` prints, from a child that imports as the tests do and has no coverage variables."""
    env = clean_env()
    env["PYTHONPATH"] = os.pathsep.join(str(ROOT / d) for d in IMPORT_PATHS)
    done = subprocess.run(
        [sys.executable, "-c", code, *args], env=env, capture_output=True, text=True, check=False, timeout=timeout
    )
    assert done.returncode == 0, done.stderr[-800:]
    return json.loads(done.stdout)
