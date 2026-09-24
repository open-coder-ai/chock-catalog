"""Shared paths and the gate driver the java-security tests run the shipped guard through."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from chock_security.decision import DENY
from chock_security.rules import registry

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "base" / "java-security"
GATE = POLICY / "implementations" / "java-security-gate.py"
SETUP = POLICY / "skill"
CORPUS = Path(__file__).resolve().parent / "corpus"

#: Every rule enforcing: the selection a repository has before anyone speaks for a rule.
ALL_DENY = dict.fromkeys(registry(), DENY)

GateRun = Callable[..., tuple[int, str]]


def run_gate(repo: Path, writes: dict[str, str], selection: dict | str | None = None) -> tuple[int, str]:
    """Run the gate as the runner does: the writes on stdin, the repository root beside them."""
    if selection is not None:
        (repo / ".chock").mkdir(exist_ok=True)
        body = selection if isinstance(selection, str) else json.dumps(selection)
        (repo / ".chock" / "security.json").write_text(body, encoding="utf-8")
    payload = json.dumps({"event": "commit", "repo_root": str(repo), "writes": writes})
    proc = subprocess.run(
        [sys.executable, str(GATE)],
        cwd=repo,
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        start_new_session=True,  # no controlling terminal, so an ask has nobody to ask
    )
    return proc.returncode, proc.stderr


@pytest.fixture
def gate(tmp_path: Path) -> GateRun:
    """The shipped gate, run in a throwaway repository of its own."""

    def _run(writes: dict[str, str], selection: dict | str | None = None) -> tuple[int, str]:
        return run_gate(tmp_path, writes, selection)

    return _run
