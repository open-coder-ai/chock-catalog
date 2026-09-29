"""Shared paths and the gate driver the agentic-code-security tests run the shipped script through."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from agentic_gate.registry import registry

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "agentic-security" / "agentic-code-security"
GATE = POLICY / "implementations" / "agentic-code-security-gate.py"
SELECTION = ".chock/agentic-security.json"

#: Every rule enforcing, the noisy heuristics included: the verdicts a case is judged under.
ALL_DENY = dict.fromkeys(registry(), "deny")

GateRun = Callable[..., tuple[int, str]]


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],  # noqa: S607 -- git from PATH, as the runner's own
        cwd=repo,
        check=True,
        capture_output=True,
    )


def commit(repo: Path, files: dict[str, str]) -> None:
    """Make `files` the repository's HEAD: what a human already reviewed."""
    if not (repo / ".git").exists():
        git(repo, "init", "-q")
    for name, body in files.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        git(repo, "add", "--", name)
    git(repo, "commit", "-q", "-m", "seed")


def run_gate(
    repo: Path, writes: dict[str, str], selection: dict | str | None = None, event: str = "commit"
) -> tuple[int, str]:
    """Run the gate as the runner does: the writes on stdin, the repository root beside them."""
    if selection is not None:
        (repo / ".chock").mkdir(exist_ok=True)
        (repo / SELECTION).write_text(
            selection if isinstance(selection, str) else json.dumps(selection), encoding="utf-8"
        )
    payload = json.dumps({"event": event, "repo_root": str(repo), "writes": writes})
    proc = subprocess.run(
        [sys.executable, str(GATE)],
        cwd=repo,
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return proc.returncode, proc.stderr


@pytest.fixture
def gate(tmp_path: Path) -> GateRun:
    """The shipped gate, run in a throwaway repository of its own."""

    def _run(writes: dict[str, str], selection: dict | str | None = None, event: str = "commit") -> tuple[int, str]:
        return run_gate(tmp_path, writes, selection, event)

    return _run
