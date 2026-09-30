"""Helpers for tool_call script gates: a repo holding the vendored session reader, a log, and a fired gate."""

from __future__ import annotations

import io
import json
import shutil
from pathlib import Path

import pytest
from chock.gate import session_reader

SESSION = "s1"


def make_repo(tmp_path: Path, vendored: bool = True) -> Path:
    """A repo root; with `vendored`, its .chock/bin holds the reader the way `chock sync` installs it."""
    repo = tmp_path / "repo"
    (repo / ".chock" / "bin").mkdir(parents=True)
    if vendored:
        shutil.copy(session_reader.__file__, repo / ".chock" / "bin" / "chock_session.py")
    return repo


def record(tool: str, phase: str, outcome: str | None = None, call: str = "t", **fields: str) -> dict:
    return {"tool": tool, "phase": phase, "outcome": outcome, "tool_use_id": call, "input": fields}


def write_log(repo: Path, records: list[dict]) -> None:
    state = repo / ".chock" / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / f"{SESSION}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def payload(repo: Path, tool: str, tool_input: dict) -> dict:
    log_path = repo / ".chock" / "state" / f"{SESSION}.jsonl"
    return {
        "event": "tool_call",
        "repo_root": str(repo),
        "tool": tool,
        "input": tool_input,
        "session": {"id": SESSION, "log_path": log_path.as_posix(), "tool_use_id": "now"},
    }


def fire(mod, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], data: dict) -> tuple[int, str]:
    """Run the gate's main() on `data`; (exit code, stderr)."""
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(data)))
    code = mod.main()
    return code, capsys.readouterr().err
