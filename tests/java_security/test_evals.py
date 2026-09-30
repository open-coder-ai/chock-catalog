"""Every eval case with an executable form, replayed through the shipped gate.

`chock check --only evals` does not replay a script gate on this engine, so without this the
suite's executable cases would be prose nothing runs. A case's `.chock/security.json`, staged or
already in the repository, is written as the selection; every other staged file is a write.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml
from java_security.conftest import POLICY, GateRun

SUITE = yaml.safe_load((POLICY / "evals" / "suite.yaml").read_text(encoding="utf-8"))["suite"]
EXECUTABLE = [case for case in SUITE["cases"] if case.get("execute")]
EXPECTED_EXIT = {"block": 1, "allow": 0}
GATE_EVENT = {"commit": "commit", "tool_use": "pre-tool-use", "stop": "stop"}


def seed_head(repo: Path, files: dict[str, str]) -> None:
    """Make `files` the repository's HEAD: what a human already reviewed."""
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com"]
    subprocess.run([*git, "init", "-q"], cwd=repo, check=True, capture_output=True)
    for name, body in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(body, encoding="utf-8")
    subprocess.run([*git, "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run([*git, "commit", "-q", "-m", "seed"], cwd=repo, check=True, capture_output=True)


@pytest.mark.parametrize("case", EXECUTABLE, ids=[c["id"] for c in EXECUTABLE])
def test_eval_case_through_the_gate(case: dict, gate: GateRun, tmp_path: Path) -> None:
    execute = case["execute"]
    if execute.get("head_files"):
        seed_head(tmp_path, execute["head_files"])
    files = dict(execute.get("files") or execute.get("writes") or {})
    present = dict(execute.get("repo_files") or {})
    selection = files.pop(".chock/security.json", None) or present.get(".chock/security.json")
    code, err = gate(files, selection, GATE_EVENT[execute.get("event", "commit")])
    assert code == EXPECTED_EXIT[execute["expect"]], err


def test_the_suite_ids_are_unique_and_most_cases_execute() -> None:
    ids = [c["id"] for c in SUITE["cases"]]
    assert len(ids) == len(set(ids))
    assert len(EXECUTABLE) >= len(ids) * 0.9
