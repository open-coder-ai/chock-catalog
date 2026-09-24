"""Every eval case with an executable form, replayed through the shipped gate.

`chock check --only evals` does not replay a script gate on this engine, so without this the
suite's executable cases would be prose nothing runs. A case's `.chock/security.json`, staged or
already in the repository, is written as the selection; every other staged file is a write.
"""

from __future__ import annotations

import pytest
import yaml
from java_security.conftest import POLICY, GateRun

SUITE = yaml.safe_load((POLICY / "evals" / "suite.yaml").read_text(encoding="utf-8"))["suite"]
EXECUTABLE = [case for case in SUITE["cases"] if case.get("execute")]
EXPECTED_EXIT = {"block": 1, "allow": 0}


@pytest.mark.parametrize("case", EXECUTABLE, ids=[c["id"] for c in EXECUTABLE])
def test_eval_case_through_the_gate(case: dict, gate: GateRun) -> None:
    execute = case["execute"]
    files = dict(execute.get("files") or {})
    present = dict(execute.get("repo_files") or {})
    selection = files.pop(".chock/security.json", None) or present.get(".chock/security.json")
    code, err = gate(files, selection)
    assert code == EXPECTED_EXIT[execute["expect"]], err


def test_the_suite_ids_are_unique_and_most_cases_execute() -> None:
    ids = [c["id"] for c in SUITE["cases"]]
    assert len(ids) == len(set(ids))
    assert len(EXECUTABLE) >= len(ids) * 0.9
