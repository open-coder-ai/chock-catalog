"""The suite's shape. Its executable cases are replayed through chock's engine by tests/policies/test_every_policy.py.

A script gate that prints a findings document is judged by the engine (a second run on the baseline
text), so replaying the gate alone would score old violations as refusals.
"""

from __future__ import annotations

import yaml
from java_security.conftest import POLICY

SUITE = yaml.safe_load((POLICY / "evals" / "suite.yaml").read_text(encoding="utf-8"))["suite"]
EXECUTABLE = [case for case in SUITE["cases"] if case.get("execute")]


def test_the_suite_ids_are_unique_and_most_cases_execute() -> None:
    ids = [c["id"] for c in SUITE["cases"]]
    assert len(ids) == len(set(ids))
    assert len(EXECUTABLE) >= len(ids) * 0.9
