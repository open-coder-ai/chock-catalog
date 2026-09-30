"""Every eval case, replayed through the shipped gate.

`chock check --only evals` does not replay a script gate on this engine, so without this the suite
would be prose nothing runs. A case's `head_files` are committed first (HEAD), its `repo_files` (the selection file) sit in the
working tree, its `files` (`writes` at the agent events) are the writes, and `event` says who wrote them.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from agentic_code_security.conftest import POLICY, commit, run_gate
from agentic_gate.registry import registry

SUITE = yaml.safe_load((POLICY / "evals" / "suite.yaml").read_text(encoding="utf-8"))["suite"]
CASES = SUITE["cases"]
EXECUTABLE = [c for c in CASES if c.get("execute")]
EXPECTED_EXIT = {"block": 1, "allow": 0}
GATE_EVENT = {"commit": "commit", "tool_use": "pre-tool-use", "stop": "stop"}


@pytest.mark.parametrize("case", EXECUTABLE, ids=[c["id"] for c in EXECUTABLE])
def test_eval_case_through_the_gate(case: dict, tmp_path: Path) -> None:
    execute = case["execute"]
    if execute.get("head_files"):
        commit(tmp_path, execute["head_files"])
    for name, body in (execute.get("repo_files") or {}).items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(body, encoding="utf-8")
    code, err = run_gate(tmp_path, execute.get("files") or execute["writes"], event=GATE_EVENT[execute["event"]])
    assert code == EXPECTED_EXIT[execute["expect"]], err


def test_the_suite_ids_are_unique_and_only_the_agents_own_events_go_unreplayed() -> None:
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids))
    prose = [c for c in CASES if not c.get("execute")]
    assert len(prose) <= len(CASES) * 0.1
    assert all("agent" in c["prompt"] for c in prose)


def test_every_rule_has_an_authored_case_each_way() -> None:
    """A case names its rule in its expectation; a rule needs one it refuses and one it does not."""
    for rule_id in registry():
        refused = [c for c in EXECUTABLE if rule_id in c["expect"] and c["execute"]["expect"] == "block"]
        quiet = [c for c in EXECUTABLE if rule_id in c["expect"] and c["execute"]["expect"] == "allow"]
        assert refused, f"{rule_id} is never refused in the suite"
        assert quiet, f"{rule_id} is never shown silent in the suite"


def test_the_suite_covers_the_events_the_eval_schema_knows() -> None:
    assert {c["execute"]["event"] for c in EXECUTABLE} == {"commit", "tool_use", "stop"}
