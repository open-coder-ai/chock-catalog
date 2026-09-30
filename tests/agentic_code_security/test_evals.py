"""The suite's shape. Its executable cases are replayed through chock's engine by tests/policies/test_every_policy.py.

A script gate that prints a findings document is judged by the engine (a second run on the baseline
text), so replaying the gate alone would score old violations as refusals.
"""

from __future__ import annotations

import yaml
from agentic_code_security.conftest import POLICY
from agentic_gate.registry import registry

SUITE = yaml.safe_load((POLICY / "evals" / "suite.yaml").read_text(encoding="utf-8"))["suite"]
CASES = SUITE["cases"]
EXECUTABLE = [c for c in CASES if c.get("execute")]


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
