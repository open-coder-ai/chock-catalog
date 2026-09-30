"""tools/mechanism.py: what a policy's shipped mechanism can promise."""

from __future__ import annotations

from pathlib import Path

import mechanism


def gate(action: str | None, on: list[str]) -> dict:
    spec: dict = {"kind": "content_regex", "on": on}
    if action:
        spec["action"] = action
    return {"id": "p", "hook": {"gate": spec}}


def test_a_blocking_or_asking_gate_at_commit_is_enforced_at_commit(tmp_path: Path) -> None:
    for action in (None, "block", "ask"):
        assert mechanism.classify(tmp_path, gate(action, ["commit", "tool_use"])) == (mechanism.GATE, "content_regex")


def test_a_warn_gate_alone_promises_nothing(tmp_path: Path) -> None:
    assert mechanism.classify(tmp_path, gate("warn", ["commit", "tool_use"])) == (mechanism.NONE, "warn-only gate")
    assert mechanism.classify(tmp_path, gate("warn", ["tool_use"])) == (mechanism.NONE, "warn-only gate")


def test_a_warn_gate_beside_an_event_script_keeps_the_scripts_ceiling(tmp_path: Path) -> None:
    impl = tmp_path / "implementations"
    impl.mkdir()
    (impl / "p-pre-commit.py").write_text("", encoding="utf-8")
    assert mechanism.classify(tmp_path, gate("warn", ["tool_use"]))[0] == mechanism.EVENT_SCRIPT


def test_a_tool_use_gate_is_enforced_in_the_agent(tmp_path: Path) -> None:
    assert mechanism.classify(tmp_path, gate("block", ["tool_use"])) == (mechanism.GUARD, "content_regex")


def test_no_gate_and_no_script_is_rule_text(tmp_path: Path) -> None:
    assert mechanism.classify(tmp_path, {"id": "p"}) == (mechanism.NONE, "rule text only")
