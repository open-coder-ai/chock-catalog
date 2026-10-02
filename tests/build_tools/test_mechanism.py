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


def _with_event_script(tmp_path: Path) -> None:
    impl = tmp_path / "implementations"
    impl.mkdir()
    (impl / "p-pre-commit.py").write_text("", encoding="utf-8")


def test_an_event_script_beside_a_tool_use_gate_names_both(tmp_path: Path) -> None:
    _with_event_script(tmp_path)
    assert mechanism.classify(tmp_path, gate("block", ["tool_use"])) == (
        mechanism.EVENT_SCRIPT,
        "commit-time guard script + tool-use content_regex gate",
    )


def test_an_event_script_alone_or_beside_a_warn_gate_names_only_the_commit(tmp_path: Path) -> None:
    _with_event_script(tmp_path)
    assert mechanism.classify(tmp_path, {"id": "p"})[1] == "commit-time guard script"
    assert mechanism.classify(tmp_path, gate("warn", ["tool_use"]))[1] == "commit-time guard script"
    assert mechanism.classify(tmp_path, gate("block", ["commit"]))[1] == "content_regex"


def test_a_warn_only_script_gate_is_not_a_command_guard(tmp_path: Path) -> None:
    impl = tmp_path / "implementations"
    impl.mkdir()
    (impl / "p-gate.py").write_text("", encoding="utf-8")
    manifest = {
        "id": "p",
        "hook": {"gate": {"kind": "script", "on": ["commit"], "action": "warn", "params": {"script": "p-gate.py"}}},
    }
    assert mechanism.classify(tmp_path, manifest) == (mechanism.NONE, "warn-only gate")
    (impl / "p-guard.py").write_text("", encoding="utf-8")
    assert mechanism.classify(tmp_path, manifest) == (mechanism.GUARD, "guard script")


def test_a_tool_call_script_gate_keeps_its_label(tmp_path: Path) -> None:
    impl = tmp_path / "implementations"
    impl.mkdir()
    (impl / "p-gate.py").write_text("", encoding="utf-8")
    manifest = {
        "id": "p",
        "hook": {"gate": {"kind": "script", "on": ["tool_call"], "action": "warn", "params": {"script": "p-gate.py"}}},
    }
    assert mechanism.classify(tmp_path, manifest) == (mechanism.GUARD, "guard script")
