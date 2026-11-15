"""tools/mechanism.py: what a policy's shipped mechanism can promise."""

from __future__ import annotations

from pathlib import Path

import mechanism
import yaml


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


def _script_gate(tmp_path: Path, on: list[str], action: str = "warn") -> dict:
    impl = tmp_path / "implementations"
    impl.mkdir()
    (impl / "p-gate.py").write_text("", encoding="utf-8")
    return {
        "id": "p",
        "hook": {"gate": {"kind": "script", "on": on, "action": action, "params": {"script": "p-gate.py"}}},
    }


def test_a_warn_script_gate_over_writes_is_not_a_command_guard(tmp_path: Path) -> None:
    manifest = _script_gate(tmp_path, ["commit", "tool_use"])
    assert mechanism.classify(tmp_path, manifest) == (mechanism.NONE, "warn-only gate")
    (tmp_path / "implementations" / "p-guard.sh").write_text("", encoding="utf-8")
    assert mechanism.classify(tmp_path, manifest) == (mechanism.GUARD, "guard script")


def test_a_tool_call_script_gate_keeps_its_script_as_a_guard(tmp_path: Path) -> None:
    assert mechanism.classify(tmp_path, _script_gate(tmp_path, ["tool_call"])) == (mechanism.GUARD, "guard script")


def test_a_blocking_script_gate_at_commit_is_still_enforced_at_commit(tmp_path: Path) -> None:
    assert mechanism.classify(tmp_path, _script_gate(tmp_path, ["commit"], "block")) == (mechanism.GATE, "script")


def _judging(tmp_path: Path, source: str, action: str = "ask") -> dict:
    manifest = {
        "id": "p",
        "hook": {
            "gate": {
                "kind": "script",
                "on": ["commit", "tool_use"],
                "action": action,
                "params": {"script": "p-gate.py"},
            }
        },
    }
    (tmp_path / "implementations").mkdir(exist_ok=True)
    (tmp_path / "implementations" / "p-gate.py").write_text(source, encoding="utf-8")
    return manifest


AGENT_ONLY = 'JUDGED = ("tool_use", "agent-commit")\n'


def test_a_gate_that_judges_only_an_agents_commit_is_not_enforced_at_commit(tmp_path: Path) -> None:
    for action in ("ask", "block"):
        kind, label = mechanism.classify(tmp_path, _judging(tmp_path, AGENT_ONLY, action))
        assert kind == mechanism.GUARD
        assert mechanism.CEILING[kind].startswith("best-effort")
        assert label.endswith("at an agent's write and an agent's commit")


def test_the_label_says_what_the_agent_commit_gate_does(tmp_path: Path) -> None:
    manifest = _judging(tmp_path, AGENT_ONLY)
    assert mechanism.classify(tmp_path, manifest) == (
        mechanism.GUARD,
        "script gate that asks at an agent's write and an agent's commit",
    )
    assert mechanism.classify(tmp_path, _judging(tmp_path, AGENT_ONLY, "block"))[1].startswith(
        "script gate that refuses"
    )


def test_a_shell_guard_beside_an_agent_commit_gate_names_both_parts(tmp_path: Path) -> None:
    manifest = _judging(tmp_path, AGENT_ONLY)
    (tmp_path / "implementations" / "p.py").write_text("", encoding="utf-8")
    assert mechanism.classify(tmp_path, manifest) == (
        mechanism.GUARD,
        "shell guard that refuses + script gate that asks at an agent's write and an agent's commit",
    )


def test_a_gate_that_judges_a_persons_commit_stays_enforced_at_commit(tmp_path: Path) -> None:
    for source in ('JUDGED = ("commit", "tool_use")\n', 'JUDGED = ("tool_use", "commit", "agent-commit")\n', ""):
        assert mechanism.classify(tmp_path, _judging(tmp_path, source)) == (mechanism.GATE, "script")


def test_a_judged_list_that_is_not_a_tuple_of_strings_is_not_trusted(tmp_path: Path) -> None:
    for source in (
        'JUDGED = ["tool_use", "agent-commit"]\n',
        "JUDGED = (EVENT, 'agent-commit')\n",
        "JUDGED: tuple = ()\n",
        "def (\n",
    ):
        assert mechanism.classify(tmp_path, _judging(tmp_path, source))[0] == mechanism.GATE


def test_a_gate_script_that_is_missing_is_not_trusted(tmp_path: Path) -> None:
    manifest = _judging(tmp_path, AGENT_ONLY)
    (tmp_path / "implementations" / "p-gate.py").unlink()
    assert mechanism.classify(tmp_path, manifest)[0] == mechanism.GATE


def test_the_shipped_protect_ci_workflows_is_in_the_agent_not_at_commit() -> None:
    root = Path(__file__).resolve().parents[2] / "base" / "protect-ci-workflows"
    manifest = yaml.safe_load((root / "manifest.yaml").read_text(encoding="utf-8"))
    kind, label = mechanism.classify(root, manifest)
    assert kind == mechanism.GUARD
    assert mechanism.CEILING[kind].startswith("best-effort")
    assert "shell guard that refuses" in label
    assert "asks at an agent's write and an agent's commit" in label
