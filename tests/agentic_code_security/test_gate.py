"""The gate's protocol and the selection file: its exit code is the verdict the runner carries."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from agentic_code_security.conftest import GATE, GateRun, run_gate
from agentic_gate.registry import registry
from agentic_gate.selection import SelectionError, load, parse

BAD = {"agent/tls.py": "import requests\n\nrequests.get(u, verify=False)\n"}
TLS = "comms-tls-verify-disabled"
HEURISTIC = {"bounds/turns.py": "agent.run(t, max_turns=None)\n"}
REFUSE, PASS = 1, 0


def pick(**packs: dict) -> dict:
    return {"version": 1, "packs": packs}


def test_a_violating_write_with_no_selection_is_refused_and_named(gate: GateRun) -> None:
    code, err = gate(BAD)
    assert code == REFUSE
    assert f"[deny: {TLS} CWE-295, ASI07]" in err
    assert "agent/tls.py:3:" in err
    assert "Fix:" in err


def test_correct_code_and_an_empty_write_pass(gate: GateRun) -> None:
    assert gate({"a.py": "import requests\n\nrequests.get(u)\n"})[0] == PASS
    assert gate({})[0] == PASS


def test_a_noisy_heuristic_is_allowed_until_someone_speaks(gate: GateRun) -> None:
    assert gate(HEURISTIC)[0] == PASS


def test_a_heuristic_can_be_turned_on_by_rule_and_by_pack(gate: GateRun) -> None:
    rule = pick(bounds={"rules": {"bounds-unbounded-turns": "deny"}})
    assert gate(HEURISTIC, rule)[0] == REFUSE
    assert gate(HEURISTIC, pick(bounds={"verdict": "deny"}))[0] == REFUSE


def test_a_pack_set_to_allow_is_honoured(gate: GateRun) -> None:
    assert gate(BAD, pick(comms={"verdict": "allow"}))[0] == PASS


def test_a_rule_set_to_allow_is_honoured(gate: GateRun) -> None:
    assert gate(BAD, pick(comms={"rules": {TLS: "allow"}}))[0] == PASS


def test_allowing_a_rule_leaves_its_pack_neighbours_enforcing(gate: GateRun) -> None:
    both = {"a.py": "import ssl\n\nc = ssl._create_unverified_context()\n"} | BAD
    code, err = gate(both, pick(comms={"rules": {TLS: "allow"}}))
    assert code == REFUSE
    assert "comms-ssl-context-unverified" in err
    assert TLS not in err


def test_a_rule_can_differ_from_its_pack(gate: GateRun) -> None:
    both = {"a.py": "import ssl\n\nc = ssl._create_unverified_context()\n"} | BAD
    code, err = gate(both, pick(comms={"verdict": "allow", "rules": {TLS: "deny"}}))
    assert code == REFUSE
    assert TLS in err
    assert "comms-ssl-context-unverified" not in err


def test_allowing_one_pack_does_not_allow_another(gate: GateRun) -> None:
    assert gate(BAD, pick(exec={"verdict": "allow"}))[0] == REFUSE


def test_an_explicit_deny_of_a_pack_refuses(gate: GateRun) -> None:
    assert gate(BAD, pick(comms={"verdict": "deny"}))[0] == REFUSE


def test_an_empty_selection_changes_nothing(gate: GateRun) -> None:
    assert gate(BAD, pick())[0] == REFUSE
    assert gate(BAD, {"version": 1})[0] == REFUSE


@pytest.mark.parametrize(
    ("selection", "words"),
    [
        ("{not json", "not valid JSON"),
        ("[]", "must be an object"),
        (json.dumps({"version": 2, "packs": {}}), "version must be 1"),
        (json.dumps({"version": 1, "extra": 1}), "unknown key"),
        (json.dumps({"version": 1, "packs": []}), "must be an object"),
        (json.dumps(pick(nosuch={"verdict": "allow"})), "names pack(s)"),
        (json.dumps(pick(comms={"verdict": "ask"})), "a verdict is one of"),
        (json.dumps(pick(comms={"rules": {TLS: {"pattern": "x"}}})), "program in disguise"),
        (json.dumps(pick(comms={"rules": {"no-such-rule": "deny"}})), "does not contain"),
        (json.dumps(pick(comms={"rules": []})), "must be an object"),
        (json.dumps(pick(comms="allow")), "must be an object"),
        (json.dumps(pick(comms={"severity": "low"})), "unknown key"),
    ],
)
def test_a_selection_that_does_not_say_what_it_means_refuses(gate: GateRun, selection: str, words: str) -> None:
    code, err = gate({"ok.py": "x = 1\n"}, selection)
    assert code == REFUSE
    assert words in err
    assert "agentic-code-security:" in err


def test_a_failure_inside_the_engine_refuses_rather_than_allows(gate: GateRun) -> None:
    code, err = gate({"a.py": 5})
    assert code == REFUSE
    assert "could not reach a decision" in err


def test_a_missing_repo_root_falls_back_to_the_working_directory(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(GATE)],
        cwd=tmp_path,
        input=json.dumps({"event": "commit", "writes": BAD}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == REFUSE


def test_every_verdict_in_a_full_selection_round_trips() -> None:
    rules = registry()
    packs = {r.pack for r in rules.values()}
    verdicts = parse(json.dumps(pick(**{p: {"verdict": "allow"} for p in packs})), rules)
    assert set(verdicts.values()) == {"allow"}


def test_load_reads_the_selection_beside_the_repo(tmp_path: Path) -> None:
    rules = registry()
    assert load(tmp_path, rules)[TLS] == "deny"
    (tmp_path / ".chock").mkdir()
    (tmp_path / ".chock" / "agentic-security.json").write_text(json.dumps(pick(comms={"verdict": "allow"})))
    assert load(tmp_path, rules)[TLS] == "allow"


def test_parse_raises_selection_error_with_the_offending_thing() -> None:
    with pytest.raises(SelectionError, match="names pack"):
        parse(json.dumps(pick(bad={})), registry())


def test_the_java_security_selection_file_is_not_this_one(tmp_path: Path) -> None:
    """A repository can carry both selections: this gate never reads or rejects java-security's."""
    java = {"version": 2, "packs": {"java": {"verdict": "allow"}}}
    (tmp_path / ".chock").mkdir()
    (tmp_path / ".chock" / "security.json").write_text(json.dumps(java))
    assert run_gate(tmp_path, BAD)[0] == REFUSE
    assert run_gate(tmp_path, {"ok.py": "x = 1\n"})[0] == PASS


def test_a_push_and_ci_are_reviewed_like_a_commit(tmp_path: Path) -> None:
    waived = {"agent/tls.py": BAD["agent/tls.py"].rstrip() + f"  # chock: allow {TLS}\n"}
    for event in ("push", "ci"):
        assert run_gate(tmp_path, waived, event=event)[0] == PASS
    assert run_gate(tmp_path, waived, event="tool_use")[0] == REFUSE


def test_the_gate_can_be_imported_without_running() -> None:
    spec = importlib.util.spec_from_file_location("agentic_code_security_gate", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert (module.ALLOW, module.REFUSE) == (PASS, REFUSE)
