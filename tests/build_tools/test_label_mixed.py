"""A blocking unit's ask cases are worded per client, and a fail-open hook says how that was established."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from agentseam import matrix
from chock.plugin import bundle_grade
from label_honesty import (
    CANNOT,
    CANNOT_EITHER,
    CANNOT_SHELL,
    FAIL_OPEN_BASIS,
    FAIL_OPEN_SAYS,
    GUARD_MIXED_SPLIT,
    GUARD_SAYS,
    MIXED_SAYS,
    Asks,
    asks_in_evals,
    fail_open_basis,
    fail_open_qualifier,
    honest_mixed,
)
from trees import ROOT

BLOCK_GATE = json.dumps({"action": "block"})
ASK_GATE = json.dumps({"action": "ask"})
GATE_SAYS = "blocks on an agent's file writes and at turn end"
STOP_SAYS = "blocks at turn end only; the write itself is not judged"


def _hooks(*events: str, guard: bool = False, gate: bool = True) -> str:
    hooks = ([{"command": "x --guard g.py"}] if guard else []) + ([{"command": "x --gate"}] if gate else [])
    return json.dumps({"hooks": {e: [{"hooks": hooks}] for e in events}})


def test_the_guard_text_is_the_engines() -> None:
    assert bundle_grade.grade_of(_hooks("PreToolUse", guard=True, gate=False), None, "claude_code")[1] == GUARD_SAYS


def test_fail_open_basis_is_the_matrix_claims_own() -> None:
    assert fail_open_basis("claude_code") == matrix.BASIS_LIVE
    assert fail_open_basis("devin") == "vendor-docs"
    assert fail_open_basis("codex_cli") == fail_open_basis("vscode_copilot") == matrix.BASIS_LIVE_PARTIAL
    assert matrix.capability("cursor", "pre_tool")["fail_mode"] == matrix.FAIL_CONFIGURABLE
    assert fail_open_basis("cursor") is None


def test_every_fail_open_client_is_qualified_and_the_basis_says_how() -> None:
    assert fail_open_qualifier("claude_code") == FAIL_OPEN_SAYS + " (measured)"
    assert fail_open_qualifier("devin") == FAIL_OPEN_SAYS + " (vendor docs only, not witnessed)"
    assert fail_open_qualifier("codex_cli") == FAIL_OPEN_SAYS + FAIL_OPEN_BASIS[matrix.BASIS_LIVE_PARTIAL]
    assert "not witnessed" in fail_open_qualifier("codex_cli")
    assert fail_open_qualifier("cursor") == ""
    assert all(" (measured)" not in says for basis, says in FAIL_OPEN_BASIS.items() if basis != matrix.BASIS_LIVE)


def test_a_basis_without_wording_stops_the_generator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(FAIL_OPEN_BASIS, "vendor-docs")
    with pytest.raises(SystemExit, match="FAIL_OPEN_BASIS"):
        fail_open_qualifier("devin")


def test_asks_in_evals_reads_which_unit_the_case_drives() -> None:
    assert asks_in_evals(ROOT / "base/guard-deletion", BLOCK_GATE) == Asks(gate=True, guard=False)
    assert asks_in_evals(ROOT / "base/block-destructive-commands", None) == Asks(gate=False, guard=True)
    assert asks_in_evals(ROOT / "base/protect-agent-config", BLOCK_GATE) == Asks(gate=True, guard=True)
    assert asks_in_evals(ROOT / "base/java-security", BLOCK_GATE) == Asks(gate=False, guard=False)


def test_an_asking_gate_is_not_counted_twice(tmp_path: Path) -> None:
    assert asks_in_evals(ROOT / "base/scan-suppression-markers", ASK_GATE) == Asks(gate=False, guard=False)
    assert asks_in_evals(ROOT / "base/scan-suppression-markers", BLOCK_GATE).gate
    assert asks_in_evals(tmp_path, BLOCK_GATE) == Asks(gate=False, guard=False)


@pytest.mark.parametrize(
    ("agent", "tail"),
    [
        ("claude_code", f"{MIXED_SAYS} asks at the write and refuses at turn end, {CANNOT}"),
        ("codex_cli", f"{MIXED_SAYS} refuses at both points, {CANNOT_EITHER}"),
    ],
)
def test_a_blocking_gates_ask_cases_follow_what_the_client_honours(agent: str, tail: str) -> None:
    hooks = _hooks("PreToolUse", "Stop")
    says = f"{GATE_SAYS}. {tail[:1].upper()}{tail[1:]}"
    assert honest_mixed(bundle_grade.BLOCKS, GATE_SAYS, hooks, agent, Asks(True, False)) == (bundle_grade.BLOCKS, says)


def test_a_turn_end_only_gate_says_what_happens_there() -> None:
    hooks = _hooks("Stop")
    grade, says = honest_mixed(bundle_grade.STOP_ONLY, STOP_SAYS, hooks, "devin", Asks(True, False))
    assert (grade, says) == (
        bundle_grade.STOP_ONLY,
        f"{STOP_SAYS}. Where its description says it asks, it refuses at turn end, {CANNOT}",
    )
    assert "refuses" in says


def test_a_guards_ask_cases_follow_chock_can_ask() -> None:
    hooks = _hooks("PreToolUse", guard=True, gate=False)
    asks = Asks(False, True)
    assert honest_mixed(bundle_grade.BLOCKS, GUARD_SAYS, hooks, "claude_code", asks)[1] == (
        f"{GUARD_SAYS}. Where its description says it asks, it asks"
    )
    assert honest_mixed(bundle_grade.BLOCKS, GUARD_SAYS, hooks, "devin", asks)[1] == (
        f"{GUARD_SAYS}. Where its description says it asks, it refuses, {CANNOT_SHELL}"
    )
    assert honest_mixed(bundle_grade.BLOCKS, GUARD_SAYS, hooks, "vscode_copilot", asks)[1] == (
        f"{GUARD_SAYS}. {GUARD_MIXED_SPLIT['vscode_copilot'][:1].upper()}{GUARD_MIXED_SPLIT['vscode_copilot'][1:]}"
    )


def test_a_split_client_without_mixed_wording_stops_the_generator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(GUARD_MIXED_SPLIT, "vscode_copilot")
    with pytest.raises(SystemExit, match="GUARD_MIXED_SPLIT"):
        honest_mixed(
            bundle_grade.BLOCKS,
            GUARD_SAYS,
            _hooks("PreToolUse", guard=True, gate=False),
            "vscode_copilot",
            Asks(False, True),
        )


def test_a_guard_beside_a_gate_words_each_half() -> None:
    hooks = _hooks("PreToolUse", "Stop", guard=True)
    both = f"{GUARD_SAYS}; {GATE_SAYS}"
    grade, says = honest_mixed(bundle_grade.BLOCKS, both, hooks, "codex_cli", Asks(True, True))
    assert grade == bundle_grade.BLOCKS
    assert says == (
        f"{GUARD_SAYS}. Where its description says it asks, it refuses, {CANNOT_SHELL}."
        f" {GATE_SAYS[:1].upper()}{GATE_SAYS[1:]}. Where its description says it asks, it refuses at both points, {CANNOT_EITHER}"
    )
    only_guard = honest_mixed(bundle_grade.BLOCKS, both, hooks, "codex_cli", Asks(False, True))[1]
    assert (
        only_guard
        == f"{GUARD_SAYS}. Where its description says it asks, it refuses, {CANNOT_SHELL}. {GATE_SAYS[:1].upper()}{GATE_SAYS[1:]}"
    )


def test_a_degraded_asking_gate_keeps_honest_asks_words_and_gains_the_guards() -> None:
    degraded = f"{GUARD_SAYS}. Refuses an agent's file writes and refuses at turn end, {CANNOT_EITHER}"
    _, says = honest_mixed(
        bundle_grade.BLOCKS, degraded, _hooks("PreToolUse", "Stop", guard=True), "codex_cli", Asks(False, True)
    )
    assert says == (
        f"{GUARD_SAYS}. Where its description says it asks, it refuses, {CANNOT_SHELL}."
        f" Refuses an agent's file writes and refuses at turn end, {CANNOT_EITHER}"
    )


def test_a_unit_with_no_ask_case_and_a_non_enforcing_grade_are_left_alone() -> None:
    hooks = _hooks("PreToolUse", "Stop", guard=True)
    both = f"{GUARD_SAYS}; {GATE_SAYS}"
    assert honest_mixed(bundle_grade.BLOCKS, both, hooks, "codex_cli", Asks(False, False)) == (
        bundle_grade.BLOCKS,
        both,
    )
    assert honest_mixed(bundle_grade.ADVISORY, "x", hooks, "codex_cli", Asks(True, True)) == (
        bundle_grade.ADVISORY,
        "x",
    )
    assert honest_mixed(bundle_grade.WARNS, "warns", hooks, "codex_cli", Asks(True, True)) == (
        bundle_grade.WARNS,
        "warns",
    )
    # A gate's ask cases need a gate in the package, and a guard's a guard: an ask-only guard's label has neither.
    asks_only = "asks before a matched shell command runs"
    assert (
        honest_mixed(
            bundle_grade.ASKS, asks_only, _hooks("PreToolUse", guard=True, gate=False), "claude_code", Asks(False, True)
        )[1]
        == asks_only
    )
