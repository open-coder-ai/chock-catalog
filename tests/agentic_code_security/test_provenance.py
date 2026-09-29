"""Provenance markers: removal is refused, a move to another written file is not."""

from __future__ import annotations

from pathlib import Path

import pytest
from agentic_code_security.conftest import commit, run_gate
from agentic_gate.rules.provenance import MARKERS, present

RULE = "provenance-marker-removed"
REFUSE, PASS = 1, 0
SIGNER = "from c2pa import Builder\n\nBuilder(m).sign(image)\n"
UNSIGNED = "def sign(image):\n    return image\n"


@pytest.mark.parametrize("marker", MARKERS)
def test_every_marker_counts_whatever_its_case(marker: str) -> None:
    assert present(f"x = '{marker.upper()}'") == {marker}
    assert present(f"x = '{marker.lower()}'") == {marker}


def test_removal_is_refused_at_commit(tmp_path: Path) -> None:
    commit(tmp_path, {"sign.py": SIGNER})
    code, err = run_gate(tmp_path, {"sign.py": UNSIGNED})
    assert code == REFUSE
    assert f"[deny: {RULE}" in err
    assert "c2pa" in err


@pytest.mark.parametrize("event", ["tool_use", "stop"])
def test_removal_is_refused_where_the_agent_writes_and_at_the_turns_end(tmp_path: Path, event: str) -> None:
    commit(tmp_path, {"sign.py": SIGNER})
    assert run_gate(tmp_path, {"sign.py": UNSIGNED}, event=event)[0] == REFUSE


def test_keeping_one_marker_is_not_removal(tmp_path: Path) -> None:
    commit(tmp_path, {"m.json": '{"synthid": 1, "ai_generated": true}\n'})
    assert run_gate(tmp_path, {"m.json": '{"synthid": 1}\n'})[0] == PASS


def test_a_marker_moved_to_another_written_file_is_not_removal(tmp_path: Path) -> None:
    commit(tmp_path, {"old.py": SIGNER, "other.py": "x = 1\n"})
    moved = {"old.py": UNSIGNED, "new.py": SIGNER}
    assert run_gate(tmp_path, moved)[0] == PASS
    assert run_gate(tmp_path, moved, event="tool_use")[0] == PASS


def test_a_different_marker_elsewhere_does_not_account_for_the_removed_one(tmp_path: Path) -> None:
    commit(tmp_path, {"old.py": SIGNER})
    elsewhere = {"old.py": UNSIGNED, "new.py": "x = 'synthid'\n"}
    assert run_gate(tmp_path, elsewhere)[0] == REFUSE


def test_a_marker_in_an_unwritten_file_does_not_count_as_moved(tmp_path: Path) -> None:
    commit(tmp_path, {"old.py": SIGNER, "keeps.py": SIGNER})
    assert run_gate(tmp_path, {"old.py": UNSIGNED})[0] == REFUSE


def test_a_new_file_and_a_file_that_never_had_a_marker_pass(tmp_path: Path) -> None:
    commit(tmp_path, {"plain.py": "x = 1\n"})
    assert run_gate(tmp_path, {"plain.py": UNSIGNED, "new.py": UNSIGNED})[0] == PASS


def test_a_waiver_line_cannot_excuse_a_removal_a_human_did_not_review(tmp_path: Path) -> None:
    commit(tmp_path, {"sign.py": SIGNER})
    waived = f"# chock: allow {RULE}\n{UNSIGNED}"
    assert run_gate(tmp_path, {"sign.py": waived}, event="tool_use")[0] == REFUSE


def test_the_selection_file_is_how_a_person_accepts_a_removal(tmp_path: Path) -> None:
    commit(tmp_path, {"sign.py": SIGNER})
    allow = {"version": 1, "packs": {"provenance": {"verdict": "allow"}}}
    assert run_gate(tmp_path, {"sign.py": UNSIGNED}, allow)[0] == PASS
