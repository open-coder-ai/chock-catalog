"""A person's waiver and a path exemption at commit: who may add one, what it covers, and a schema that breaks."""

from __future__ import annotations

from pathlib import Path

import pytest
from a11y.waiverkit import (
    ASK,
    DECORATIVE,
    FIXTURE,
    SIDECAR,
    WARN,
    commit,
    refs,
    scriptkit,
    sidecar,
    staged_repo,
    waiver_for,
)


@pytest.mark.parametrize("pair_id", DECORATIVE)
def test_without_a_waiver_the_verdict_is_today_s(tmp_path: Path, pair_id: str) -> None:
    code, err = commit(staged_repo(tmp_path, pair_id))
    assert code == ASK
    assert "BLOCKED" in err


@pytest.mark.parametrize("pair_id", DECORATIVE)
def test_a_waiver_in_head_lets_the_change_through_and_logs_it(tmp_path: Path, pair_id: str) -> None:
    code, err = commit(staged_repo(tmp_path, pair_id, head_sidecar=waiver_for(pair_id)))
    assert code == WARN
    assert "BLOCKED" not in err
    assert "waived" in err
    assert "reviewed: decorative" in err


@pytest.mark.parametrize("pair_id", DECORATIVE)
def test_a_waiver_a_person_adds_in_the_same_commit_counts(tmp_path: Path, pair_id: str) -> None:
    code, err = commit(staged_repo(tmp_path, pair_id, staged_sidecar=waiver_for(pair_id)))
    assert code == WARN
    assert "waived" in err


@pytest.mark.parametrize("pair_id", DECORATIVE)
def test_a_waiver_an_agent_adds_in_the_same_commit_counts_for_nothing(tmp_path: Path, pair_id: str) -> None:
    code, err = commit(staged_repo(tmp_path, pair_id, staged_sidecar=waiver_for(pair_id)), agent=True)
    assert code == ASK
    assert "adds a waiver" in err
    assert "BLOCKED" in err


def test_an_agent_commit_honours_a_waiver_already_in_head(tmp_path: Path) -> None:
    code, err = commit(staged_repo(tmp_path, "N04", head_sidecar=waiver_for("N04")), agent=True)
    assert code == WARN
    assert "waived" in err


def test_a_waiver_for_another_element_or_file_waives_nothing(tmp_path: Path) -> None:
    other = sidecar([{"file": "other.html", "element": refs("N04")[0][1], "reason": "r"}])
    assert commit(staged_repo(tmp_path, "N04", head_sidecar=other))[0] == ASK
    other = sidecar([{"file": refs("N04")[0][0], "element": "img[src=/other.png]", "reason": "r"}])
    assert commit(staged_repo(tmp_path / "b", "N04", head_sidecar=other))[0] == ASK


def test_a_path_exemption_waives_a_fixture_tree(tmp_path: Path) -> None:
    exempt = sidecar(exempt=[{"path": "tests/fixtures/*", "reason": "deliberately inaccessible fixtures"}])
    code, err = commit(staged_repo(tmp_path, FIXTURE))
    assert (code, "warning:" in err, "waived" in err) == (WARN, True, False)
    code, err = commit(staged_repo(tmp_path / "b", FIXTURE, head_sidecar=exempt))
    assert (code, "warning:" in err, "waived" in err) == (WARN, False, True)
    assert "deliberately inaccessible fixtures" in err


def test_a_path_exemption_covers_a_block_too(tmp_path: Path) -> None:
    exempt = sidecar(exempt=[{"path": "*.html", "reason": "generated"}])
    code, err = commit(staged_repo(tmp_path, "N04", head_sidecar=exempt))
    assert code == WARN
    assert "generated" in err


BROKEN = {
    "an unknown top-level key": '{"waive": [], "skip": []}',
    "a waiver with an extra key": '{"waive": [{"file": "a.html", "element": "img:1", "reason": "r", "x": "y"}]}',
    "a waiver without a reason": '{"waive": [{"file": "a.html", "element": "img:1"}]}',
    "an empty reason": '{"waive": [{"file": "a.html", "element": "img:1", "reason": " "}]}',
    "a value that is not text": '{"waive": [{"file": "a.html", "element": 1, "reason": "r"}]}',
    "waive not a list": '{"waive": {}}',
    "exempt not a list": '{"exempt": "tests"}',
    "an exemption that covers every file": '{"exempt": [{"path": "**", "reason": "r"}]}',
    "an exemption with an extra key": '{"exempt": [{"path": "t/*", "reason": "r", "x": "y"}]}',
    "a repeated key": '{"waive": [], "waive": []}',
    "text that is not JSON": "waive everything",
    "a document that is not an object": "[]",
}


@pytest.mark.parametrize("text", BROKEN.values(), ids=BROKEN.keys())
def test_a_sidecar_that_breaks_the_schema_honours_nothing_and_says_so(tmp_path: Path, text: str) -> None:
    good = waiver_for("N04").rstrip().removesuffix("}") + ',\n  "skip": []}\n'  # a real waiver beside a broken key
    repo = staged_repo(tmp_path, "N04", head_sidecar=text)
    code, err = commit(repo)
    assert code == ASK
    assert "breaks its closed schema" in err
    assert SIDECAR in err
    repo = staged_repo(tmp_path / "b", "N04", head_sidecar=good)
    code, err = commit(repo)
    assert code == ASK
    assert "breaks its closed schema" in err


def test_a_broken_staged_sidecar_leaves_the_waivers_in_head(tmp_path: Path) -> None:
    repo = staged_repo(tmp_path, "N04", head_sidecar=waiver_for("N04"), staged_sidecar="{")
    code, err = commit(repo)
    assert code == WARN
    assert "breaks its closed schema" in err


def test_a_correct_change_is_silent_and_exits_zero(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "r", {"a.html": '<img src="/a.png" alt="Chart">\n'})
    scriptkit.write(repo, {"a.html": '<img src="/a.png" alt="Revenue chart">\n'})
    scriptkit.git(repo, "add", "-A")
    assert commit(repo) == (0, "")


def test_a_warning_alone_exits_with_the_warn_code(tmp_path: Path) -> None:
    code, err = commit(staged_repo(tmp_path, FIXTURE))
    assert (code, "warning:" in err) == (WARN, True)
