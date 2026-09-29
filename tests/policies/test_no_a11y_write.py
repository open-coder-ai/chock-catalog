"""no-a11y-regression: the write-time script gate, driven with the payload the runner sends it."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from policies import scriptkit

NAME = "no-a11y-regression-write.py"
mod = scriptkit.load("no-a11y-regression", NAME)

NAMED = '<img src="/hero.png" alt="Revenue by quarter">\n'
EMPTIED = '<img src="/hero.png" alt="">\n'
RENAMED = '<img src="/hero.png" alt="Quarterly revenue">\n'


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"page.html": NAMED, "notes.txt": "x\n"})


def payload(repo: Path, writes: dict[str, str]) -> dict:
    return {"event": "tool_use", "repo_root": str(repo), "writes": writes}


def test_emptying_an_alt_the_file_already_carried_is_refused(repo: Path) -> None:
    lines = mod.judge(payload(repo, {"page.html": EMPTIED}))
    assert any("page.html" in ln and "satisfied -> suppressed" in ln for ln in lines)


def test_rewording_a_name_is_silent(repo: Path) -> None:
    assert mod.judge(payload(repo, {"page.html": RENAMED})) == []


def test_a_file_that_is_not_markup_is_not_judged(repo: Path) -> None:
    assert mod.judge(payload(repo, {"notes.txt": EMPTIED})) == []


def test_the_baseline_is_the_file_on_disk_before_the_write(repo: Path) -> None:
    scriptkit.write(repo, {"page.html": EMPTIED})  # an earlier, uncommitted edit already emptied it
    assert mod.judge(payload(repo, {"page.html": EMPTIED + "<p>more</p>\n"})) == []


def test_at_the_turns_end_disk_holds_the_write_so_head_is_the_baseline(repo: Path) -> None:
    scriptkit.write(repo, {"page.html": EMPTIED})
    assert mod.judge(payload(repo, {"page.html": EMPTIED}))
    scriptkit.write(repo, {"page.html": RENAMED})
    assert mod.judge(payload(repo, {"page.html": RENAMED})) == []


def test_a_new_file_is_judged_against_nothing(repo: Path) -> None:
    assert mod.judge(payload(repo, {"new.html": NAMED})) == []
    assert mod.judge(payload(repo, {"new.html": '<img src="/a.png">\n'}))


def test_no_writes_is_silent(repo: Path) -> None:
    assert mod.judge({"repo_root": str(repo)}) == []


def test_a_parse_failure_is_skipped_not_refused(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    guard = mod._guard()

    def boom(_before: str, _after: str) -> list:
        raise ValueError

    monkeypatch.setattr(mod, "_guard", lambda: type("G", (), {"MARKUP_SUFFIXES": (".html",), "evaluate": boom}))
    assert mod.judge(payload(repo, {"page.html": EMPTIED})) == []
    assert "skipped page.html: ValueError" in capsys.readouterr().err
    assert guard.DENY == "deny"


def test_main_refuses_with_reasons_and_allows_the_correct_form(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload(repo, {"page.html": EMPTIED}))))
    assert mod.main() == 1
    err = capsys.readouterr().err
    assert "destroys an accessibility assertion" in err
    assert "Restore what the element carried" in err
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload(repo, {"page.html": RENAMED}))))
    assert mod.main() == 0
    assert capsys.readouterr().err == ""


def test_the_script_runs_as_a_process_and_speaks_through_its_exit_code(repo: Path) -> None:
    code, err = scriptkit.run_script(
        "no-a11y-regression", NAME, repo, stdin=json.dumps(payload(repo, {"page.html": EMPTIED}))
    )
    assert code == 1
    assert "page.html" in err
    code, _ = scriptkit.run_script(
        "no-a11y-regression", NAME, repo, stdin=json.dumps(payload(repo, {"page.html": RENAMED}))
    )
    assert code == 0
