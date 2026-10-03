"""protect-agent-config: literal scripts, git restore and clean, glob compilation (fourth review round)."""

from __future__ import annotations

import time
import warnings
from pathlib import Path

import pytest
from policies import guard_cases_scripts as cases
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
match = guardkit.load_guard(POLICY, "pathmatch")


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in (".git", ".claude", ".cursor", ".chock", "src"):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


@pytest.mark.parametrize("raw", cases.SCRIPT_REFUSED)
def test_a_script_the_line_shows_or_hides_is_judged(raw: str) -> None:
    assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize("raw", cases.SCRIPT_ALLOWED)
def test_an_ordinary_script_the_line_runs_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None, raw


def test_a_run_of_stars_is_one_wildcard_and_does_not_backtrack() -> None:
    start = time.monotonic()
    assert guard.check("echo y > " + "*" * 30 + "x") is None
    assert guard.check("echo y > " + "*?" * 30 + "x") is None
    assert guard.check("echo y > " + "a*" * 30 + "x") in (None, guard.REASON)  # past a few stars it is any text
    assert time.monotonic() - start < 1


def test_a_glob_that_reaches_a_protected_name_is_still_refused_after_stars_are_squeezed() -> None:
    assert guard.check("echo y > .m**p.json") == guard.REASON
    assert guard.check("echo y > .mc?*.json") == guard.REASON
    assert guard.check("echo y > .***") == guard.REASON


@pytest.mark.parametrize("glob", ["[a-z&&b]", "[a||b]", "[a~~b]", "[a--b]", "[[a]", "[a-]", "[!&&]"])
def test_a_bracket_expression_compiles_without_a_warning(glob: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        match.pattern.cache_clear()
        assert match.pattern(glob, loose=False).pattern
