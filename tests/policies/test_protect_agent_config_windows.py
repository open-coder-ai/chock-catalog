"""protect-agent-config: robocopy and xcopy into the repository folder, their option values, a trailing backslash."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guard_cases_windows as cases
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in (".git", ".claude", ".cursor", ".chock", "src", "build"):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


@pytest.mark.parametrize("raw", [*cases.WINDOWS_REFUSED, *cases.TRAILING_REFUSED])
def test_a_windows_copy_into_the_repository_folder_or_a_protected_one_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize("raw", cases.WINDOWS_ALLOWED)
def test_a_windows_copy_elsewhere_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None, raw


def test_the_absolute_repository_path_and_its_parent_hold_every_protected_path(_repo_root: Path) -> None:
    assert guard.check(f"robocopy src {_repo_root} /MIR") == guard.REASON
    assert guard.check(f"robocopy src {_repo_root.parent} /E") == guard.REASON
    assert guard.check(f"robocopy src {_repo_root}/build /MIR") is None
    assert guard.check(f"robocopy src {_repo_root}-other /MIR") is None


def test_the_folder_a_robocopy_runs_in_is_the_one_it_copies_into() -> None:
    assert guard.check("cd src && robocopy .. . /MIR") is None
    assert guard.check("cd src && robocopy x .. /MIR") == guard.REASON
    assert guard.check("cd build && robocopy src ../src /MIR") is None


def test_a_trailing_backslash_is_a_separator_for_a_command_that_ends_there() -> None:
    assert guard.check("xcopy /y a.txt build\\\n") is None
    assert guard.check("xcopy /y a.txt build\\   ") is None
    assert guard.check("xcopy a.txt .cursor\\\n") == guard.REASON
    assert guard.check("echo done\\\\") is None
