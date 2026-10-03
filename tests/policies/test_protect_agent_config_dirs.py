"""protect-agent-config v2: the shell guard protects whole agent directories, whatever the case or spelling of the path."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guardkit
from policies.guard_cases_dirs import ALLOWED, CASED, LEAF, REFUSED, RESPELLED, ROOTS

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    for name in (".git", ".claude", ".cursor", ".chock", ".github", "src", "docs"):
        (root / name).mkdir(parents=True)
    monkeypatch.chdir(root)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return root


@pytest.mark.parametrize("raw", REFUSED)
def test_a_write_anywhere_in_an_agent_directory_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.REASON


@pytest.mark.parametrize("root", ROOTS)
def test_every_agent_directory_root_holds_whatever_is_written_below_it(root: str) -> None:
    assert guard.check(f"echo x > {root}/{LEAF}") == guard.REASON
    assert guard.check(f"echo x > deep/er/{root}/{LEAF}") == guard.REASON
    assert guard.hit(f"{root}/{LEAF}")


@pytest.mark.parametrize("raw", CASED)
def test_the_segments_match_without_regard_to_case(raw: str) -> None:
    assert guard.check(raw) == guard.REASON


@pytest.mark.parametrize("raw", RESPELLED)
def test_a_respelled_path_or_a_wrapped_write_is_the_same_write(raw: str) -> None:
    assert guard.check(raw) in (guard.REASON, guard.BLIND), raw


@pytest.mark.parametrize("raw", ALLOWED)
def test_a_read_a_look_alike_and_a_file_another_policy_owns_stay_open(raw: str) -> None:
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize("root", ROOTS)
def test_the_folder_name_alone_is_not_a_file_but_removing_it_is_refused(root: str) -> None:
    assert guard.check(f"rm -rf {root}") == guard.REASON
    assert guard.check(f"cat {root}/{LEAF}") is None
    assert guard.check(f"ls {root}") is None


def test_the_directory_entries_do_not_shadow_a_name_that_only_contains_them() -> None:
    for name in ("my.claude", "x.cursor", "agents", "chocks", "claude"):
        assert not guard.hit(f"{name}/a.md"), name
