"""protect-agent-config v2: a write through a symlink whose target is protected is a write to the protected path."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from policies import guardkit
from policies.guard_cases_links import ALLOWED, LINKS, REFUSED

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
links = guardkit.load_guard(POLICY, "pathlink")
pytestmark = pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root, outside = tmp_path / "repo", tmp_path / "elsewhere"
    for name in (".git", ".claude/commands", ".cursor/rules", "src", "docs", "deep/a", "cfg-not-a-link", "out"):
        (root / name).mkdir(parents=True)
    outside.mkdir()
    (root / "AGENTS.md").write_text("# rules\n", encoding="utf-8")
    (root / ".claude/settings.json").write_text("{}\n", encoding="utf-8")
    (root / "src/real.txt").write_text("x\n", encoding="utf-8")
    for name, target in LINKS.items():
        (root / name).symlink_to(target.replace("@ROOT@", str(root)).replace("@OUT@", str(outside)))
    monkeypatch.chdir(root)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return root


@pytest.mark.parametrize("raw", REFUSED)
def test_a_write_through_a_link_to_a_protected_path_is_refused(raw: str) -> None:
    assert guard.check(raw) in (guard.REASON, guard.BLIND), raw


@pytest.mark.parametrize("raw", ALLOWED)
def test_a_read_a_harmless_link_and_a_link_out_of_the_repository_stay_open(raw: str) -> None:
    assert guard.check(raw) is None, raw


def test_the_same_write_without_the_link_is_allowed(_repo_root: Path) -> None:
    (_repo_root / "notes.md").unlink()
    assert guard.check("echo x > notes.md") is None
    (_repo_root / "notes.md").symlink_to("src/real.txt")
    assert guard.check("echo x > notes.md") is None


def test_a_link_to_a_protected_file_outside_the_repository_is_refused_too(_repo_root: Path, tmp_path: Path) -> None:
    home = tmp_path / "home" / ".claude"
    home.mkdir(parents=True)
    (_repo_root / "global").symlink_to(home)
    assert guard.check("echo x > global/settings.json") == guard.REASON


def test_a_folder_that_cannot_be_listed_is_read_as_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(_path: str) -> list[str]:
        raise PermissionError

    monkeypatch.setattr(links.os, "listdir", refuse)
    assert guard.check("echo x > src/a.txt") is None
    assert guard.check("echo x > src/*") is None
    assert guard.check("echo x > .claude/a.md") == guard.REASON


def test_a_wildcard_too_wide_to_read_through_the_links_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    assert guard.check("echo x > out/*") is None
    monkeypatch.setattr(links.os, "listdir", lambda _path: [f"f{k}" for k in range(links._BUDGET + 1)])
    assert guard.check("echo x > out/*") == guard.REASON


def test_a_link_that_cannot_be_read_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(_path: str) -> str:
        raise OSError

    monkeypatch.setattr(links.os, "readlink", refuse)
    assert guard.check("echo x > notes.md") == guard.REASON


def test_a_link_chain_longer_than_the_limit_is_refused(_repo_root: Path) -> None:
    previous = "AGENTS.md"
    for k in range(60):
        (_repo_root / f"hop{k}").symlink_to(previous)
        previous = f"hop{k}"
    assert guard.check(f"echo x > {previous}") == guard.REASON
