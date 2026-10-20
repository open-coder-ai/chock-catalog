"""protect-agent-config: a Windows repository root (drive letter) is judged like a POSIX one for tc-474 and tc-524 (CAT-13)."""

from __future__ import annotations

import sys

import pytest
from policies import guardkit

POLICY = "protect-agent-config"
pathguard = guardkit.load_guard(POLICY, "pathguard")
pathset = sys.modules["pathset"]
pathsubst = sys.modules["pathsubst"]

ROOTS = [
    pytest.param("C:/Users/runner/work/r", id="drive-slash"),
    pytest.param("c:\\Users\\runner\\work\\r", id="drive-backslash"),
]


def _refuses(command: str, root: str, monkeypatch: pytest.MonkeyPatch) -> bool:
    monkeypatch.setenv("CHOCK_HOOK_CWD", root)
    return pathguard.refuses(command, pathset.PROTECTED, pathset.hit, pathset.normalise)


@pytest.mark.parametrize("root", ROOTS)
def test_a_posix_absolute_destination_is_outside_a_windows_repository(
    root: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert not _refuses("cp CLAUDE.md /srv/backup/", root, monkeypatch)


@pytest.mark.parametrize("root", ROOTS)
def test_cd_into_a_git_dir_substitution_then_hooks_reaches_the_hooks_folder(
    root: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _refuses("cd $(git rev-parse --git-dir) && cd hooks && echo x > pre-commit", root, monkeypatch)


@pytest.mark.parametrize("root", ["C:/Users/runner/work/r", "/work/r"])
def test_the_resolver_reads_the_git_dir_of_a_drive_root(root: str) -> None:
    read = pathsubst.resolver(root)
    assert read("git rev-parse --git-dir") == f"{root}/.git"
    assert read("git rev-parse --show-toplevel") == root
    assert read("git rev-parse --git-path hooks") == f"{root}/.git/hooks"
