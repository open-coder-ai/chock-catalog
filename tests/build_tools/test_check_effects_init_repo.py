"""check_effects.init_repo starts no background git maintenance, and no .git write goes unseen."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import check_effects
import pytest

GIT = shutil.which("git") or "git"


def git_config(repo: Path, key: str) -> str:
    return subprocess.run(
        [GIT, "config", "--get", key], cwd=repo, capture_output=True, text=True, check=False
    ).stdout.strip()


def test_init_repo_turns_background_maintenance_off(tmp_path: Path) -> None:
    check_effects.init_repo(tmp_path)
    assert git_config(tmp_path, "maintenance.auto") == "false"
    assert git_config(tmp_path, "gc.auto") == "0"


def test_init_repo_commits_the_canaries(tmp_path: Path) -> None:
    check_effects.plant(tmp_path)
    check_effects.init_repo(tmp_path)
    log = subprocess.run([GIT, "log", "--format=%s"], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert log.stdout.strip() == "canary"


@pytest.mark.parametrize(
    ("action", "report"),
    [
        ("create", "created .git/objects/maintenance.lock"),
        ("delete", "deleted .git/objects/maintenance.lock"),
        ("modify", "modified .git/config"),
    ],
)
def test_a_guard_writing_under_dot_git_is_still_reported(
    monkeypatch: pytest.MonkeyPatch, action: str, report: str
) -> None:
    def guard(_bash: str, _guard: Path, _command: str, workspace: Path, *_a: object, **_k: object) -> None:
        lock = workspace / ".git" / "objects" / "maintenance.lock"
        if action == "create":
            lock.write_text("x", encoding="utf-8")
        elif action == "delete":
            lock.unlink()
        else:
            (workspace / ".git" / "config").write_text("changed", encoding="utf-8")

    real_init = check_effects.init_repo

    def init_with_lock(workspace: Path) -> None:
        real_init(workspace)
        (workspace / ".git" / "objects" / "maintenance.lock").write_text("held", encoding="utf-8")
        if action == "create":
            (workspace / ".git" / "objects" / "maintenance.lock").unlink()

    monkeypatch.setattr(check_effects, "run_guard", guard)
    monkeypatch.setattr(check_effects, "init_repo", init_with_lock)
    how = check_effects.Exercise(effects={"read_only"}, script_gate=False, git_repo=True, commands=["x"])
    failures = check_effects.check_guard("bash", "demo", Path("g.sh"), how)
    assert any(report in f for f in failures)
