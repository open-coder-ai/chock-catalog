"""gen_adoption_transcript.py --check --base sees the work in progress, not only commits."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from gen_adoption_transcript import changed_policy_ids

GIT = shutil.which("git") or "git"


def _git(repo: Path, *args: str) -> None:
    subprocess.run([GIT, "-c", "core.hooksPath=/dev/null", *args], cwd=repo, check=True, capture_output=True)


def _write(repo: Path, rel: str, text: str = "x\n") -> None:
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(text, encoding="utf-8")


def test_committed_staged_unstaged_and_untracked_changes_all_count(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@chock.invalid")
    _git(tmp_path, "config", "user.name", "t")
    for pid in ("untouched", "committed", "staged", "unstaged"):
        _write(tmp_path, f"base/{pid}/manifest.yaml")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    _git(tmp_path, "checkout", "-qb", "work")
    _write(tmp_path, "base/committed/manifest.yaml", "y\n")
    _git(tmp_path, "commit", "-qam", "change")
    _write(tmp_path, "base/staged/manifest.yaml", "y\n")
    _git(tmp_path, "add", "base/staged")
    _write(tmp_path, "base/unstaged/manifest.yaml", "y\n")
    _write(tmp_path, "compliance/untracked/manifest.yaml")
    _write(tmp_path, "docs/transcript-only/adoption.md")
    _write(tmp_path, "docs/transcript-only/README.md")
    assert changed_policy_ids("main", tmp_path) == {"committed", "staged", "unstaged", "untracked", "transcript-only"}


def test_an_unknown_base_is_an_error(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    with pytest.raises(SystemExit, match="merge-base"):
        changed_policy_ids("no-such-ref", tmp_path)
