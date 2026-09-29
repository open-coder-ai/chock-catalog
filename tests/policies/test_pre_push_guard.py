"""block-destructive-commands-pre-push: the git pre-push script that refuses a non-fast-forward push."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from policies import scriptkit

POLICY = "block-destructive-commands"
NAME = "block-destructive-commands-pre-push.py"
ZERO = "0" * 40
mod = scriptkit.load(POLICY, NAME)


def rev(repo: Path, ref: str = "HEAD") -> str:
    done = subprocess.run([scriptkit.GIT, "rev-parse", ref], cwd=repo, capture_output=True, text=True, check=True)
    return done.stdout.strip()


def commit(repo: Path, name: str) -> str:
    scriptkit.write(repo, {name: name})
    scriptkit.git(repo, "add", "-A")
    scriptkit.git(repo, "commit", "-q", "-m", name)
    return rev(repo)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A repository that is also the working directory, as it is when git runs a hook."""
    path = scriptkit.init_repo(tmp_path / "r", {"a.txt": "a"})
    monkeypatch.chdir(path)
    return path


def line(local: str, remote: str, ref: str = "refs/heads/main") -> str:
    return f"{ref} {local} {ref} {remote}\n"


def test_the_manifest_declares_the_script_on_push() -> None:
    assert scriptkit.manifest(POLICY)["hook"]["script"]["on"] == ["push"]


def test_a_fast_forward_is_let_through(repo: Path) -> None:
    old = rev(repo)
    new = commit(repo, "b.txt")
    assert mod.rewritten([line(new, old)]) == []
    assert scriptkit.run_script(POLICY, NAME, repo, line(new, old)) == (0, "")


def test_a_rewrite_is_refused_with_its_ref_named(repo: Path) -> None:
    old = commit(repo, "b.txt")
    scriptkit.git(repo, "reset", "-q", "--soft", "HEAD~1")
    scriptkit.git(repo, "commit", "-q", "-m", "rewritten")
    new = rev(repo)
    code, err = scriptkit.run_script(POLICY, NAME, repo, line(new, old))
    assert code == 1
    assert err.startswith("BLOCKED: ")
    assert "refs/heads/main" in err
    assert "Traceback" not in err


def test_a_diverged_branch_is_refused(repo: Path) -> None:
    base = rev(repo)
    theirs = commit(repo, "theirs.txt")
    scriptkit.git(repo, "checkout", "-q", "-b", "mine", base)
    mine = commit(repo, "mine.txt")
    assert mod.rewritten([line(mine, theirs)]) == ["refs/heads/main"]


def test_a_remote_object_this_clone_never_saw_counts_as_a_rewrite(repo: Path) -> None:
    assert mod.rewritten([line(rev(repo), "1" * 40)]) == ["refs/heads/main"]


def test_a_new_ref_a_deletion_and_a_no_op_are_not_rewrites(repo: Path) -> None:
    head = rev(repo)
    assert mod.rewritten([line(head, ZERO)]) == []
    assert mod.rewritten([line(ZERO, head)]) == []
    assert mod.rewritten([line(head, head)]) == []
    assert mod.rewritten([line("0" * 64, head)]) == []


def test_a_tag_moved_sideways_is_a_rewrite(repo: Path) -> None:
    old = rev(repo)
    scriptkit.git(repo, "checkout", "-q", "--orphan", "other")
    new = commit(repo, "orphan.txt")
    assert mod.rewritten([line(new, old, "refs/tags/v1")]) == ["refs/tags/v1"]


def test_every_refused_ref_is_listed_and_a_malformed_line_is_skipped(repo: Path) -> None:
    old = commit(repo, "b.txt")
    scriptkit.git(repo, "checkout", "-q", "-b", "side", "HEAD~1")
    new = commit(repo, "side.txt")
    stdin = "\n".join(
        [
            line(new, old, "refs/heads/one").strip(),
            "garbage line",
            "",
            line(new, old, "refs/heads/two").strip(),
        ]
    )
    code, err = scriptkit.run_script(POLICY, NAME, repo, stdin)
    assert code == 1
    assert "refs/heads/one, refs/heads/two" in err


def test_no_input_is_a_push_of_nothing(repo: Path) -> None:
    assert scriptkit.run_script(POLICY, NAME, repo, "") == (0, "")


def test_a_fault_in_the_check_is_reported_and_is_not_a_verdict(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_lines: list[str]) -> list[str]:
        raise OSError

    monkeypatch.setattr(mod, "rewritten", boom)
    assert mod.run(line("a" * 40, "b" * 40)) == 2
    err = capsys.readouterr().err
    assert "internal error (OSError)" in err
    assert "BLOCKED" not in err


def test_git_runs_the_hook_a_fast_forward_pushes_and_a_force_does_not(tmp_path: Path) -> None:
    remote = tmp_path / "remote.git"
    remote.mkdir()
    scriptkit.git(remote, "init", "-q", "--bare", "--initial-branch=main")
    work = scriptkit.init_repo(tmp_path / "work", {"a.txt": "a"})
    hook = work / ".git" / "hooks" / "pre-push"
    hook.write_text(
        f'#!/bin/sh\nexec "{sys.executable}" "{scriptkit.script_path(POLICY, NAME)}"\n',
        encoding="utf-8",
    )
    hook.chmod(0o755)
    scriptkit.git(work, "remote", "add", "origin", str(remote))
    scriptkit.git(work, "push", "-q", "origin", "main")
    commit(work, "b.txt")
    scriptkit.git(work, "push", "-q", "origin", "main")
    scriptkit.git(work, "reset", "-q", "--soft", "HEAD~1")
    scriptkit.git(work, "commit", "-q", "-m", "rewritten")
    forced = subprocess.run(
        [scriptkit.GIT, "push", "--force", "origin", "main"], cwd=work, capture_output=True, text=True, check=False
    )
    assert forced.returncode != 0
    assert "would rewrite history on refs/heads/main" in forced.stderr
    assert rev(remote, "main") != rev(work)
