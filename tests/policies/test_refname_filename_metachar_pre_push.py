"""refname-filename-metachar: the pre-push hook that judges every pushed branch and tag name."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from policies import scriptkit

POLICY = "refname-filename-metachar"
push = scriptkit.load(POLICY, "refname-filename-metachar-pre-push.py")
SHA1 = "5c9350738729a2cf1c40f5851628384751cae484"
SHA256 = "ab" * 32
ZERO = "0" * 40
CRASH = ("traceback (most recent call last)", "syntax error", "syntaxerror", "unexpected eof")


def line(remote: str, local: str = SHA1, local_ref: str = "refs/heads/work") -> str:
    return f"{local_ref} {local} {remote} {ZERO}\n"


@pytest.mark.parametrize(
    "remote",
    [
        f"refs/heads/{SHA1}",
        "refs/heads/x${IFS}y",
        f"refs/tags/{SHA256}",
        "refs/heads/feat/x;id",
        "refs/heads/-x",
        "refs/tags/v1.",
    ],
)
def test_a_push_of_a_refused_name_is_refused(remote: str, tmp_path: Path) -> None:
    code, err = scriptkit.run_script(POLICY, "refname-filename-metachar-pre-push.py", tmp_path, line(remote))
    assert code == 1
    assert err.startswith("BLOCKED: pushed ref ")
    assert not any(marker in err.lower() for marker in CRASH)


def test_plain_pushes_and_deletions_pass(tmp_path: Path) -> None:
    stdin = (
        line("refs/heads/feature/np26")
        + line("refs/tags/v1.2.0")
        + line("refs/heads/fix/base64-decode-padding")
        + line("refs/heads/x;id", local=ZERO)
        + "\n"
    )
    assert scriptkit.run_script(POLICY, "refname-filename-metachar-pre-push.py", tmp_path, stdin) == (0, "")


def test_every_refused_ref_is_named(tmp_path: Path) -> None:
    stdin = line("refs/heads/a;b") + line(f"refs/heads/{SHA1}")
    code, err = scriptkit.run_script(POLICY, "refname-filename-metachar-pre-push.py", tmp_path, stdin)
    assert code == 1
    assert err.count("BLOCKED:") == 2


def test_a_ref_holding_other_whitespace_is_read_whole() -> None:
    assert push.refused([f"refs/heads/a{chr(0x3000)}b {SHA1} refs/heads/a{chr(0x3000)}b {ZERO}"]) == []


def test_a_line_git_would_never_write_is_refused() -> None:
    assert push.refused(["refs/heads/a 1 2"]) == ["unreadable pre-push line 'refs/heads/a 1 2'"]


def test_a_pre_push_fault_exits_two(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    def boom(_lines: list[str]) -> list[str]:
        raise ValueError

    monkeypatch.setattr(push, "refused", boom)
    assert push.run("x") == 2
    assert "internal error (ValueError)" in capsys.readouterr().err


def test_the_hook_refuses_a_real_push_of_a_sha_named_branch(tmp_path: Path) -> None:
    """End to end through git: the hook sees the remote name git hands it."""
    remote = tmp_path / "remote.git"
    subprocess.run([scriptkit.GIT, "init", "-q", "--bare", str(remote)], check=True)
    work = scriptkit.init_repo(tmp_path / "w", {"a.txt": "a"})
    hook = work / ".git" / "hooks" / "pre-push"
    script = scriptkit.script_path(POLICY, "refname-filename-metachar-pre-push.py")
    hook.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}"\n', encoding="utf-8")
    hook.chmod(0o755)
    refused = subprocess.run(
        [scriptkit.GIT, "push", "-q", str(remote), f"HEAD:refs/heads/{SHA1}"],
        cwd=work,
        capture_output=True,
        text=True,
        check=False,
    )
    assert refused.returncode != 0
    assert "full commit id" in refused.stderr
    allowed = subprocess.run([scriptkit.GIT, "push", "-q", str(remote), "HEAD:refs/heads/main"], cwd=work, check=False)
    assert allowed.returncode == 0
