"""protect-commit-privacy-commit-msg: the git commit-msg script that applies the guard's markers to the real message."""

from __future__ import annotations

import stat
import subprocess
import sys
from pathlib import Path

import pytest
from policies import guardkit, scriptkit

POLICY = "protect-commit-privacy"
NAME = "protect-commit-privacy-commit-msg.py"
mod = scriptkit.load(POLICY, NAME)
guard = guardkit.load_guard(POLICY)
mod.load_guard()
guardkit.forget_shellparse()
CRASH = ("traceback (most recent call last)", "syntax error", "syntaxerror", "unexpected eof")
LEAK = "the user asked for this"
SESSION = "claude.ai/code/" + "sess" + "ion-link"


def message(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "MSG"
    path.write_text(text, encoding="utf-8")
    return path


def run_on(path: Path, tmp_path: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(scriptkit.script_path(POLICY, NAME)), str(path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stderr


def test_the_manifest_declares_the_script_on_commit_msg_and_no_gate() -> None:
    manifest = scriptkit.manifest(POLICY)
    assert manifest["hook"] == {"script": {"on": ["commit-msg"]}}
    assert manifest["artifact"] == "rule"
    assert scriptkit.script_path(POLICY, f"{POLICY}.py").is_file()


def test_it_uses_the_guards_own_markers() -> None:
    assert mod.load_guard().MARKERS == guard.MARKERS


@pytest.mark.parametrize("marker", guard.MARKERS)
def test_every_marker_of_the_guard_refuses_a_message(marker: str, tmp_path: Path) -> None:
    code, err = run_on(message(tmp_path, f"Fix parser\n\nBody says {marker.upper()} here.\n"), tmp_path)
    assert code == 1
    assert err.startswith("BLOCKED: ")
    assert f"'{marker}'" in err
    assert not any(bad in err.lower() for bad in CRASH)


def test_a_clean_message_passes(tmp_path: Path) -> None:
    assert run_on(message(tmp_path, "Fix the parser\n\nHandle empty input.\n"), tmp_path) == (0, "")


def test_git_comment_lines_are_not_the_message(tmp_path: Path) -> None:
    text = f"Fix the parser\n\n# Please enter the commit message; {LEAK}\n#   {SESSION}\n"
    assert run_on(message(tmp_path, text), tmp_path) == (0, "")


def test_a_marker_after_a_hash_that_is_not_at_line_start_still_counts(tmp_path: Path) -> None:
    code, _ = run_on(message(tmp_path, f"Fix the parser\n\n  # {LEAK}\n"), tmp_path)
    assert code == 1


def test_a_verbose_diff_below_the_scissors_line_is_cut() -> None:
    text = f"Fix\n\n# ------------------------ >8 ------------------------\n+ note: {LEAK}\n"
    assert mod.message_body(text) == "Fix\n"
    assert mod.marker_in(text, guard.MARKERS) is None


def test_the_subject_line_is_checked_too(tmp_path: Path) -> None:
    assert run_on(message(tmp_path, f"{SESSION} fix\n"), tmp_path)[0] == 1


@pytest.mark.parametrize("args", [[], ["a", "b"]])
def test_the_wrong_argument_count_is_a_fault_not_an_allow(args: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert mod.run(args) == 2
    err = capsys.readouterr().err
    assert "not checked" in err
    assert not any(bad in err.lower() for bad in CRASH)


def test_an_unreadable_message_file_is_a_fault_not_an_allow(tmp_path: Path) -> None:
    code, err = run_on(tmp_path / "missing", tmp_path)
    assert code == 2
    assert "internal error" in err
    assert not any(bad in err.lower() for bad in CRASH)


def test_the_message_text_is_never_echoed(tmp_path: Path) -> None:
    text = f"Rotate the key sk-live-123456\n\n{LEAK}\n"
    code, err = run_on(message(tmp_path, text), tmp_path)
    assert code == 1
    assert "sk-live-123456" not in err


def install_hook(repo: Path) -> None:
    hook = repo / ".git" / "hooks" / "commit-msg"
    script = scriptkit.script_path(POLICY, NAME)
    hook.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$1"\n', encoding="utf-8")
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR)


def commit(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [scriptkit.GIT, "commit", "-q", "--allow-empty", *args], cwd=repo, capture_output=True, text=True, check=False
    )


def test_git_aborts_a_commit_whose_message_narrates_and_records_a_clean_one(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "r", {"a.txt": "a\n"})
    install_hook(repo)
    refused = commit(repo, "-m", f"Add feature\n\n{LEAK}")
    assert refused.returncode != 0
    assert "narrates the development process" in refused.stderr
    assert (
        scriptkit.GIT
        and subprocess.run(
            [scriptkit.GIT, "log", "--oneline"], cwd=repo, capture_output=True, text=True, check=False
        ).stdout.count("\n")
        == 1
    )
    assert commit(repo, "-m", "Add feature", "-m", "Describe the change.").returncode == 0


def test_a_message_from_a_file_and_a_verbose_commit_are_judged_on_the_message(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "r", {"a.txt": "a\n"})
    install_hook(repo)
    scriptkit.write(repo, {"a.txt": f"a\n{LEAK}\n"})
    scriptkit.git(repo, "add", "-A")
    file = message(tmp_path, "Change a\n")
    assert commit(repo, "-F", str(file), "--verbose").returncode == 0
    assert commit(repo, "-F", str(message(tmp_path, f"Change a\n{SESSION}\n"))).returncode != 0
