"""tools/framework_ref.py: the pin is one full commit SHA, and a checkout of it is that commit."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import framework_ref
import pytest
from trees import ROOT

SHA = "5c9350738729a2cf1c40f5851628384751cae484"


@pytest.mark.parametrize(
    "ref",
    [
        "",
        "main",
        "v1.2.0",
        SHA[:7],
        SHA[:39],
        SHA + "0",
        SHA.upper(),
        SHA + "\n",
        " " + SHA,
        "refs/heads/" + SHA,
        SHA[:39] + "g",
        "-" + SHA[1:],
    ],
)
def test_anything_but_forty_lowercase_hex_is_refused(ref: str) -> None:
    assert not framework_ref.valid(ref)


def test_a_full_lowercase_sha_is_valid() -> None:
    assert framework_ref.valid(SHA)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (SHA.encode(), SHA),
        (SHA.encode() + b"\n", SHA),
        (SHA.encode() + b"\n\n", None),
        (SHA.encode() + b"\r\n", None),
        (b" " + SHA.encode() + b"\n", None),
        (b"v1.0.0\n", None),
        (SHA.encode() + b"\nFRAMEWORK_REF=main\n", None),
        (b"\xff" * 40, None),
    ],
)
def test_the_pin_file_holds_one_sha_and_at_most_one_newline(tmp_path: Path, raw: bytes, expected: str | None) -> None:
    (tmp_path / ".framework-ref").write_bytes(raw)
    assert framework_ref.read_pin(tmp_path) == expected


def test_a_missing_pin_file_is_refused(tmp_path: Path) -> None:
    assert framework_ref.read_pin(tmp_path) is None


def test_this_repo_pin_is_valid() -> None:
    assert framework_ref.read_pin(ROOT) is not None


def test_read_exports_the_pin_to_the_job_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    env_file = tmp_path / "github_env"
    env_file.write_text("EARLIER=1\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_ENV", str(env_file))
    assert framework_ref.main(["read"]) == 0
    pin = framework_ref.read_pin(ROOT)
    assert env_file.read_text(encoding="utf-8") == f"EARLIER=1\nFRAMEWORK_REF={pin}\n"
    assert capsys.readouterr().out == f"FRAMEWORK_REF={pin}\n"


def test_read_without_a_job_env_only_prints(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.delenv("GITHUB_ENV", raising=False)
    assert framework_ref.main(["read"]) == 0
    assert capsys.readouterr().out.startswith("FRAMEWORK_REF=")


def test_read_refuses_a_bad_pin_and_exports_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    (tmp_path / ".framework-ref").write_text("main\n", encoding="utf-8")
    env_file = tmp_path / "github_env"
    monkeypatch.setattr(framework_ref, "ROOT", tmp_path)
    monkeypatch.setenv("GITHUB_ENV", str(env_file))
    assert framework_ref.main(["read"]) == framework_ref.REFUSED
    assert not env_file.exists()
    assert "::error::.framework-ref must hold one full" in capsys.readouterr().err


@pytest.mark.parametrize(("ref", "rc"), [(SHA, 0), ("main", 2), (SHA[:12], 2), (SHA.upper(), 2), ("", 2)])
def test_check_validates_the_env_ref(monkeypatch: pytest.MonkeyPatch, ref: str, rc: int) -> None:
    monkeypatch.setenv("FRAMEWORK_REF", ref)
    assert framework_ref.main(["check"]) == rc


def test_check_refuses_an_unset_ref(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FRAMEWORK_REF", raising=False)
    assert framework_ref.main(["check"]) == framework_ref.REFUSED


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    cmd = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args]
    return subprocess.run(cmd, check=True, capture_output=True, text=True, env=env).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str, str]:
    """A repo with two commits: the pinned one, and an impostor reachable by a name spelled like it."""
    path = tmp_path / "framework"
    path.mkdir()
    _git(path, "init", "-q")
    _git(path, "commit", "-q", "--allow-empty", "-m", "pinned")
    pinned = _git(path, "rev-parse", "HEAD")
    _git(path, "commit", "-q", "--allow-empty", "-m", "impostor")
    impostor = _git(path, "rev-parse", "HEAD")
    _git(path, "checkout", "-q", pinned)
    return path, pinned, impostor


def test_verify_passes_on_the_pinned_commit(repo, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    path, pinned, _ = repo
    monkeypatch.setenv("FRAMEWORK_REF", pinned)
    assert framework_ref.main(["verify", str(path)]) == 0
    assert f"is the pinned commit {pinned}" in capsys.readouterr().out


@pytest.mark.parametrize("kind", ["branch", "tag"])
def test_verify_refuses_a_name_spelled_like_the_sha(repo, monkeypatch: pytest.MonkeyPatch, capsys, kind: str) -> None:
    path, pinned, impostor = repo
    if kind == "branch":
        _git(path, "branch", pinned, impostor)
    else:
        _git(path, "tag", pinned, impostor)
    _git(path, "checkout", "-q", f"refs/{'heads' if kind == 'branch' else 'tags'}/{pinned}")
    monkeypatch.setenv("FRAMEWORK_REF", pinned)
    assert framework_ref.main(["verify", str(path)]) == framework_ref.REFUSED
    assert f"checked out at {impostor}, not the pinned {pinned}" in capsys.readouterr().err


def test_verify_refuses_what_is_not_a_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    monkeypatch.setenv("FRAMEWORK_REF", SHA)
    assert framework_ref.main(["verify", str(tmp_path)]) == framework_ref.REFUSED
    assert "checked out at no commit" in capsys.readouterr().err


def test_verify_refuses_a_bad_ref_before_looking(repo, monkeypatch: pytest.MonkeyPatch) -> None:
    path, pinned, _ = repo
    monkeypatch.setenv("FRAMEWORK_REF", pinned[:12])
    assert framework_ref.main(["verify", str(path)]) == framework_ref.REFUSED


def test_runs_as_a_script(repo) -> None:
    path, pinned, impostor = repo
    env = {**os.environ, "FRAMEWORK_REF": impostor}
    cmd = [sys.executable, str(ROOT / "tools" / "framework_ref.py"), "verify", str(path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
    assert proc.returncode == framework_ref.REFUSED
    assert f"not the pinned {impostor}" in proc.stderr
    assert pinned in proc.stderr
