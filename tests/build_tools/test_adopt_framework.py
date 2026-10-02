"""tools/adopt_framework.py: pins one full commit SHA, regenerates, then runs every check."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import adopt_framework
import pytest
from trees import ROOT, TREES

SHA = "0123456789abcdef0123456789abcdef01234567"
OLD = "5c9350738729a2cf1c40f5851628384751cae484"


class FakeRun:
    """Stands in for adopt_framework._run: records each label, fails the ones named."""

    def __init__(self, failing: tuple[str, ...] = ()) -> None:
        self.labels: list[str] = []
        self.failing = failing

    def __call__(self, label: str, cmd: list[str]) -> int:
        del cmd
        self.labels.append(label)
        return int(label in self.failing)


@pytest.fixture
def pin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / ".framework-ref"
    path.write_text(OLD + "\n", encoding="utf-8")
    monkeypatch.setattr(adopt_framework, "FRAMEWORK_REF_FILE", path)
    monkeypatch.setattr(adopt_framework.shutil, "which", lambda _name: "/bin/chock")
    return path


def _fake(monkeypatch: pytest.MonkeyPatch, failing: tuple[str, ...] = ()) -> FakeRun:
    stub = FakeRun(failing)
    monkeypatch.setattr(adopt_framework, "_run", stub)
    return stub


@pytest.mark.parametrize("ref", ["main", "v0.1.0", OLD[:12], OLD.upper(), f"{OLD}\n", "refs/heads/" + OLD])
def test_anything_but_a_full_sha_is_refused_before_the_pin_moves(pin: Path, monkeypatch, capsys, ref: str) -> None:
    stub = _fake(monkeypatch)
    assert adopt_framework.main([ref]) == 2
    assert pin.read_text(encoding="utf-8") == OLD + "\n"
    assert stub.labels == []
    assert "not a full 40-character lowercase commit SHA" in capsys.readouterr().err


def test_a_sha_is_pinned_regenerated_and_checked(pin: Path, monkeypatch, capsys) -> None:
    stub = _fake(monkeypatch)
    assert adopt_framework.main([SHA]) == 0
    assert pin.read_text(encoding="utf-8") == SHA + "\n"
    assert stub.labels[0] == "plugin packages"
    assert {"workflow safety", "transcript reproducibility", "adoption transcripts"} <= set(stub.labels)
    assert "ADOPTION CLEAN" in capsys.readouterr().out


@pytest.mark.usefixtures("pin")
def test_the_same_sha_leaves_the_pin_alone_and_skips_transcripts_on_request(monkeypatch, capsys) -> None:
    stub = _fake(monkeypatch)
    assert adopt_framework.main([OLD, "--skip-transcripts"]) == 0
    assert "pinned framework ref" not in capsys.readouterr().out
    assert not {"adoption transcripts", "transcript reproducibility"} & set(stub.labels)


@pytest.mark.usefixtures("pin")
def test_a_failed_regeneration_stops_before_the_checks(monkeypatch, capsys) -> None:
    stub = _fake(monkeypatch, failing=("policy docs",))
    assert adopt_framework.main([SHA]) == 1
    assert "check" not in stub.labels
    assert "regeneration failed" in capsys.readouterr().err


@pytest.mark.usefixtures("pin")
def test_a_failed_check_fails_the_adoption(monkeypatch, capsys) -> None:
    _fake(monkeypatch, failing=("workflow safety",))
    assert adopt_framework.main([SHA]) == 1
    assert "ADOPTION FAILED" in capsys.readouterr().out


@pytest.mark.usefixtures("pin")
def test_a_missing_tree_fails_regeneration(tmp_path: Path, monkeypatch, capsys) -> None:
    _fake(monkeypatch)
    monkeypatch.setattr(adopt_framework, "ROOT", tmp_path)
    assert adopt_framework.main([SHA]) == 1
    assert f"tree listed by tools/trees.py is missing: {TREES[0]}" in capsys.readouterr().err


@pytest.mark.usefixtures("pin")
def test_needs_chock_on_path(monkeypatch) -> None:
    monkeypatch.setattr(adopt_framework.shutil, "which", lambda _name: None)
    assert adopt_framework.main([SHA]) == 1


def test_needs_the_pin_file(pin: Path) -> None:
    pin.unlink()
    assert adopt_framework.main([SHA]) == 1


def test_run_echoes_and_returns_the_exit_code(capsys) -> None:
    assert adopt_framework._run("ok", [sys.executable, "-c", "raise SystemExit(3)"]) == 3
    assert "== ok:" in capsys.readouterr().out


def test_runs_as_a_script() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "adopt_framework.py"), "main"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "'main'" in proc.stderr
