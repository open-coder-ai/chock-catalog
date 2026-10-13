"""tools/adopt_framework.py: pins one full commit SHA, regenerates, then runs every check."""

from __future__ import annotations

import json
import subprocess
import sys
from importlib.metadata import PackageNotFoundError
from pathlib import Path

import adopt_framework
import pytest
import regen_all
from trees import ROOT, TREES

SHA = "0123456789abcdef0123456789abcdef01234567"
OLD = "5c9350738729a2cf1c40f5851628384751cae484"


class FakeRun:
    """Stands in for adopt_framework._run and regen_all.run: records each label, fails the ones named."""

    def __init__(self, failing: tuple[str, ...] = ()) -> None:
        self.labels: list[str] = []
        self.failing = failing

    def __call__(self, label: str, cmd: list[str]) -> int:
        del cmd
        self.labels.append(label)
        return int(label in self.failing)

    def regen(self, label: str, cmd: regen_all.Cmd, cwd: Path = ROOT) -> regen_all.Result:
        del cwd
        return regen_all.Result(label, self(label, cmd), 0.0, "")


@pytest.fixture
def pin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / ".framework-ref"
    path.write_text(OLD + "\n", encoding="utf-8")
    monkeypatch.setattr(adopt_framework, "FRAMEWORK_REF_FILE", path)
    monkeypatch.setattr(adopt_framework.shutil, "which", lambda _name: "/bin/chock")
    monkeypatch.setattr(adopt_framework, "installed_engine", lambda: SHA)
    return path


def _fake(monkeypatch: pytest.MonkeyPatch, failing: tuple[str, ...] = ()) -> FakeRun:
    stub = FakeRun(failing)
    monkeypatch.setattr(adopt_framework, "_run", stub)
    monkeypatch.setattr(regen_all, "run", stub.regen)
    for update in ("update_registry", "update_readme", "update_prose"):
        monkeypatch.setattr(regen_all.gen_registry, update, lambda name=update: f"{name} ran")
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
    assert stub.labels[1] == "plugin build (installed)"
    regenerated = {"policy docs", "coverage matrix", "figures", "adoption transcripts"}
    assert regenerated | {"workflow safety", "transcript reproducibility"} <= set(stub.labels)
    out = capsys.readouterr().out
    assert all(f"update_{name} ran" in out for name in ("registry", "readme", "prose"))
    assert "ADOPTION CLEAN" in out


@pytest.mark.parametrize("engine", [OLD, None])
def test_an_engine_other_than_the_ref_is_refused_before_the_pin_moves(pin: Path, monkeypatch, capsys, engine) -> None:
    stub = _fake(monkeypatch)
    monkeypatch.setattr(adopt_framework, "installed_engine", lambda: engine)
    assert adopt_framework.main([SHA]) == 2
    assert pin.read_text(encoding="utf-8") == OLD + "\n"
    assert stub.labels == []
    err = capsys.readouterr().err
    assert f"the installed chock is {engine or 'unidentified'}, not {SHA}" in err
    assert f'pip install --force-reinstall --no-deps "chock @ git+https://github.com/open-coder-ai/chock@{SHA}"' in err


class FakeDist:
    def __init__(self, direct_url: str | None) -> None:
        self.direct_url = direct_url

    def read_text(self, name: str) -> str | None:
        assert name == "direct_url.json"
        return self.direct_url


def _installed(monkeypatch: pytest.MonkeyPatch, direct_url: object) -> str | None:
    def dist(name: str) -> FakeDist:
        assert name == "chock"
        if direct_url is PackageNotFoundError:
            raise PackageNotFoundError(name)
        return FakeDist(direct_url if direct_url is None or isinstance(direct_url, str) else json.dumps(direct_url))

    monkeypatch.setattr(adopt_framework, "distribution", dist)
    return adopt_framework.installed_engine()


def test_a_git_install_is_identified_by_its_commit(monkeypatch) -> None:
    vcs = {"url": "https://github.com/open-coder-ai/chock", "vcs_info": {"vcs": "git", "commit_id": SHA}}
    assert _installed(monkeypatch, vcs) == SHA


def _git(repo: Path, *args: str) -> str:
    cmd = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t.invalid", *args]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()


def test_a_directory_install_is_identified_by_its_checkout_ignoring_build_output(tmp_path: Path, monkeypatch) -> None:
    engine = tmp_path / "engine"
    engine.mkdir()
    _git(engine, "init", "-q")
    (engine / ".gitignore").write_text("build/\n*.egg-info/\n", encoding="utf-8")
    (engine / "cli.py").write_text("v1\n", encoding="utf-8")
    _git(engine, "add", ".")
    _git(engine, "commit", "-qm", "engine")
    (engine / "build").mkdir()
    (engine / "build" / "lib.py").write_text("built\n", encoding="utf-8")
    direct_url = {"url": engine.as_uri(), "dir_info": {}}
    assert _installed(monkeypatch, direct_url) == _git(engine, "rev-parse", "HEAD")
    (engine / "extra.py").write_text("untracked\n", encoding="utf-8")
    assert _installed(monkeypatch, direct_url) is None
    (engine / "extra.py").unlink()
    (engine / "cli.py").write_text("v2\n", encoding="utf-8")
    assert _installed(monkeypatch, direct_url) is None
    assert _installed(monkeypatch, {"url": (tmp_path / "gone").as_uri(), "dir_info": {}}) is None


@pytest.mark.parametrize(
    "direct_url",
    [PackageNotFoundError, None, "", "not json", {"url": "https://x", "archive_info": {}}, {"dir_info": {}}],
)
def test_an_unrecorded_install_is_unidentified(monkeypatch, direct_url: object) -> None:
    assert _installed(monkeypatch, direct_url) is None


@pytest.mark.usefixtures("pin")
def test_the_same_sha_leaves_the_pin_alone_and_skips_transcripts_on_request(monkeypatch, capsys) -> None:
    stub = _fake(monkeypatch)
    monkeypatch.setattr(adopt_framework, "installed_engine", lambda: OLD)
    assert adopt_framework.main([OLD, "--skip-transcripts"]) == 0
    assert "pinned framework ref" not in capsys.readouterr().out
    assert not {"adoption transcripts", "transcript reproducibility"} & set(stub.labels)


@pytest.mark.usefixtures("pin")
def test_a_failed_regeneration_stops_before_the_checks(monkeypatch, capsys) -> None:
    stub = _fake(monkeypatch, failing=("policy docs",))
    assert adopt_framework.main([SHA]) == 1
    assert "check" not in stub.labels
    assert "regeneration failed" in capsys.readouterr().err


def test_the_registry_is_regenerated_after_the_pin_moves_and_before_the_checks(pin: Path, monkeypatch) -> None:
    stub = _fake(monkeypatch)

    def update_registry() -> str:
        assert pin.read_text(encoding="utf-8") == SHA + "\n"
        stub.labels.append("registry")
        return "registry.yaml rewritten"

    monkeypatch.setattr(regen_all.gen_registry, "update_registry", update_registry)
    assert adopt_framework.main([SHA]) == 0
    assert stub.labels.index("registry") < stub.labels.index("check")


@pytest.mark.usefixtures("pin")
def test_a_failed_registry_regeneration_stops_before_the_checks(monkeypatch) -> None:
    stub = _fake(monkeypatch)

    def update_registry() -> str:
        raise ValueError

    monkeypatch.setattr(regen_all.gen_registry, "update_registry", update_registry)
    with pytest.raises(ValueError):
        adopt_framework.main([SHA])
    assert "check" not in stub.labels


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
