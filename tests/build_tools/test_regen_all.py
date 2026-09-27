"""tools/regen_all.py: every derived file, in dependency order, then every CI check, once."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import regen_all
from regen_all import Result


class FakeRun:
    """Stands in for regen_all.run: records each label, fails the ones named."""

    def __init__(self, failing: tuple[str, ...] = ()) -> None:
        self.labels: list[str] = []
        self.failing = failing

    def __call__(self, label: str, cmd: regen_all.Cmd, cwd: Path = regen_all.ROOT) -> Result:
        del cmd, cwd
        self.labels.append(label)
        return Result(label, int(any(label.startswith(f) for f in self.failing)), 0.0, "tail line")


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeRun:
    stub = FakeRun()
    monkeypatch.setattr(regen_all, "run", stub)
    monkeypatch.setattr(regen_all.gen_registry, "update_registry", lambda: "registry.yaml already current")
    monkeypatch.setattr(regen_all.gen_registry, "update_readme", lambda: "README.md counts already current")
    monkeypatch.setattr(regen_all, "changed_policy_ids", lambda _base: {"pin-github-actions", "not-a-policy"})
    return stub


def test_run_takes_an_argv_or_a_shell_string(tmp_path: Path) -> None:
    assert regen_all.run("argv", [sys.executable, "-c", "print('hi')"]).out == "hi"
    failed = regen_all.run("shell", "echo out; echo err >&2; exit 3", cwd=tmp_path)
    assert (failed.rc, failed.out) == (3, "out\nerr")


def test_a_failure_prints_the_tail_of_its_output(capsys) -> None:
    assert regen_all.report(Result("good", 0, 1.0, "hidden")) == 0
    assert regen_all.report(Result("bad", 2, 1.0, "shown")) == 2
    out = capsys.readouterr().out
    assert "hidden" not in out
    assert "FAIL" in out
    assert "        shown" in out


def test_vendor_hook_configs_come_back_as_they_were(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "hooks.json").write_text("committed", encoding="utf-8")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("committed", encoding="utf-8")
    (tmp_path / ".claude" / "skills.json").write_text("not a hook config", encoding="utf-8")
    saved = regen_all.snapshot(tmp_path)
    assert len(saved) == 2
    (tmp_path / ".cursor" / "hooks.json").write_text("/this/machine/python", encoding="utf-8")
    (tmp_path / ".claude" / "settings.json").unlink()
    assert regen_all.restore(saved, tmp_path) == [".claude/settings.json", ".cursor/hooks.json"]
    assert (tmp_path / ".cursor" / "hooks.json").read_text(encoding="utf-8") == "committed"
    assert regen_all.restore(saved, tmp_path) == []


def test_sync_runs_only_on_drift_and_keeps_vendor_configs(fake: FakeRun, monkeypatch, capsys) -> None:
    assert regen_all.sync() == 0
    assert fake.labels == ["sync --check"]
    fake.failing = ("sync --check",)
    monkeypatch.setattr(regen_all, "snapshot", dict)
    monkeypatch.setattr(regen_all, "restore", lambda _saved: [".cursor/hooks.json"])
    assert regen_all.sync() == 0
    assert fake.labels[-1].startswith("chock sync")
    assert "kept as committed" in capsys.readouterr().out
    monkeypatch.setattr(regen_all, "restore", lambda _saved: [])
    regen_all.sync()
    assert "kept as committed" not in capsys.readouterr().out


@pytest.mark.parametrize("cairosvg", [True, False])
def test_regenerate_runs_in_dependency_order(fake: FakeRun, monkeypatch, capsys, cairosvg: bool) -> None:
    monkeypatch.setattr(regen_all, "find_spec", lambda _name: object() if cairosvg else None)
    assert regen_all.regenerate("origin/main") == 0
    labels = fake.labels
    order = ["plugin build base", "sync --check", "policy docs", "coverage matrix", "figures"]
    assert [labels.index(label) for label in order] == sorted(labels.index(label) for label in order)
    assert labels[-1] == "adoption transcript pin-github-actions"
    assert not any("not-a-policy" in label for label in labels)
    assert ("brand card" in labels) is cairosvg
    assert "registry.yaml already current" in capsys.readouterr().out


def test_regenerate_reports_a_failed_step(fake: FakeRun) -> None:
    fake.failing = ("policy docs",)
    assert regen_all.regenerate("origin/main") == 1


def test_check_only_mode_diffs_the_figures_in_a_copy(tmp_path: Path) -> None:
    cmd = regen_all.figures_check(tmp_path)
    assert f'diff -r -x __pycache__ docs/figures "{tmp_path}/figures/docs/figures"' in cmd


@pytest.mark.parametrize("cairosvg", [True, False])
def test_fast_checks_cover_every_generated_file(tmp_path: Path, monkeypatch, cairosvg: bool) -> None:
    monkeypatch.setattr(regen_all, "find_spec", lambda _name: object() if cairosvg else None)
    labels = [label for label, _cmd in regen_all.fast_checks(tmp_path)]
    for expected in ("registry", "installed policies vs their source", "readme", "sync --check", "figures"):
        assert expected in labels
    assert [lb for lb in labels if lb.startswith("plugin --check")] == [f"plugin --check {t}" for t in regen_all.TREES]
    assert ("brand card --check" in labels) is cairosvg


def test_the_staged_adopter_checks_evals_once_and_the_owasp_claim(tmp_path: Path) -> None:
    script = regen_all.stage_adopter(tmp_path)
    assert script.count("chock check") == 1
    assert "--only evals" not in script
    assert "compliance report --framework owasp_asi" in script


def test_slow_checks(tmp_path: Path) -> None:
    labels = [lb for lb, _ in regen_all.slow_checks("b", tmp_path / "fast", fast=True, packaged=False)]
    assert labels == ["chock check (validate, lockfile, every eval)"]
    (tmp_path / "full").mkdir()
    labels = [lb for lb, _ in regen_all.slow_checks("b", tmp_path / "full", fast=False, packaged=True)]
    assert labels[1:] == ["adoption transcripts --check", "staged adopter: check + OWASP claim", "pytest --cov -n auto"]


def test_transcripts_are_checked_only_once_packages_are_current(fake: FakeRun, capsys) -> None:
    assert regen_all.check("b", fast=True) == 0
    assert "adoption transcripts --check" in fake.labels
    fake.labels.clear()
    fake.failing = ("plugin --check compliance",)
    assert regen_all.check("b", fast=True) == 1
    assert "adoption transcripts --check" not in fake.labels
    assert "plugin packages are stale" in capsys.readouterr().out


def test_run_all_handles_no_checks() -> None:
    assert regen_all.run_all([]) == []


def test_main(fake: FakeRun, monkeypatch, capsys) -> None:
    monkeypatch.setattr(regen_all.shutil, "which", lambda _name: None)
    assert regen_all.main([]) == 1
    monkeypatch.setattr(regen_all.shutil, "which", lambda name: name)
    assert regen_all.main(["--check-only", "--fast"]) == 0
    assert "plugin build base" not in fake.labels
    assert capsys.readouterr().out.splitlines()[-1].startswith("== CLEAN")
    fake.failing = ("readme",)
    assert regen_all.main(["--fast", "--base", "main"]) == 1
    assert "plugin build base" in fake.labels
    assert capsys.readouterr().out.splitlines()[-1].startswith("== FAILED")


def test_the_script_documents_its_modes() -> None:
    proc = subprocess.run(
        [sys.executable, str(regen_all.ROOT / "tools" / "regen_all.py"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    for mode in ("--check-only", "--fast", "--base"):
        assert mode in proc.stdout
