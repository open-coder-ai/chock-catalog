"""tools/check_installed.py: this repo never runs a policy ahead of the copy it publishes."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import check_installed
from trees import ROOT


def _write(folder: Path, version: str, *, extra: dict[str, str] | None = None) -> None:
    (folder / "evals").mkdir(parents=True)
    (folder / "manifest.yaml").write_text(f"id: {folder.name}\nversion: '{version}'\n", encoding="utf-8")
    for rel, text in {"evals/suite.yaml": "suite: {}\n", **(extra or {})}.items():
        (folder / rel).write_text(text, encoding="utf-8")


def _pair(root: Path, pid: str, installed: str, source: str, **extra: dict[str, str]) -> None:
    _write(root / ".agents" / "policies" / pid, installed, extra=extra.get("installed_files"))
    _write(root / "base" / pid, source, extra=extra.get("source_files"))


def test_ahead_and_same_version_divergence_fail_and_behind_warns(tmp_path: Path, capsys) -> None:
    _pair(tmp_path, "ahead", "0.0.3", "0.0.2")
    _pair(tmp_path, "behind", "0.0.9", "0.0.10")
    _pair(tmp_path, "same", "1.2.0", "1.2.0")
    _pair(tmp_path, "forked", "0.1.0", "0.1.0", installed_files={"evals/suite.yaml": "suite: {cases: []}\n"})
    _write(tmp_path / ".agents" / "policies" / "local-only", "0.0.1")
    (tmp_path / ".agents" / "policies" / "INDEX.md").write_text("# index\n", encoding="utf-8")
    problems, warnings = check_installed.compare(tmp_path)
    assert problems == [
        "ahead: installed 0.0.3, base/ has 0.0.2 -- port the change into base/ahead/",
        "forked: installed 0.1.0, base/ has 0.1.0, but they differ at the same version: evals/suite.yaml",
    ]
    assert warnings == ["behind: installed 0.0.9, base/ has 0.0.10 -- chock add behind --from . --force"]
    assert check_installed.main(tmp_path) == 1
    out = capsys.readouterr().out
    assert out.startswith("warning: behind")
    assert "ahead of, or diverge from" in out


def test_files_only_on_one_side_are_divergence(tmp_path: Path) -> None:
    _pair(tmp_path, "p", "0.0.1", "0.0.1", source_files={"plugin.json": "{}\n"})
    cache = tmp_path / ".agents" / "policies" / "p" / "__pycache__"
    cache.mkdir()
    (cache / "guard.cpython-312.pyc").write_bytes(b"\0")
    assert check_installed.differs(tmp_path / ".agents" / "policies" / "p", tmp_path / "base" / "p") == ["plugin.json"]


def test_a_repo_whose_copies_match_passes(tmp_path: Path, capsys) -> None:
    _pair(tmp_path, "p", "0.0.1", "0.0.1")
    _pair(tmp_path, "q", "0.0.1", "0.0.2")
    assert check_installed.main(tmp_path) == 0
    assert capsys.readouterr().out.endswith("matches or trails its published source (1 behind).\n")


def test_this_repository_passes() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "check_installed.py")], capture_output=True, check=False
    )
    assert proc.returncode == 0, proc.stdout
