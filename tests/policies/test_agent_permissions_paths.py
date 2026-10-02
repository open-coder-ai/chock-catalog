"""agent-permissions-scan: every spelling of a path reaches the same file, and the sidecar keeps its name."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from policies import scriptkit
from policies.permskit import CLAUDE, keys, mod, payload, sidecar
from policies.test_agent_permissions_scan import WAIVE, held, settings, waiver_file


def test_the_writes_path_forms_all_reach_the_same_file(tmp_path: Path) -> None:
    base = held(tmp_path, {CLAUDE: settings(deny=["Read(.env)"])})
    wanted = ["ap-deny-removed|permissions.deny|Read(.env)"]
    forms = (CLAUDE, "./" + CLAUDE, ".claude\\\\settings.json", str(base / CLAUDE), ".claude//settings.json")
    for form in (*forms, ".claude/./settings.json", ".Claude/Settings.json", "sub/../" + CLAUDE):
        for event in ("commit", "tool_use"):
            assert keys(base, {form: settings()}, event) == wanted, form


def test_a_config_outside_the_repository_cannot_be_compared_and_says_so(tmp_path: Path) -> None:
    repo = held(tmp_path, {"README.md": "x\n"})
    for form in ("/elsewhere/" + CLAUDE, "../" + CLAUDE):
        (found,) = mod.findings(payload(repo, {form: settings()}))
        assert found["key"].startswith("ap-unmapped|")


def test_the_sidecar_under_a_non_canonical_name_is_still_the_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = held(tmp_path, {"README.md": "x\n"})
    monkeypatch.setenv("CLAUDECODE", "1")
    for form in (".chock//devenv.json", "x/../.chock/devenv.json", ".CHOCK/devenv.json"):
        (found,) = mod.findings(payload(base, {form: waiver_file(WAIVE)}, "tool_use"))
        assert found["key"].startswith("ap-agent-waiver|"), form


def test_a_git_that_cannot_run_finds_no_head_copies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = scriptkit.init_repo(tmp_path / "g", {"a.txt": "x\n"})

    def boom(*_a: object, **_k: object) -> None:
        raise OSError

    monkeypatch.setattr(subprocess, "run", boom)
    assert sidecar.committed_all(repo, "a.txt") == []
