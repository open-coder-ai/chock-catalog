"""lockfile-integrity: at ci and push the registry allowlist is the one at the range base, not the change's own."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from policies import scriptkit
from policies.lockkit import BASE_LOCK, BASE_MANIFEST, NAME, POLICY, found, gate, model, npm_lock, payload, pkg

ALLOWLIST = ".chock/registry-allowlist.txt"
EVIL = "https://npm.evil.example/left-pad-1.3.0.tgz"
SWAPPED = npm_lock({"left-pad": pkg("left-pad", "1.3.0", resolved=EVIL)})
BASE = {"package.json": BASE_MANIFEST, "package-lock.json": BASE_LOCK}


@pytest.fixture(autouse=True)
def no_ci_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)


def rev(repo: Path, ref: str = "HEAD") -> str:
    return subprocess.run(
        [scriptkit.GIT, "rev-parse", ref], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def pull_request(tmp_path: Path, base_files: dict[str, str], head_files: dict[str, str]) -> Path:
    """A repository whose `origin/main` is the base commit and whose HEAD is the change on top of it."""
    repo = scriptkit.init_repo(tmp_path / "r", base_files)
    scriptkit.git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    scriptkit.write(repo, head_files)
    scriptkit.git(repo, "add", "-A")
    scriptkit.git(repo, "commit", "-qm", "the change")
    return repo


@pytest.fixture
def widened(tmp_path: Path) -> Path:
    return pull_request(tmp_path, BASE, {ALLOWLIST: "npm.evil.example\n", "package-lock.json": SWAPPED})


def test_ci_ignores_an_allowlist_the_change_itself_adds(widened: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    assert model.SOURCE in found(widened, {"package-lock.json": SWAPPED}, "ci")


def test_push_uses_the_before_commit_of_the_event(
    widened: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"before": rev(widened, "HEAD^1")}))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    assert model.SOURCE in found(widened, {"package-lock.json": SWAPPED}, "push")


def test_without_a_named_base_the_first_parent_is_the_base(widened: Path, tmp_path: Path) -> None:
    assert model.SOURCE in found(widened, {"package-lock.json": SWAPPED}, "ci")
    assert model.SOURCE in found(widened, {"package-lock.json": SWAPPED}, "push")


def test_a_before_commit_git_cannot_resolve_falls_back_to_the_first_parent(
    widened: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"before": "b" * 40}))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    assert model.SOURCE in found(widened, {"package-lock.json": SWAPPED}, "push")


def test_an_allowlist_the_base_already_holds_still_counts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = pull_request(
        tmp_path, {**BASE, ALLOWLIST: "npm.evil.example\n"}, {"package-lock.json": SWAPPED, "notes.txt": "x\n"}
    )
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    assert model.SOURCE not in found(repo, {"package-lock.json": SWAPPED}, "ci")


def test_a_named_base_that_does_not_resolve_is_a_fault(widened: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_BASE_REF", "nope")
    with pytest.raises(gate.BaseError):
        gate.judge(payload(widened, {"package-lock.json": SWAPPED}, "ci"))
    proc = scriptkit.run_script_full(
        POLICY,
        NAME,
        widened,
        json.dumps(payload(widened, {"package-lock.json": SWAPPED}, "ci")),
        {**os.environ, "GITHUB_BASE_REF": "nope"},
    )
    assert proc.returncode == 2
    assert "internal error" in proc.stderr


def test_a_shallow_checkout_with_no_parent_is_a_fault(widened: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate, "parent_exists", lambda _root: False)
    monkeypatch.setattr(gate, "is_shallow", lambda _root: True)
    with pytest.raises(gate.BaseError):
        gate.judge(payload(widened, {"package-lock.json": SWAPPED}, "ci"))


def test_a_root_commit_has_no_base_so_only_the_default_registries_count(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "root", {**BASE, ALLOWLIST: "npm.evil.example\n"})
    assert model.SOURCE in found(repo, {"package-lock.json": SWAPPED}, "ci")


def test_ci_raises_the_allowlist_edit_but_a_person_s_push_does_not(
    widened: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    edit = {ALLOWLIST: "npm.evil.example\n"}
    assert found(widened, edit, "ci") == [model.ALLOWLIST_EDIT]
    assert found(widened, edit, "push") == []
