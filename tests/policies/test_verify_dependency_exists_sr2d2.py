"""verify-dependency-exists: at an agent's events the allowlist is HEAD's, and an agent's write cannot add to it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import depkit, scriptkit

mod, _ = depkit.load()
POLICY = "verify-dependency-exists"
NAME = "dependency-manifests.py"
ALLOWLIST = ".chock/dependency-allowlist.txt"
AGENT_EVENTS = ["tool_use", "stop", "agent-commit"]


def run(repo: Path, event: str, writes: dict[str, str]) -> tuple[int, list[str], str]:
    payload = {"event": event, "repo_root": str(repo), "writes": writes}
    proc = scriptkit.run_script_full(POLICY, NAME, repo, json.dumps(payload))
    found = json.loads(proc.stdout)["findings"] if proc.stdout else []
    return proc.returncode, [item["key"] for item in found], proc.stderr


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {ALLOWLIST: "requests\n", "README.md": "x\n"})


@pytest.mark.parametrize("event", AGENT_EVENTS)
def test_a_deleted_allowlist_is_empty_not_unseeded(repo: Path, event: str) -> None:
    (repo / ALLOWLIST).unlink()
    code, keys, _ = run(repo, event, {"requirements.txt": "requests\n"})
    assert (code, keys) == (1, ["py|requests"])


@pytest.mark.parametrize("event", AGENT_EVENTS)
def test_an_allowlist_grown_on_disk_does_not_approve(repo: Path, event: str) -> None:
    (repo / ALLOWLIST).write_text("requests\nevil-pkg\n")
    code, keys, _ = run(repo, event, {"requirements.txt": "requests\nevil-pkg\n"})
    assert (code, keys) == (1, ["py|evil-pkg"])


def test_a_person_s_commit_reads_the_allowlist_on_disk(repo: Path) -> None:
    (repo / ALLOWLIST).write_text("requests\nnew-pkg\n")
    assert run(repo, "commit", {"requirements.txt": "requests\nnew-pkg\n"})[:2] == (0, [])


@pytest.mark.parametrize("event", AGENT_EVENTS)
def test_missing_at_head_and_on_disk_stays_warn_only(tmp_path: Path, event: str) -> None:
    bare = scriptkit.init_repo(tmp_path / "bare", {"README.md": "x\n"})
    code, keys, err = run(bare, event, {"requirements.txt": "requests\n"})
    assert (code, keys) == (4, [])
    assert "does not exist" in err


def test_an_allowlist_created_after_head_does_not_approve(tmp_path: Path) -> None:
    bare = scriptkit.init_repo(tmp_path / "bare", {"README.md": "x\n"})
    scriptkit.write(bare, {ALLOWLIST: "evil-pkg\n"})
    assert run(bare, "tool_use", {"requirements.txt": "evil-pkg\n"})[0] == 4


@pytest.mark.parametrize("event", AGENT_EVENTS)
def test_without_any_commit_an_agent_s_allowlist_on_disk_is_not_read(tmp_path: Path, event: str) -> None:
    fresh = scriptkit.init_repo(tmp_path / "fresh")
    scriptkit.write(fresh, {ALLOWLIST: "evil-pkg\n"})
    assert mod.load_allowlist(fresh, event) is None
    assert run(fresh, event, {"requirements.txt": "evil-pkg\n"})[0] == 4
    assert run(fresh, event, {ALLOWLIST: "evil-pkg\n"})[:2] == (1, ["allowlist|evil-pkg"])


def test_without_any_commit_a_person_s_commit_still_reads_the_disk(tmp_path: Path) -> None:
    fresh = scriptkit.init_repo(tmp_path / "fresh")
    scriptkit.write(fresh, {ALLOWLIST: "requests\n"})
    assert run(fresh, "commit", {"requirements.txt": "requests\nother\n"})[:2] == (1, ["py|other"])


@pytest.mark.parametrize("event", AGENT_EVENTS)
def test_without_git_an_agent_s_allowlist_on_disk_is_not_read(
    repo: Path, event: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mod, "GIT", str(repo / "no-such-git"))
    assert mod.load_allowlist(repo, event) is None
    assert mod.load_allowlist(repo, "commit") == ["requests"]


@pytest.mark.parametrize("event", AGENT_EVENTS)
def test_an_agent_write_that_adds_to_the_allowlist_is_refused(repo: Path, event: str) -> None:
    code, keys, err = run(repo, event, {ALLOWLIST: "requests\n# note\nevil-pkg  # approved\n"})
    assert (code, keys) == (1, ["allowlist|evil-pkg"])
    assert "evil-pkg" in err


def test_an_agent_write_that_only_removes_or_keeps_entries_passes(repo: Path) -> None:
    assert run(repo, "tool_use", {ALLOWLIST: "requests\n"})[:2] == (0, [])
    assert run(repo, "tool_use", {ALLOWLIST: "# emptied\n"})[:2] == (0, [])


def test_an_agent_cannot_seed_the_first_allowlist(tmp_path: Path) -> None:
    bare = scriptkit.init_repo(tmp_path / "bare", {"README.md": "x\n"})
    code, keys, _ = run(bare, "tool_use", {ALLOWLIST: "evil-pkg\n"})
    assert (code, keys) == (1, ["allowlist|evil-pkg"])


def test_a_person_s_commit_may_add_to_the_allowlist(repo: Path) -> None:
    assert run(repo, "commit", {ALLOWLIST: "requests\nnew-pkg\n"})[:2] == (0, [])
