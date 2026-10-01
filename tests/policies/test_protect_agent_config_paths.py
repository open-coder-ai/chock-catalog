"""protect-agent-config: a command is judged by the paths it resolves to, not by the text it names."""

from __future__ import annotations

import posixpath
from pathlib import Path

import pytest
from policies import guardkit
from policies.guard_cases_paths import ALLOWED, REFUSED

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
paths = guardkit.load_guard(POLICY, "pathguard")


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / ".git").mkdir()
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _target(entry: str) -> str:
    """A concrete file the guard protects, for an entry of PROTECTED."""
    if entry.endswith("/"):
        return f"{entry}x"
    return f"{entry}.json" if entry == ".claude/settings" else entry


TARGETS = sorted({_target(e) for e in guard.PROTECTED})


def _forms(target: str) -> list[str]:
    folder, name = posixpath.split(target)
    forms = [
        f"echo x > $(echo {target})",
        f"echo x > `echo {target}`",
        f"echo x > x/../{target}",
        f"echo x > {target.replace('/', '/x/../', 1)}",
        f"echo x > ${{D}}/{name}",
        f"cd src && echo x > ../{target}",
        f"cd src; tee ../{target}",
        f"cd $UNKNOWN; echo x > {name}",
    ]
    if folder:
        forms += [
            f"cd {folder} && echo x > {name}",
            f"cd {folder}; tee {name}",
            f"pushd {folder}; sed -i s/a/b/ {name}",
            f"D={folder}; echo x > $D/{name}",
            f"D={folder}; rm $D/{name}",
        ]
        parts = folder.split("/")
        for i in range(1, len(parts) + 1):
            top = "/".join(parts[:i])
            forms += [f"mv {top} /tmp/old", f"ln -s /tmp/x {top}", f"rm -r {top}", f"cp -r evil/ {top}"]
    return forms


@pytest.mark.parametrize("raw", REFUSED)
def test_a_command_that_resolves_to_a_protected_path_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.REASON


@pytest.mark.parametrize("raw", ALLOWED)
def test_an_ordinary_command_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None


@pytest.mark.parametrize("target", TARGETS)
def test_every_protected_path_is_refused_through_every_bypass(target: str) -> None:
    for raw in _forms(target):
        assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize("target", TARGETS)
def test_reading_every_protected_path_stays_allowed(target: str) -> None:
    folder, name = posixpath.split(target)
    reads = [f"cat {target}", f"ls {folder or '.'}", f"cd {folder or '.'} && cat {name}", f"cat x/../{target}"]
    assert [raw for raw in reads if guard.check(raw)] == []


@pytest.mark.parametrize(
    "raw",
    [
        "rm -r .agents",
        "rm -r .agents/policies",
        "rm -r .agents/policies/protect-agent-config",
        "echo x > .agents/policies/p/implementations/x.py",
        "rm .agents/policies/*/implementations/*.py",
        "cd .agents/policies/p/implementations && echo x > g.py",
    ],
)
def test_the_guard_sources_are_protected_through_their_parents(raw: str) -> None:
    assert guard.check(raw) == guard.REASON


@pytest.mark.parametrize(
    "raw",
    [
        "cd .cursor && cd .. && echo x > mcp.json",
        "pushd .cursor; popd; echo x > mcp.json",
        "cd .cursor/rules && echo x > ../mcp.json.bak",
        "popd; echo x > mcp.json",
        "cd /tmp && echo x > mcp.json",
        "cd ~ && echo x > mcp.json",
    ],
)
def test_the_virtual_directory_follows_cd_pushd_and_popd(raw: str) -> None:
    expected = guard.REASON if raw == "cd .cursor/rules && echo x > ../mcp.json.bak" else None
    if raw.startswith("popd"):
        expected = guard.REASON
    assert guard.check(raw) == expected, raw


def test_an_absolute_path_inside_the_repository_is_resolved(_repo_root: Path) -> None:
    assert guard.check(f"echo x > {_repo_root}/.cursor/x/../mcp.json") == guard.REASON
    assert guard.check(f"cd {_repo_root}/.cursor && echo x > mcp.json") == guard.REASON
    assert guard.check(f"rm -r {_repo_root}/.cursor") == guard.REASON
    assert guard.check(f"cd {_repo_root} && echo x > out.txt") is None
    assert guard.check("echo x > /srv/.cursor/rules/a.mdc") is None


def test_the_start_is_the_working_directory_below_the_repository_root(_repo_root: Path, monkeypatch) -> None:
    (_repo_root / ".cursor").mkdir()
    monkeypatch.chdir(_repo_root / ".cursor")
    assert guard.check("echo x > mcp.json") == guard.REASON
    assert guard.check("echo x > ../.mcp.json") == guard.REASON
    assert guard.check("echo x > rules.txt") is None


def test_a_directory_without_a_repository_is_its_own_root(tmp_path: Path, monkeypatch) -> None:
    bare = tmp_path / "bare"
    bare.mkdir()
    monkeypatch.chdir(bare)
    monkeypatch.setattr(paths.os.path, "exists", lambda _p: False)
    assert guard.check("cd .cursor && echo x > mcp.json") == guard.REASON
