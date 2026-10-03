"""protect-agent-config: Cline, Kiro, Augment and machine-wide Windsurf hook files, and the user copies of agent files, are protected."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from policies import gatekit, guardkit, scriptkit
from policies.guard_cases_hookfiles import CASED, MACHINE, OPEN, PROJECT, USER

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
gate_script = guardkit.load_guard(POLICY, "protect-agent-config-gate")
pathset = guardkit.load_guard(POLICY, "pathset")
REFUSED = [*PROJECT, *USER, *MACHINE, *CASED]


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    for name in (".git", "src", "docs"):
        (root / name).mkdir(parents=True)
    monkeypatch.chdir(root)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return root


def shell(path: str) -> str:
    """The write of a path as a shell command; a name with a space or a backslash is quoted."""
    return f"echo x > '{path}'" if re.search(r"[ \\]", path) else f"echo x > {path}"


@pytest.mark.parametrize("path", REFUSED)
def test_a_shell_write_to_a_hook_file_is_refused(path: str) -> None:
    assert guard.check(shell(path)) == guard.REASON, path


@pytest.mark.parametrize("path", REFUSED)
def test_the_edit_write_gate_refuses_the_same_file(_repo_root: Path, path: str) -> None:
    assert gate_script.judge(_repo_root, path) == "block", path


@pytest.mark.parametrize("path", REFUSED)
def test_the_verdict_is_block_whatever_tool_asks(path: str) -> None:
    assert pathset.verdict(path) == pathset.BLOCK
    assert guard.hit(path)


@pytest.mark.parametrize("path", OPEN)
def test_a_neighbour_a_look_alike_and_a_path_below_a_folder_of_that_name_stay_open(_repo_root: Path, path: str) -> None:
    assert guard.check(shell(path)) is None, path
    assert gate_script.judge(_repo_root, path) == "", path


@pytest.mark.parametrize(
    "path", [".clinerules/hooks/PreToolUse", "/etc/augment/settings.json", ".kiro/agents/dev.json"]
)
@pytest.mark.parametrize("raw", ["cat {p}", "ls -la {p}", "grep -n x {p}", "git log -p -- {p}"])
def test_reading_a_hook_file_passes(raw: str, path: str) -> None:
    assert guard.check(raw.format(p=path)) is None


@pytest.mark.parametrize(
    "raw",
    [
        "cd .kiro/hooks && echo x > lint.kiro.hook",
        "D=.kiro; echo x > $D/hooks/lint.kiro.hook",
        "rm -rf .kiro",
        "rm .clinerules/hooks/PreToolUse",
        "mv .augment .augment.old",
        "cp a .augment/settings.json",
        "tee .kiro/agents/dev.json",
        "sed -i s/a/b/ .augment/settings.json",
        "bash -c 'echo x > .kiro/hooks/lint.kiro.hook'",
        "echo x > $HOME/Documents/Cline/Hooks/PreToolUse",
        "echo x > ${HOME}/.augment/settings.json",
        "echo x > $HOME/.grok/user-settings.json",
        "cd ~/.codex && echo x > config.toml",
        "echo x | tee /etc/windsurf/hooks.json",
        "sudo tee /etc/augment/settings.json",
        "cp evil.json /etc/windsurf/hooks.json",
        "echo x >> /etc/windsurf/hooks.json",
        "cd /etc/windsurf && echo x > hooks.json",
    ],
)
def test_the_usual_ways_to_write_one_are_refused_too(raw: str) -> None:
    assert guard.check(raw) in (guard.REASON, guard.BLIND), raw


@pytest.mark.parametrize("raw", ["mkdir .kiro", "mkdir -p .clinerules/hooks", "ls .augment"])
def test_the_folder_itself_may_be_made_and_listed(raw: str) -> None:
    assert guard.check(raw) is None


@pytest.mark.parametrize(
    "path", [".kiro/hooks/lint.kiro.hook", "/home/dev/Documents/Cline/Hooks/PreToolUse", "/etc/windsurf/hooks.json"]
)
def test_the_gate_names_the_path_it_refuses(tmp_path: Path, path: str) -> None:
    repo = scriptkit.init_repo(tmp_path / "r", {"src/app.py": "x = 1\n"})
    code, err = gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {path: "new\n"}, {path: "new\n"})
    assert code == 1
    assert f"{path}: forbidden path" in err


def test_a_machine_path_is_read_from_the_start_of_the_path() -> None:
    assert pathset.verdict("/etc/windsurf/hooks.json") == pathset.BLOCK
    assert pathset.verdict("/etc/windsurf/hooks.json.bak") == pathset.BLOCK
    assert pathset.verdict("x/etc/windsurf/hooks.json") == ""
    assert pathset.verdict("/x/etc/windsurf/hooks.json") == ""
    assert pathset.verdict("/etc/windsurf") == ""


def test_the_new_folders_are_entries_of_the_protected_set_and_the_machine_files_are_not() -> None:
    for entry in (".augment/", ".claude-plugin/", ".clinerules/hooks/", ".kiro/hooks/", ".kiro/agents/"):
        assert entry in guard.PROTECTED
    assert not any(e.startswith(("etc/", "/etc/", "library/")) or "programdata" in e for e in guard.PROTECTED)
