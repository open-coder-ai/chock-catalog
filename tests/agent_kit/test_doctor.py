"""The doctor proves the gate is wired before a scenario is spent; the first Windows run needed it.

There, a global `bin/` ignore kept `.chock/bin/` out of the workspace's baseline, the first reset
lost it, and every hook Claude Code ran was missing -- the agent declined the SQL on its own, and
nothing said the gate had never run.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import doctor
import grading
import kit
import pytest
from workspace import BASELINE, git

needs_chock = pytest.mark.skipif(shutil.which("chock") is None, reason="the repo route installs with chock")


def _setup(tmp_path: Path, agent: str = "claude", route: str = "repo", name: str = "shop") -> Path:
    workspace = tmp_path / name
    kit.main(["setup", "--dir", str(workspace), "--agent", agent, "--route", route])
    return workspace


def _lose_bin(workspace: Path) -> None:
    """The Windows state: .chock/bin/ never in the baseline, and gone from disk."""
    git(workspace, "rm", "-rq", "--cached", ".chock/bin")
    git(workspace, "commit", "-qm", "as a global bin/ ignore left it", "--no-verify")
    git(workspace, "tag", "-f", BASELINE)
    shutil.rmtree(workspace / ".chock" / "bin")


@needs_chock
def test_a_wired_claude_workspace_passes_every_check(tmp_path: Path, capsys) -> None:
    workspace = _setup(tmp_path)
    kit.main(["doctor", "--dir", str(workspace)])
    out = capsys.readouterr().out
    assert "FAIL" not in out
    assert "denies the construct, allows the fix" in out
    assert git(workspace, "status", "--porcelain").stdout == ""  # the probes leave the tree as they found it


@needs_chock
def test_hooks_naming_missing_files_are_caught_and_block_start(tmp_path: Path, capsys) -> None:
    workspace = _setup(tmp_path)
    _lose_bin(workspace)
    with pytest.raises(SystemExit, match="gate is not wired"):
        kit.main(["doctor", "--dir", str(workspace)])
    assert "missing ['.chock/bin/claude_code.py']" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="name files that are not there"):
        kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])


@needs_chock
def test_setup_commits_chocks_files_even_under_a_global_bin_ignore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ignore = tmp_path / "global-ignore"
    ignore.write_text("bin/\n", encoding="utf-8")
    config = tmp_path / "gitconfig"
    config.write_text(f"[core]\n\texcludesFile = {ignore}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    workspace = _setup(tmp_path)
    assert ".chock/bin/claude_code.py" in git(workspace, "ls-files", ".chock/bin").stdout
    kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])
    assert (workspace / ".chock" / "bin" / "claude_code.py").is_file()


def test_the_plugin_route_is_not_second_guessed(tmp_path: Path, capsys) -> None:
    workspace = _setup(tmp_path, route="plugin")
    kit.main(["doctor", "--dir", str(workspace)])
    assert "plugin route" in capsys.readouterr().out


def test_hook_files_are_read_off_a_windows_command(tmp_path: Path) -> None:
    command = '"C:\\\\Python314\\\\python.exe" "${CLAUDE_PROJECT_DIR}/.chock/bin/claude_code.py" --gate "${CLAUDE_PROJECT_DIR}/.chock/compiled/java-security/pre-tool-use/gate.json"'
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command": command}]}]}}), encoding="utf-8")
    assert doctor.missing_hook_files(tmp_path, "claude") == [
        ".chock/bin/claude_code.py",
        ".chock/compiled/java-security/pre-tool-use/gate.json",
    ]


def test_an_agent_that_declines_is_not_a_gate_failure_nor_gate_evidence() -> None:
    item = kit.scenario("smoke-sql-direct")
    graded = grading.grade(item, [], "silent", None)
    assert (graded["verdict"], graded["declined"], graded["gate_ok"]) == ("pass", True, None)
    assert "agent declined, gate not exercised" in grading.cell({**graded, "gate_seen": "silent"})
    wrote_it = [{"rule": "persistence-sql-string-concat", "path": "R.java", "line": 3, "cwe": []}]
    assert grading.grade(item, wrote_it, "silent", None)["verdict"] == "fail"
