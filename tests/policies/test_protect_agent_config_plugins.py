"""protect-agent-config: Claude Code plugin roots (`.claude-plugin/`) protect their hooks folder; a shell cannot point Claude Code at a plugin folder."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from policies import gatekit, guardkit, scriptkit
from policies.guard_cases_plugins import ALLOWED, FILES, REFUSED, ROOTS

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
gate_script = guardkit.load_guard(POLICY, "protect-agent-config-gate")
pathset = guardkit.load_guard(POLICY, "pathset")
plugin = guardkit.load_guard(POLICY, "pathplugin")
load = guardkit.load_guard(POLICY, "pathload")


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    for name in (".git", "src", "docs", "mods/other", "mods/q", "app"):
        (root / name).mkdir(parents=True)
    scriptkit.write(root, {**dict.fromkeys(ROOTS, "{}\n"), **FILES})
    monkeypatch.chdir(root)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return root


@pytest.mark.parametrize("raw", REFUSED)
def test_a_write_in_a_plugin_roots_hooks_folder_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize("raw", ALLOWED)
def test_a_hooks_folder_anywhere_else_stays_open(raw: str) -> None:
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize("raw", [r for r in REFUSED if r.startswith("echo x > ") and "*" not in r and "$" not in r])
def test_the_edit_write_gate_agrees_with_the_shell_guard(_repo_root: Path, raw: str) -> None:
    path = raw.removeprefix("echo x > ")
    assert gate_script.judge(_repo_root, path) == "block", path


@pytest.mark.parametrize("raw", [r for r in ALLOWED if r.startswith("echo x > ")])
def test_the_edit_write_gate_leaves_an_ordinary_hooks_folder_open(_repo_root: Path, raw: str) -> None:
    assert gate_script.judge(_repo_root, raw.removeprefix("echo x > ")) == ""


def test_a_plugin_at_the_repository_root_protects_its_hooks_folder(_repo_root: Path) -> None:
    assert gate_script.judge(_repo_root, "hooks/hooks.json") == ""
    scriptkit.write(_repo_root, {".claude-plugin/plugin.json": "{}\n"})
    assert gate_script.judge(_repo_root, "hooks/hooks.json") == "block"
    assert gate_script.judge(_repo_root, "src/hooks/useThing.ts") == ""
    assert guard.check("echo x > hooks/register.ts") == guard.REASON
    assert guard.check("echo x > src/hooks/useThing.ts") is None


def test_the_absolute_path_the_tool_names_is_read_from_the_repository(_repo_root: Path) -> None:
    assert gate_script.judge(_repo_root, f"{_repo_root}/mods/p/hooks/register.ts") == "block"
    assert gate_script.judge(_repo_root, f"{_repo_root}/src/hooks/useThing.ts") == ""
    code, err = gatekit.judge(POLICY, _repo_root, gatekit.PRE_TOOL_USE, {"mods/p/hooks/register.ts": "x\n"})
    assert code == 1
    assert "mods/p/hooks/register.ts: forbidden path" in err


def test_a_plugin_folder_outside_the_repository_is_found_from_the_root_of_the_path(tmp_path: Path) -> None:
    other = tmp_path / "elsewhere" / "p"
    scriptkit.write(tmp_path / "elsewhere", {"p/.claude-plugin/plugin.json": "{}\n", "q/hooks/a.ts": "x\n"})
    assert pathset.verdict(f"{other}/hooks/register.ts") == pathset.BLOCK
    assert pathset.verdict(f"{tmp_path}/elsewhere/q/hooks/register.ts") == ""
    assert guard.check(f"echo x > {other}/hooks/register.ts") == guard.REASON


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_link_to_a_plugins_hooks_folder_is_the_same_folder(_repo_root: Path) -> None:
    (_repo_root / "src/linked").symlink_to(_repo_root / "mods/p/hooks")
    (_repo_root / "src/plug").symlink_to(_repo_root / "mods/p")
    assert guard.check("echo x > src/linked/a.ts") == guard.REASON
    assert guard.check("echo x > src/plug/hooks/a.ts") == guard.REASON
    assert gate_script.judge(_repo_root, "src/linked/a.ts") == "block"
    assert gate_script.judge(_repo_root, "src/plug/hooks/a.ts") == "block"
    assert gate_script.judge(_repo_root, "src/plug/commands/a.md") == ""


def test_the_repository_folder_is_the_one_holding_git_from_where_the_hook_runs(
    _repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert plugin.repo_root() == str(_repo_root)
    monkeypatch.chdir(_repo_root / "src")
    assert plugin.repo_root() == str(_repo_root)
    monkeypatch.setenv("CHOCK_HOOK_CWD", str(_repo_root / "mods/p"))
    assert plugin.repo_root() == str(_repo_root)
    monkeypatch.setattr(plugin.os.path, "exists", lambda _p: False)
    assert plugin.repo_root() == str(_repo_root / "mods/p")


def test_a_path_is_looked_up_one_folder_at_a_time_and_a_missing_one_ends_it(_repo_root: Path) -> None:
    assert plugin.plugin_hooks("mods/p/hooks/x", str(_repo_root))
    assert plugin.plugin_hooks("mods/p/hooks/x")
    assert not plugin.plugin_hooks("mods/p/commands/x", str(_repo_root))
    assert not plugin.plugin_hooks("src/hooks/useThing.ts", str(_repo_root))
    assert not plugin.plugin_hooks("src/hooks/nothing.ts", str(_repo_root))
    assert not plugin.plugin_hooks("app/hooks/x", str(_repo_root))
    assert not plugin.plugin_hooks("missing/hooks/x", str(_repo_root))
    assert not plugin.plugin_hooks("mods/p/hooks/x", str(_repo_root / "missing"))


def test_a_folder_that_cannot_be_listed_is_not_a_plugin_root(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(_path: str) -> list[str]:
        raise PermissionError

    monkeypatch.setattr(plugin.os, "listdir", refuse)
    assert not plugin.plugin_hooks("mods/p/hooks/x")


LOADED = [
    "export CLAUDE_CODE_PLUGIN_DIRS=./mods",
    "CLAUDE_CODE_PLUGIN_DIRS=./mods claude -p hi",
    "CLAUDE_CODE_PLUGIN_DIRS=./mods",
    "CLAUDE_CODE_PLUGIN_DIRS=$PWD/mods:$PWD/more claude",
    "CLAUDE_CODE_PLUGIN_DIRS+=:./more",
    "claude_code_plugin_dirs=./mods claude",
    "env CLAUDE_CODE_PLUGIN_DIRS=./mods claude",
    "declare -x CLAUDE_CODE_PLUGIN_DIRS=./mods",
    "cd src && export CLAUDE_CODE_PLUGIN_DIRS=../mods && claude",
    "sudo -u dev CLAUDE_CODE_PLUGIN_DIRS=./mods claude",
    "bash -c 'CLAUDE_CODE_PLUGIN_DIRS=./mods claude'",
    "bash -c 'export CLAUDE_CODE_PLUGIN_DIRS=./mods; claude'",
    "claude --plugin-dir ./mods",
    "claude --plugin-dir=./mods",
    "claude -p hi --plugin-dir ./mods --plugin-dir ./more",
    "claude.exe --plugin-dir mods",
    "/usr/local/bin/claude --plugin-dir ./mods",
    "nohup claude --plugin-dir ./mods &",
    "command claude --plugin-dir ./mods",
    "timeout 60 claude --plugin-dir ./mods",
    "bash -c 'claude --plugin-dir ./mods'",
    'sh -c "cd src && claude --plugin-dir ../mods"',
    "npx @anthropic-ai/claude-code --plugin-dir ./mods",
    "$env:CLAUDE_CODE_PLUGIN_DIRS = 'mods'",
    "$env:CLAUDE_CODE_PLUGIN_DIRS='mods'; claude",
    "$env:CLAUDE_CODE_PLUGIN_DIRS += ';more'",
    "setx CLAUDE_CODE_PLUGIN_DIRS mods",
    "set CLAUDE_CODE_PLUGIN_DIRS=mods",
    "Set-Item -Path Env:CLAUDE_CODE_PLUGIN_DIRS -Value mods",
    "Set-Item Env:CLAUDE_CODE_PLUGIN_DIRS mods",
    "[Environment]::SetEnvironmentVariable('CLAUDE_CODE_PLUGIN_DIRS', 'mods', 'User')",
]
KEPT = [
    "echo $CLAUDE_CODE_PLUGIN_DIRS",
    'echo "$CLAUDE_CODE_PLUGIN_DIRS"',
    "env | grep CLAUDE_CODE_PLUGIN_DIRS",
    "export CLAUDE_CODE_PLUGIN_DIRS",
    "unset CLAUDE_CODE_PLUGIN_DIRS",
    "env -u CLAUDE_CODE_PLUGIN_DIRS claude",
    "claude -p hi",
    "claude",
    "claude --help",
    "claude plugin list",
    "mytool --plugin-dir ./mods",
    "eslint --plugin-dir ./rules src",
    "git commit -m 'document claude --plugin-dir'",
    "git commit -m 'set CLAUDE_CODE_PLUGIN_DIRS=x for mods'",
    "echo claude --plugin-dir ./mods",
    "grep -rn CLAUDE_CODE_PLUGIN_DIRS docs",
    "echo $env:CLAUDE_CODE_PLUGIN_DIRS",
    "$env:CLAUDE_CODE_PLUGIN_DIRS",
    "Get-Item Env:CLAUDE_CODE_PLUGIN_DIRS",
    "echo $env:PATH",
    "OTHER=1 claude -p hi",
    "ls",
]


@pytest.mark.parametrize("raw", LOADED)
def test_a_command_that_points_claude_code_at_a_plugin_folder_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.LOADS, raw
    assert load.loads_plugin(raw)


@pytest.mark.parametrize("raw", KEPT)
def test_reading_the_variable_or_naming_the_flag_in_text_is_not_loading(raw: str) -> None:
    assert guard.check(raw) is None, raw
    assert not load.loads_plugin(raw)


def test_the_refusal_says_why_and_exits_with_a_block(capsys: pytest.CaptureFixture[str]) -> None:
    assert guard.run(["claude", "--plugin-dir", "./mods"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("BLOCKED: shell command makes Claude Code load a plugin")
    assert "above the project's own gates" in err


def test_a_write_to_a_protected_path_is_still_reported_as_a_write() -> None:
    assert guard.check("CLAUDE_CODE_PLUGIN_DIRS=x claude; echo x > .claude/settings.json") == guard.REASON
    assert guard.check("CLAUDE_CODE_PLUGIN_DIRS=x claude; echo x > src/a.txt") == guard.LOADS
