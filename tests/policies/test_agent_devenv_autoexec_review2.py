"""agent-devenv-autoexec: the second review's findings (regex time, waivers in values, mounts, spawns), pinned."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from policies import scriptkit
from policies.devenvkit import as_json, found, gate, rules

B, A = "block", "ask"
DC = ".devcontainer/devcontainer.json"
scan = gate.sys.modules["devenv.scan"]


def task(command: str) -> str:
    return as_json({"tasks": [{"label": "a", "command": command}]})


@pytest.mark.parametrize("command", ["echo " + "${a}/" * 40 + "!", "a" * 40000, "x/" * 4000])
def test_path_scan_is_linear(command: str) -> None:
    started = time.monotonic()
    found({".vscode/tasks.json": task(command)})
    assert time.monotonic() - started < 5


def test_paths_in() -> None:
    assert scan.paths_in('bash "$CLAUDE_PROJECT_DIR"/.claude/x.sh ${HOME}/a ./b/c ../d/e /abs/f g') == [
        ".claude/x.sh",
        "b/c",
        "d/e",
    ]
    assert scan.paths_in("x" * 9000 + "/y") == []


@pytest.mark.parametrize(
    ("path", "text"),
    [
        (".cursor/hooks.json", as_json({"hooks": {"stop": [{"command": "./x.sh # chock: allow dev-claude-hooks"}]}})),
        ("mise.toml", "[tasks.a]\nrun = 'echo hi # chock: allow dev-shell-toolchain'\n"),
        ("lefthook.yml", 'pre-commit:\n  commands:\n    a:\n      run: "id # chock: allow dev-hook-launchers"\n'),
        (".envrc", "echo hi ;chock: allow dev-shell-toolchain\n"),
    ],
)
def test_a_waiver_inside_a_value_never_counts_even_for_a_person(path: str, text: str) -> None:
    assert found({path: text}, event="tool_use", root=None) and found({path: text}, event="ci")


def test_a_real_comment_waiver_still_counts_for_a_person(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in ("CHOCK_AGENT_COMMIT", "CLAUDECODE", "AI_AGENT"):
        monkeypatch.delenv(name, raising=False)
    assert found({".envrc": "echo hi  # chock: allow dev-shell-toolchain\n"}, event="push") == []
    config = "[core]\n; chock: allow dev-gitconfig-exec\n\tpager = less\n"
    repo = scriptkit.init_repo(tmp_path / "r", {".gitconfig": config})
    assert found({".gitconfig": config}, event="push", root=repo) == []


@pytest.mark.parametrize(
    "run_args",
    [
        ["-v", "${localEnv:HOME}/.ssh:/root/.ssh"],
        ["--volume=${localEnv:HOME}/.docker:/d"],
        ["--privileged=1"],
        ["--volumes-from", "other"],
        ["-v", "/var:/h"],
        ["-v", "/Users/me:/h"],
        ["-v", "C:\\:/h"],
    ],
)
def test_more_run_args(run_args: list) -> None:
    assert rules(DC, as_json({"runArgs": run_args})) == [("dev-devcontainer-init", B)]


@pytest.mark.parametrize(
    "mount",
    ["source=${localEnv:HOME}${localEnv:USERPROFILE},target=/h,type=bind", 'source="/",target=/h,type=bind'],
)
def test_more_mounts(mount: str) -> None:
    assert rules(DC, as_json({"mounts": [mount]})) == [("dev-devcontainer-init", B)]


@pytest.mark.parametrize(
    "text",
    [
        'claude -p "a; b" --dangerously-skip-permissions\n',
        "claude -p hi \\\n  --dangerously-skip-permissions\n",
        "claude -p " + "x" * 2000 + " --dangerously-skip-permissions\n",
        "codex -c approval_policy=never exec hi\n",
        "codex --config 'sandbox_mode=\"danger-full-access\"' exec hi\n",
        "claude -p hi \\\r\n  --yolo\r\n",
        "claude --yolo \\",
    ],
)
def test_more_spawn_forms(text: str) -> None:
    assert rules("run.sh", text) == [("dev-agent-spawn", B)]


def test_spawn_is_linear_and_quoted_mentions_stay_quiet() -> None:
    started = time.monotonic()
    rules("run.sh", "gemini " * 150000 + "\n")
    assert time.monotonic() - started < 5
    assert rules("run.sh", "echo 'see docs' | claude -p hi\n") == []


@pytest.mark.parametrize("setting", [{"python.testing.pytestPath": "./x"}, {"python.testing.unittestPath": "./x"}])
def test_test_runner_paths_are_programs(setting: dict) -> None:
    assert rules(".vscode/settings.json", as_json(setting)) == [("dev-exec-path-settings", B)]


@pytest.mark.parametrize(("pattern", "severity"), [("/./", B), ("/.?/", B), ("/(/", B), ("/^npm test$/", A)])
def test_terminal_catch_all_patterns(pattern: str, severity: str) -> None:
    setting = {"chat.tools.terminal.autoApprove": {pattern: True}}
    assert rules(".vscode/settings.json", as_json(setting)) == [("dev-vscode-autoapprove", severity)]


def test_service_host_names_are_not_overrides() -> None:
    assert rules("mise.toml", "[env]\nDB_HOST = 'db'\nREDIS_HOST = 'r'\nDOCKER_HOST = 'tcp://x:2375'\n") == [
        ("dev-shell-toolchain", B)
    ]


def test_round3_quote_scans_are_linear() -> None:
    started = time.monotonic()
    rules("run.sh", '"\\' * 200000 + "\n")
    found({".envrc": '"\\' * 200000 + " # chock: allow dev-shell-toolchain\n"}, event="push")
    assert time.monotonic() - started < 5


def test_round3_waiver_on_a_multi_line_string_does_not_count() -> None:
    text = '[tasks.a]\nrun = """./x.sh # chock: allow dev-shell-toolchain\n"""\n'
    assert found({"mise.toml": text}, event="push")


@pytest.mark.parametrize(
    "text",
    [
        "claude -p hi 2>&1 --dangerously-skip-permissions\n",
        "claude -p hi &>/dev/null --yolo\n",
        'claude -p "a\nb" --dangerously-skip-permissions\n',
        "//usr/bin/claude --dangerously-skip-permissions\n",
        "env AGENT=claude gemini -y\n",
        "claude --permission-mode\tbypassPermissions\n",
        "claude --allow-dangerously-skip-permissions\n",
        "claude -p 'say \\' --yolo\n",
    ],
)
def test_round3_spawn_forms(text: str) -> None:
    assert rules("run.sh", text) == [("dev-agent-spawn", B)]


def test_round3_statement_reader() -> None:
    statements = gate.sys.modules["devenv.spawn"].statements
    text = 'a "x;\\"y" 2>&1 b # c ; d\r\ne \\\n f; g < &h\n"open'
    assert statements(text) == [(1, 'a x "y 2>&1 b '), (2, "e   f"), (3, " g < "), (3, "h"), (4, "open")]
    assert rules("run.sh", "cl\\aude --yolo\n") == [("dev-agent-spawn", B)]
    assert rules("run.sh", "# claude --yolo\necho claude; echo --yolo\n") == []


def test_round3_doubled_and_back_separators_in_paths() -> None:
    assert scan.paths_in("sh tools//c.sh tools\\d.sh") == ["tools/c.sh", "tools/d.sh"]
