"""block-unguarded-agent-spawn: a bare command-running, writing or network tool name in --allowedTools is a wildcard grant."""

from __future__ import annotations

import shlex

import pytest
from policies import guardkit

guard = guardkit.load_guard("block-unguarded-agent-spawn")
BLOCK, OK = 1, 0


def code(command: str, monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setenv("CHOCK_RAW_COMMAND", command)
    return guard.run(shlex.split(command))


@pytest.mark.parametrize(
    "command",
    [
        "claude -p task --allowedTools Bash",
        "claude -p task --allowedTools=Edit",
        "claude -p task --allowed-tools Write",
        "claude -p task --allowedTools 'Read,MultiEdit'",
        "claude -p task --allowedTools 'Read NotebookEdit'",
        "claude -p task --allowedTools WebFetch",
        "claude -p task --allowedTools mcp__github",
        "claude -p task --allowedTools 'Read,mcp__github__create_issue'",
    ],
)
def test_a_bare_tool_name_is_a_wildcard_grant(command: str, monkeypatch: pytest.MonkeyPatch) -> None:
    assert code(command, monkeypatch) == BLOCK


@pytest.mark.parametrize(
    "command",
    [
        "claude -p task --allowedTools Read",
        "claude -p task --allowedTools 'Read,Grep,Glob'",
        "claude -p task --allowedTools 'Bash(git status)'",
        "claude -p task --allowedTools 'Bash(git:*)'",
        "claude -p task --allowedTools 'Edit(src/a.py)'",
    ],
)
def test_narrow_grants_are_left_alone(command: str, monkeypatch: pytest.MonkeyPatch) -> None:
    assert code(command, monkeypatch) == OK
