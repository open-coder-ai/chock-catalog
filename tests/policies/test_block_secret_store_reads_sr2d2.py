"""block-secret-store-reads: echo, printf, print and Write-Output of a secret-named variable ask like printenv."""

from __future__ import annotations

import shlex

import pytest
from policies import guardkit

POLICY = "block-secret-store-reads"
guard = guardkit.load_guard(POLICY)
ASK, OK = 3, 0


def code(command: str, monkeypatch: pytest.MonkeyPatch) -> int:
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()
    monkeypatch.setenv("CHOCK_RAW_COMMAND", command)
    return guard.run(argv)


@pytest.mark.parametrize(
    "command",
    [
        'echo "$GITHUB_TOKEN"',
        "echo $GITHUB_TOKEN",
        "echo ${AWS_SECRET_ACCESS_KEY}",
        "echo -n $NPM_TOKEN",
        'printf %s "$AWS_SECRET_ACCESS_KEY"',
        'printf "%s\\n" "${DB_PASSWORD:-}"',
        "print $API_KEY",
        'Write-Output "$env:GITHUB_TOKEN"',
        "Write-Output $env:GITHUB_TOKEN",
        "write-output ${env:GITHUB_TOKEN}",
        "sudo echo $GITHUB_TOKEN",
        "true && echo $GITHUB_TOKEN",
        "bash -c 'echo $GITHUB_TOKEN'",
        'echo "token is $GITHUB_TOKEN"',
    ],
)
def test_printing_a_secret_named_variable_asks(command: str, monkeypatch: pytest.MonkeyPatch) -> None:
    assert code(command, monkeypatch) == ASK


@pytest.mark.parametrize(
    "command",
    [
        "echo $HOME",
        'echo "$PATH"',
        "echo GITHUB_TOKEN",
        "echo hello",
        'printf "%s" "$USER"',
        'Write-Output "$env:HOME"',
    ],
)
def test_other_prints_are_left_alone(command: str, monkeypatch: pytest.MonkeyPatch) -> None:
    assert code(command, monkeypatch) == OK
