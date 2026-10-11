"""ask-credential-switching under CHOCK_CAN_ASK: "0" lets a switch through with a note; anything else asks.

The eval harness unsets CHOCK_CAN_ASK for every case (chock's interpreter_env), so these verdicts are pinned here only.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from policies import guardkit
from policies.test_ask_credential_switching import IMPL, LISTED, POLICY, repo_with

GUARD = guardkit.load_guard(POLICY)
ASK, OK = 3, 0
SWITCHES = (
    "aws s3 ls --profile prod",
    "export AWS_PROFILE=prod",
    "aws sts assume-role --role-arn arn:aws:iam::111122223333:role/admin --role-session-name s",
    "gcloud auth login",
    "az login --identity",
    "kubectl config use-context prod",
    "echo x >> ~/.aws/credentials",
    "aws s3 ls --profile dev && kubectl config use-context prod",
)


def run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command: str, can_ask: str | None) -> int:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CHOCK_RAW_COMMAND", command)
    if can_ask is None:
        monkeypatch.delenv("CHOCK_CAN_ASK", raising=False)
    else:
        monkeypatch.setenv("CHOCK_CAN_ASK", can_ask)
    return GUARD.run([])


@pytest.mark.parametrize("command", SWITCHES)
def test_where_the_client_cannot_prompt_a_switch_is_let_through_with_a_note(
    command: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert run(monkeypatch, tmp_path, command, "0") == OK
    err = capsys.readouterr().err
    assert err.count("\n") == 1
    assert err.startswith("ask-credential-switching: let through, this client cannot prompt here: ")
    assert "CONFIRM" not in err


@pytest.mark.parametrize("can_ask", [None, "1", "", "yes", "false", "00", " 0"])
@pytest.mark.parametrize("command", SWITCHES)
def test_unset_or_any_other_value_asks(
    command: str,
    can_ask: str | None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    assert run(monkeypatch, tmp_path, command, can_ask) == ASK
    assert capsys.readouterr().err.startswith("CONFIRM: ")


def test_the_note_names_what_was_let_through_and_not_what_is_listed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    root = repo_with(tmp_path, json.dumps(LISTED))
    assert run(monkeypatch, root, "aws s3 ls --profile dev; kubectl config use-context prod", "0") == OK
    err = capsys.readouterr().err
    assert "Kubernetes context prod" in err
    assert "profile dev" not in err


@pytest.mark.parametrize("can_ask", ["0", "1", None])
@pytest.mark.parametrize("command", ["aws s3 ls --profile dev", "kubectl config use-context kind-dev", "aws s3 ls"])
def test_a_listed_identity_or_no_switch_stays_silent(
    command: str,
    can_ask: str | None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    root = repo_with(tmp_path, json.dumps(LISTED))
    assert run(monkeypatch, root, command, can_ask) == OK
    assert capsys.readouterr().err == ""


def test_a_fault_is_still_a_fault_where_the_client_cannot_prompt(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def boom(*_args: object) -> None:
        raise ValueError

    monkeypatch.setattr(GUARD, "unlisted", boom)
    assert run(monkeypatch, tmp_path, "aws s3 ls --profile prod", "0") == 2
    assert "internal error (ValueError)" in capsys.readouterr().err


@pytest.mark.parametrize(("can_ask", "want"), [("0", OK), ("1", ASK), (None, ASK)])
def test_run_as_a_script_the_env_decides(can_ask: str | None, want: int, tmp_path: Path) -> None:
    """The dispatcher starts the file itself with CHOCK_CAN_ASK set per wire event; "0" never exits 3."""
    env = {k: v for k, v in os.environ.items() if k != "CHOCK_CAN_ASK"}
    env |= {"CHOCK_RAW_COMMAND": "aws s3 ls --profile prod", **({} if can_ask is None else {"CHOCK_CAN_ASK": can_ask})}
    done = subprocess.run(
        [sys.executable, str(IMPL / f"{POLICY}.py")], env=env, capture_output=True, text=True, check=False, cwd=tmp_path
    )
    assert done.returncode == want
    assert done.stderr.startswith("ask-credential-switching: let through" if want == OK else "CONFIRM: ")
