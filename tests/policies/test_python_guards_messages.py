"""The Python command guards: a message file the guard reads, and the refusal that names the override it will not take."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies.test_python_guards import BLOCK, OK, assert_case, verdict


@pytest.mark.parametrize(
    ("flag", "text", "want"),
    [
        ("--file=msg.txt", "Per the conversation, do it\n", BLOCK),
        ("--body-file=msg.txt", "Session summary: x\n", BLOCK),
        ("-Fmsg.txt", "the user asked for it\n", BLOCK),
        ("--file=msg.txt", "Retry on 503\n", OK),
        ("-Fmsg.txt", "Retry on 503\n", OK),
    ],
)
def test_a_message_file_is_read_when_it_exists(
    flag: str, text: str, want: int, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.chdir(tmp_path)
    (tmp_path / "msg.txt").write_text(text, encoding="utf-8")
    command = f"gh pr create --title x {flag}"
    assert_case("protect-commit-privacy", command, want, capsys)
    if flag.startswith("-F"):
        assert_case("protect-commit-privacy", f"git commit {flag}", want, capsys)
    monkeypatch.undo()


@pytest.mark.parametrize(
    ("command", "name"),
    [
        ("CHOCK_ALLOW=x git push", "CHOCK_ALLOW"),
        ("export CHOCK_AGENT_COMMIT=0", "CHOCK_AGENT_COMMIT"),
        ("$env:CHOCK_ALLOW='x'", "CHOCK_ALLOW"),
        ("unset CLAUDECODE", "CLAUDECODE"),
        ("env -u AI_AGENT git commit", "AI_AGENT"),
        ("env -i git commit", "CLAUDECODE/AI_AGENT"),
    ],
)
def test_an_override_refusal_tells_the_agent_to_ask_the_person(
    command: str, name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code, err = verdict("block-no-verify", command, capsys)
    assert code == BLOCK
    assert "ask the person to run the command themselves" in err
    assert name in err
