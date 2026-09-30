"""End to end through chock's runner: an agent's commit honours a waiver only where HEAD already has it."""

from __future__ import annotations

from pathlib import Path

import pytest
from agentic_code_security.conftest import commit
from policies import gatekit, scriptkit

TLS = "comms-tls-verify-disabled"
PATH = "agent/tls.py"
NAME = "agentic-code-security"
PLAIN = "import requests\n\n"
BAD = "requests.get(u, verify=False)"
REFUSE, PASS = 1, 0


def waived(rule: str = TLS) -> str:
    return f"{PLAIN}{BAD}  # chock: allow {rule}\n"


def staged_commit(repo: Path, writes: dict[str, str]) -> tuple[int, str]:
    """The pre-commit verdict on `writes` staged against HEAD."""
    scriptkit.write(repo, writes)
    scriptkit.git(repo, "add", "-A")
    return gatekit.judge(NAME, repo, gatekit.COMMIT)


@pytest.fixture
def as_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CHOCK_AGENT_COMMIT", "AI_AGENT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLAUDECODE", "1")


@pytest.fixture
def as_person(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CHOCK_AGENT_COMMIT", "AI_AGENT", "CLAUDECODE"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.usefixtures("as_agent")
def test_an_agent_commit_refuses_a_waiver_it_adds(tmp_path: Path) -> None:
    commit(tmp_path, {"seed.py": "x = 1\n"})
    code, err = staged_commit(tmp_path, {PATH: waived()})
    assert code == REFUSE
    assert TLS in err
    assert "already in HEAD" in err


@pytest.mark.usefixtures("as_agent")
def test_an_agent_commit_refuses_a_waiver_added_to_an_old_finding(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: f"{PLAIN}{BAD}\n"})
    assert staged_commit(tmp_path, {PATH: waived()})[0] == REFUSE


@pytest.mark.usefixtures("as_agent")
def test_an_agent_commit_honours_a_waiver_a_person_committed(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: waived()})
    assert staged_commit(tmp_path, {PATH: waived() + "x = 1\n"})[0] == PASS


@pytest.mark.usefixtures("as_agent")
def test_an_agent_commit_refuses_a_committed_waiver_pasted_onto_a_new_line(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: waived()})
    twice = waived() + f"requests.post(u, verify=False)  # chock: allow {TLS}\n"
    assert staged_commit(tmp_path, {PATH: twice})[0] == REFUSE


@pytest.mark.usefixtures("as_person")
def test_a_persons_commit_honours_a_waiver_it_adds(tmp_path: Path) -> None:
    commit(tmp_path, {"seed.py": "x = 1\n"})
    assert staged_commit(tmp_path, {PATH: waived()})[0] == PASS
