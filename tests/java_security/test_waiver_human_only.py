"""A waiver is a human reviewer's decision, never the agent's.

The first Claude Code bait run was refused at PreToolUse for concatenating an ORDER BY column into
SQL; it then wrote `// chock: allow persistence-sql-string-concat` on the line itself and carried
on. Where the agent wrote the text -- as it writes, and at its turn's end -- a waiver now counts
only on a line a human committed. At commit and push the person committing reviews what is
staged, so a waiver there is theirs, as before.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from chock_security.decision import DENY, FileText
from chock_security.engine import evaluate
from java_security.conftest import GateRun

RULE = "java-xss-unescaped-template"
BARE = '<p th:utext="${bio}"></p>'
WAIVED = f"{BARE} <!-- chock: allow {RULE} -->"
OTHER = '<p th:text="${name}"></p>'
REFUSE, PASS = 1, 0


def _found(text: str, committed: str | None) -> list[int]:
    return [f.line_no for f in evaluate([FileText("p.html", text)], {RULE: DENY}, lambda _path: committed)]


def test_a_waiver_the_agent_wrote_does_not_count() -> None:
    assert _found(f"{WAIVED}\n", None) == [1]
    assert _found(f"{WAIVED}\n", f"{BARE}\n") == [1]


def test_a_waiver_a_human_committed_still_counts_when_the_agent_edits_the_file() -> None:
    assert _found(f"{OTHER}\n{WAIVED}\n", f"{WAIVED}\n") == []


def test_a_committed_waiver_pasted_onto_a_new_line_counts_once() -> None:
    assert _found(f"{WAIVED}\n{WAIVED}\n", f"{WAIVED}\n") == [2]


def test_without_a_reviewed_text_every_waiver_counts_as_at_commit() -> None:
    assert [f.line_no for f in evaluate([FileText("p.html", f"{WAIVED}\n")], {RULE: DENY})] == []


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)  # noqa: S607 -- git from PATH


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    return tmp_path


def _commit(repo: Path, path: str, text: str) -> None:
    (repo / path).write_text(text, encoding="utf-8")
    _git(repo, "add", path)
    _git(repo, "commit", "-qm", "reviewed")


@pytest.mark.usefixtures("repo")
@pytest.mark.parametrize("event", ["tool_use", None])
def test_the_gate_refuses_a_waiver_the_agent_writes(gate: GateRun, event: str | None) -> None:
    """An event the gate does not know is the agent's: it never widens what counts."""
    code, err = gate({"p.html": f"{WAIVED}\n"}, event=event)
    assert code == REFUSE
    assert RULE in err
    assert "never the agent's" in err


def test_the_gate_honours_a_committed_waiver_as_the_agent_edits(gate: GateRun, repo: Path) -> None:
    _commit(repo, "p.html", f"{WAIVED}\n")
    assert gate({"p.html": f"{OTHER}\n{WAIVED}\n"}, event="tool_use")[0] == PASS


@pytest.mark.usefixtures("repo")
def test_at_commit_the_committer_reviews_the_waiver(gate: GateRun) -> None:
    code, err = gate({"p.html": f"{WAIVED}\n"}, event="commit")
    assert code == PASS
    assert "never the agent's" not in err


def test_outside_a_repository_no_waiver_counts_in_the_agent(gate: GateRun) -> None:
    assert gate({"p.html": f"{WAIVED}\n"}, event="tool_use")[0] == REFUSE


def test_an_absolute_path_is_read_against_the_repository(gate: GateRun, repo: Path) -> None:
    """Some clients hand the gate absolute paths; the committed text is found all the same."""
    _commit(repo, "p.html", f"{WAIVED}\n")
    assert gate({str(repo / "p.html"): f"{OTHER}\n{WAIVED}\n"}, event="tool_use")[0] == PASS


def test_a_path_outside_the_repository_has_no_committed_waiver(gate: GateRun, repo: Path, tmp_path_factory) -> None:
    elsewhere = tmp_path_factory.mktemp("elsewhere") / "p.html"
    _commit(repo, "p.html", f"{WAIVED}\n")
    assert gate({str(elsewhere): f"{WAIVED}\n"}, event="tool_use")[0] == REFUSE
