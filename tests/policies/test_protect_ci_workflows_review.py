"""protect-ci-workflows: the hardening review's Edit/Write and commit cases (REVIEW-infra.md section 5)."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from policies import gatekit, scriptkit

POLICY = "protect-ci-workflows"
WORKFLOW = ".github/workflows/ci.yml"

# id -> (path, caught): the Edit/Write cases. Five drive CI indirectly and are out of scope (declared).
EDITS = {
    "E01": (WORKFLOW, True),
    "E01v": (".github/workflows/reusable.yml", True),
    "E02": (WORKFLOW, True),
    "E02v": (".github/actions/setup/action.yml", True),
    "E03": (WORKFLOW, True),
    "E03v": (WORKFLOW, True),
    "E04": (WORKFLOW, True),
    "E04v": (WORKFLOW, True),
    "E05": (WORKFLOW, True),
    "E05v": ("pyproject.toml", False),
    "E06": (".gitlab-ci.yml", True),
    "E06v": (".circleci/config.yml", True),
    "E07": (".github/CODEOWNERS", True),
    "E07v": ("docs/CODEOWNERS", True),
    "E08": (".pre-commit-config.yaml", True),
    "E08v": (".husky/pre-commit", True),
    "E09": ("Makefile", False),
    "E09v": ("package.json", False),
    "E10": ("codecov.yml", False),
    "E10v": (".github/zizmor.yml", False),
    "E11": (WORKFLOW, True),
}
# Correct work the gate asks about by design (disclosed): fixture, non-GitHub action.yml, README, vendored copy, template.
CORRECT_WRITES = {
    "Z01": ("docs/ci.md", False),
    "Z02": ("src/workflows/engine.py", False),
    "Z03": (".github/ISSUE_TEMPLATE/bug.md", False),
    "Z04": ("tests/fixtures/repo/.github/workflows/sample.yml", True),
    "Z05": ("bot/action.yml", True),
    "Z06": (".github/workflows/README.md", True),
    "Z07": ("docs/Jenkinsfile-notes.txt", False),
    "Z08": ("src/actions/index.ts", False),
    "Z09": ("third_party/lib/.github/workflows/ci.yml", True),
    "Z10": (".github/FUNDING.yml", False),
    "Z11": ("docs/renovate.md", False),
    "Z12": (".gitlab/merge_request_templates/default.md", True),
    "Z13": ("tests/test_ci_workflow.py", False),
}
CAUGHT_EDITS = [case for case, (_, caught) in EDITS.items() if caught]
UNCAUGHT_EDITS = [case for case, (_, caught) in EDITS.items() if not caught]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {WORKFLOW: "on: push\n", "src/app.py": "x = 1\n"})


@pytest.fixture
def agent(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate judges this commit as an agent's, as the test process's own environment says."""
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.delenv("CHOCK_AGENT_COMMIT", raising=False)


@pytest.fixture
def person(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CLAUDECODE", "AI_AGENT", "CHOCK_AGENT_COMMIT"):
        monkeypatch.delenv(name, raising=False)


def committed(repo: Path, path: str) -> tuple[int, str]:
    """Stage a change to `path` and judge the commit through the runner."""
    scriptkit.write(repo, {path: "changed\n"})
    scriptkit.git(repo, "add", "-A")
    return gatekit.judge(POLICY, repo, gatekit.COMMIT)


@pytest.mark.usefixtures("agent")
@pytest.mark.parametrize("case", CAUGHT_EDITS)
def test_an_agents_commit_of_a_protected_path_asks(repo: Path, case: str) -> None:
    code, err = committed(repo, EDITS[case][0])
    assert code == 1, case
    assert EDITS[case][0] in err


@pytest.mark.usefixtures("agent")
@pytest.mark.parametrize("case", UNCAUGHT_EDITS)
def test_an_agents_commit_of_a_file_that_drives_ci_indirectly_is_not_judged(repo: Path, case: str) -> None:
    assert committed(repo, EDITS[case][0]) == (0, "")


@pytest.mark.usefixtures("person")
@pytest.mark.parametrize("case", [*CAUGHT_EDITS, *UNCAUGHT_EDITS])
def test_a_persons_commit_is_not_judged(repo: Path, case: str) -> None:
    assert committed(repo, EDITS[case][0]) == (0, "")


@pytest.mark.parametrize("case", CAUGHT_EDITS)
def test_the_write_before_it_lands_still_asks(repo: Path, case: str) -> None:
    path = EDITS[case][0]
    code, err = gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {path: "new\n"}, {path: "new\n"})
    assert code == 3, case
    assert path in err


@pytest.mark.parametrize("case", CAUGHT_EDITS)
def test_the_turns_end_still_warns(repo: Path, case: str) -> None:
    path = EDITS[case][0]
    scriptkit.write(repo, {path: "changed\n"})
    code, err = gatekit.judge(POLICY, repo, gatekit.STOP, {path: "changed\n"})
    assert code == 4, case
    assert path in err


@pytest.mark.usefixtures("agent")
@pytest.mark.parametrize("case", sorted(CORRECT_WRITES))
def test_correct_writes_are_asked_as_before_at_the_write_and_at_an_agents_commit(repo: Path, case: str) -> None:
    path, asked = CORRECT_WRITES[case]
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {path: "x\n"}, {path: "x\n"})[0] == (3 if asked else 0)
    assert committed(repo, path)[0] == (1 if asked else 0)


GATE = scriptkit.load(POLICY, "protect-ci-workflows-gate.py")


@pytest.mark.parametrize("stdin", ["", "not json", "[]", '{"writes": 3}', '{"event": "tool_use", "writes": null}'])
def test_a_gate_input_it_cannot_read_is_a_fault_not_an_allow(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], stdin: str
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    assert GATE.main() == 2
    assert "not the gate JSON" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("event", "code"), [("tool_use", 3), ("agent-commit", 3), ("commit", 0), ("ci", 0), ("push", 0)]
)
def test_the_gate_asks_only_at_the_events_an_agent_acts_at(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], event: str, code: int
) -> None:
    payload = json.dumps({"event": event, "writes": {WORKFLOW: "x\n", "src/app.py": "x\n"}})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    assert GATE.main() == code
    err = capsys.readouterr().err
    assert (WORKFLOW in err) == (code == 3)
    assert "src/app.py" not in err


def test_the_gate_runs_as_a_process_and_asks_with_its_words_on_stderr(repo: Path) -> None:
    payload = json.dumps({"event": "agent-commit", "writes": {WORKFLOW: "x\n"}})
    code, err = scriptkit.run_script(POLICY, "protect-ci-workflows-gate.py", repo, payload)
    assert code == 3
    assert err.startswith(f"{WORKFLOW}: CI, hook or bot configuration")
    assert scriptkit.run_script(POLICY, "protect-ci-workflows-gate.py", repo, "not json")[0] == 2


def test_a_control_character_in_a_file_name_does_not_reach_the_terminal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = json.dumps({"event": "tool_use", "writes": {".github/workflows/a\x1b[31m.yml": "x\n"}})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    assert GATE.main() == 3
    assert "\x1b" not in capsys.readouterr().err


@pytest.mark.usefixtures("agent")
def test_an_agents_commit_of_an_ordinary_file_passes(repo: Path) -> None:
    assert committed(repo, "src/app.py") == (0, "")
