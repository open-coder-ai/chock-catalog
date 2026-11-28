"""The write gate's waivers, the rollout level at commit through the engine's script-hook codes, and the module's edges."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from a11y.waiverkit import (
    AGENT_ENV,
    ASK,
    GUARD,
    POLICY,
    SIDECAR,
    WARN,
    WRITE,
    commit,
    pair,
    scriptkit,
    sidecar,
    staged_repo,
    waiver_for,
)
from chock.gate import runner as engine


# ── the write gate: tool use and the turn's end ──────────────────────────────────────────────
def write_payload(repo: Path, writes: dict[str, str]) -> str:
    return json.dumps({"event": "tool_use", "repo_root": str(repo), "writes": writes})


def write_run(repo: Path, writes: dict[str, str]) -> tuple[int, str]:
    env = {k: v for k, v in os.environ.items() if k not in AGENT_ENV}
    return scriptkit.run_script(POLICY, WRITE, repo, stdin=write_payload(repo, writes), env=env)


def head_repo(tmp: Path, head_sidecar: str | None) -> Path:
    files = {p: t["before"] for p, t in pair("N04")["files"].items()}
    if head_sidecar is not None:
        files[SIDECAR] = head_sidecar
    return scriptkit.init_repo(tmp / "r", files)


def after_n04() -> dict[str, str]:
    return {p: t["after"] for p, t in pair("N04")["files"].items()}


def test_a_write_the_head_waiver_covers_passes_and_is_logged(tmp_path: Path) -> None:
    code, err = write_run(head_repo(tmp_path, waiver_for("N04")), after_n04())
    assert code == WARN
    assert "waived" in err


def test_a_write_with_no_waiver_is_refused(tmp_path: Path) -> None:
    assert write_run(head_repo(tmp_path, None), after_n04())[0] == 1


def test_a_waiver_written_in_the_same_change_does_not_cover_it(tmp_path: Path) -> None:
    repo = head_repo(tmp_path, None)
    code, err = write_run(repo, {**after_n04(), SIDECAR: waiver_for("N04")})
    assert code == 1
    assert "adds a waiver" in err
    assert "img" in err


def test_an_agent_written_waiver_is_refused_at_tool_use(tmp_path: Path) -> None:
    repo = head_repo(tmp_path, None)
    code, err = write_run(repo, {SIDECAR: waiver_for("N04")})
    assert code == 1
    assert SIDECAR in err
    assert "never writes it" in err


def test_an_agent_written_waiver_is_refused_at_the_turns_end(tmp_path: Path) -> None:
    repo = head_repo(tmp_path, None)
    scriptkit.write(repo, {SIDECAR: waiver_for("N04")})  # the turn left it on disk, and Stop sends what it wrote
    code, err = write_run(repo, {SIDECAR: waiver_for("N04")})
    assert code == 1
    assert "adds a waiver" in err


def test_rewriting_a_sidecar_without_a_new_entry_passes(tmp_path: Path) -> None:
    repo = head_repo(tmp_path, waiver_for("N04"))
    assert write_run(repo, {SIDECAR: waiver_for("N04")})[0] == 0


def test_a_broken_sidecar_write_says_so(tmp_path: Path) -> None:
    code, err = write_run(head_repo(tmp_path, None), {SIDECAR: "{"})
    assert code == 0
    assert "breaks its closed schema" in err


# ── the rollout level reaches the commit through the engine's own script-hook codes ──────────
@pytest.fixture
def runner() -> object:
    return engine


def engine_exit(runner: object, repo: Path, code: int, monkeypatch: pytest.MonkeyPatch) -> int:
    for name in (*AGENT_ENV, runner.ALLOW_ENV, runner.ROLLOUT_ENV, runner.GATE_LOG_ENV):
        monkeypatch.delenv(name, raising=False)
    return runner.script_verdict(POLICY, "pre-commit", code, repo)


def log_lines(repo: Path) -> list[dict]:
    log = repo / ".chock" / "log" / "gate-events.jsonl"
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []


def test_the_codes_are_the_engine_s(runner: object) -> None:
    assert (runner.EXIT_ASK, runner.EXIT_WARN) == (ASK, WARN)


@pytest.mark.parametrize(("level", "exit_code"), [("observe", 0), ("ask", 1), ("enforce", 1)])
def test_the_rollout_level_reaches_the_commit(
    tmp_path: Path, runner: object, monkeypatch: pytest.MonkeyPatch, level: str, exit_code: int
) -> None:
    repo = staged_repo(tmp_path, "N04", level=level)
    code, _ = commit(repo)
    assert code == ASK
    assert engine_exit(runner, repo, code, monkeypatch) == exit_code


def test_under_observe_the_finding_is_logged(tmp_path: Path, runner: object, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = staged_repo(tmp_path, "N04", level="observe")
    engine_exit(runner, repo, commit(repo)[0], monkeypatch)
    held = [r for r in log_lines(repo) if r.get("policy_id") == POLICY]
    assert held
    assert held[-1]["verdict"] == "warn"
    assert held[-1]["would_action"] == "ask"


def test_a_waived_finding_is_logged_as_a_warn(tmp_path: Path, runner: object, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = staged_repo(tmp_path, "N04", head_sidecar=waiver_for("N04"))
    code, _ = commit(repo)
    assert engine_exit(runner, repo, code, monkeypatch) == 0
    assert log_lines(repo)[-1]["verdict"] == "warn"


# ── the module's own edges ───────────────────────────────────────────────────────────────────
WAIVER = GUARD.waiver


def test_a_sidecar_is_named_whatever_the_case_or_separator() -> None:
    assert WAIVER.is_sidecar(SIDECAR)
    assert WAIVER.is_sidecar("./" + SIDECAR.upper())
    assert WAIVER.is_sidecar(SIDECAR.replace("/", "\\"))
    assert not WAIVER.is_sidecar("docs/" + SIDECAR)


@pytest.mark.parametrize(("value", "person"), [("1", False), ("true", False), ("0", True), ("", True), ("off", True)])
def test_an_agent_marker_is_read_as_the_engine_reads_it(
    monkeypatch: pytest.MonkeyPatch, value: str, person: bool
) -> None:
    for name in AGENT_ENV:
        monkeypatch.delenv(name, raising=False)
    assert WAIVER.by_person()
    for name in AGENT_ENV:
        monkeypatch.setenv(name, value)
        assert WAIVER.by_person() is person
        monkeypatch.delenv(name)


def test_git_that_cannot_run_shows_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def missing(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError

    monkeypatch.setattr(WAIVER.subprocess, "run", missing)
    assert WAIVER.show("HEAD:./x", tmp_path) is None


def test_a_waiver_reads_back_with_its_reason_and_its_exemptions() -> None:
    text = sidecar(
        [{"file": "./a\\b.html", "element": "img:1", "reason": "r1"}],
        [{"path": "gen/*", "reason": "r2"}],
    )
    honoured = WAIVER.read(text, None, person=False)
    assert honoured.reason("a/b.html", "img:1") == "r1"
    assert honoured.reason("gen/deep/x.html", "img:9") == "r2"
    assert honoured.reason("a/b.html", "img:2") is None
    assert honoured.added == []


def test_a_change_adds_entries_beyond_head_and_only_a_person_is_held_to_them() -> None:
    head = sidecar([{"file": "a.html", "element": "img:1", "reason": "r"}])
    both = sidecar(
        [{"file": "a.html", "element": "img:1", "reason": "r"}, {"file": "b.html", "element": "img:1", "reason": "s"}]
    )
    agent, person = WAIVER.read(head, both, person=False), WAIVER.read(head, both, person=True)
    assert agent.added == person.added == [("waive", "b.html", "img:1", "s")]
    assert (agent.reason("b.html", "img:1"), person.reason("b.html", "img:1")) == (None, "s")
    assert agent.reason("a.html", "img:1") == "r"


def test_an_agent_adding_a_waiver_to_a_commit_that_breaks_nothing_is_still_asked_about(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "r", {"a.html": '<img src="/a.png" alt="Chart">\n'})
    scriptkit.write(repo, {SIDECAR: waiver_for("N04")})
    scriptkit.git(repo, "add", "-A")
    code, err = commit(repo, agent=True)
    assert code == ASK
    assert "BLOCKED" not in err
    assert "adds a waiver" in err
    assert commit(repo)[0] == 0  # a person's own commit of a sidecar breaks nothing
