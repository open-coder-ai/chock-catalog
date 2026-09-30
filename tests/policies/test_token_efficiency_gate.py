"""token-efficiency: the tool_call gate that warns on a repeated Read and a command retried past the cap."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import scriptkit, toolcallkit
from policies.toolcallkit import payload, record, write_log

POLICY = "token-efficiency"
NAME = "token-efficiency-gate.py"
mod = scriptkit.load(POLICY, NAME)
READ = {"file_path": "src/a.py"}
CMD = "make test"


def reads(n: int, path: str = "src/a.py") -> list[dict]:
    return [record("Read", "pre", call=f"r{i}", path=path) for i in range(n)]


def runs(*outcomes: str, command: str = CMD) -> list[dict]:
    return [record("Bash", "post", o, call=f"b{i}", command=command) for i, o in enumerate(outcomes)]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return toolcallkit.make_repo(tmp_path)


def run(ctx: tuple, tool: str, tool_input: dict, records: list[dict]) -> tuple[int, str]:
    repo, monkeypatch, capsys = ctx
    write_log(repo, records)
    return toolcallkit.fire(mod, monkeypatch, capsys, payload(repo, tool, tool_input))


def test_the_manifest_declares_a_warn_script_gate_on_read_and_bash() -> None:
    gate = scriptkit.manifest(POLICY)["hook"]["gate"]
    assert (gate["kind"], gate["on"], gate["action"]) == ("script", ["tool_call"], "warn")
    assert gate["params"] == {"script": NAME, "tools": ["Read", "Bash"]}


@pytest.mark.parametrize(
    "records",
    [
        reads(2),
        reads(5),
        [*reads(1), record("Edit", "post", "ok", path="src/a.py"), *reads(2)],
        [record("Read", "pre", "blocked", path="src/a.py"), *reads(2)],
    ],
)
def test_the_third_read_of_an_unchanged_file_warns(repo, monkeypatch, capsys, records: list[dict]) -> None:
    code, err = run((repo, monkeypatch, capsys), "Read", READ, records)
    assert code == 4
    assert "src/a.py" in err


@pytest.mark.parametrize(
    "records",
    [
        [],
        reads(1),
        reads(3, path="src/b.py"),
        [*reads(2), record("Edit", "pre", path="src/a.py")],
        [*reads(2), record("Write", "post", "ok", path="src/a.py")],
        [*reads(1), record("Grep", "pre", path="src/a.py")],
        [record("Read", "post", "ok", path="src/a.py")] * 3,
    ],
)
def test_fewer_reads_since_an_edit_stay_quiet(repo, monkeypatch, capsys, records: list[dict]) -> None:
    assert run((repo, monkeypatch, capsys), "Read", READ, records) == (0, "")


@pytest.mark.parametrize("key", ["file_path", "filePath", "path", "notebook_path"])
def test_the_path_is_read_from_any_vendor_key(repo, monkeypatch, capsys, key: str) -> None:
    assert run((repo, monkeypatch, capsys), "Read", {key: "src/a.py"}, reads(2))[0] == 4


@pytest.mark.parametrize("tool_input", [{}, {"file_path": ""}, {"file_path": 3}])
def test_a_read_without_a_path_is_not_judged(repo, monkeypatch, capsys, tool_input: dict) -> None:
    assert run((repo, monkeypatch, capsys), "Read", tool_input, reads(3)) == (0, "")


@pytest.mark.parametrize(
    "records",
    [runs("error", "error", "error"), runs("ok", "error", "error", "error", "error"), runs("error") * 4],
)
def test_a_command_failed_past_the_retry_cap_warns(repo, monkeypatch, capsys, records: list[dict]) -> None:
    code, err = run((repo, monkeypatch, capsys), "Bash", {"command": CMD}, records)
    assert code == 4
    assert "retry cap 3" in err
    assert CMD not in err


@pytest.mark.parametrize(
    "records",
    [
        [],
        runs("error", "error"),
        runs("error", "error", "error", "ok"),
        runs("error", "error", "ok", "error"),
        runs("error", "error", "error", command="make lint"),
        [record("Bash", "pre", command=CMD)] * 5,
        [record("Read", "post", "error", path="src/a.py")] * 4,
    ],
)
def test_fewer_failures_or_another_command_stay_quiet(repo, monkeypatch, capsys, records: list[dict]) -> None:
    assert run((repo, monkeypatch, capsys), "Bash", {"command": CMD}, records) == (0, "")


def test_the_command_is_compared_as_the_log_stores_it(repo, monkeypatch, capsys) -> None:
    logged = runs("error", "error", "error", command="LEVEL=*** pytest -k a=***")
    assert run((repo, monkeypatch, capsys), "Bash", {"command": "LEVEL=3 pytest -k a=b"}, logged)[0] == 4
    long_cmd = "echo " + "x" * 400
    capped = runs("error", "error", "error", command=long_cmd[:300])
    assert run((repo, monkeypatch, capsys), "Bash", {"command": long_cmd}, capped)[0] == 4


@pytest.mark.parametrize("tool_input", [{}, {"command": 3}, {"command": ""}, {"command": "make a\nmake b"}])
def test_an_unjudgeable_command_is_skipped(repo, monkeypatch, capsys, tool_input: dict) -> None:
    assert run((repo, monkeypatch, capsys), "Bash", tool_input, runs("error") * 4) == (0, "")


def test_other_tools_and_a_missing_reader_or_log_stay_quiet(tmp_path: Path, repo: Path, monkeypatch, capsys) -> None:
    assert run((repo, monkeypatch, capsys), "Grep", READ, reads(5)) == (0, "")
    (repo / ".chock" / "state" / f"{toolcallkit.SESSION}.jsonl").unlink()
    assert toolcallkit.fire(mod, monkeypatch, capsys, payload(repo, "Read", READ)) == (0, "")
    monkeypatch.delitem(__import__("sys").modules, "chock_session", raising=False)
    monkeypatch.setattr("sys.path", [p for p in __import__("sys").path if not p.endswith(".chock/bin")])
    bare = toolcallkit.make_repo(tmp_path / "bare", vendored=False)
    assert toolcallkit.fire(mod, monkeypatch, capsys, payload(bare, "Read", READ)) == (0, "")


def test_run_as_a_process_it_speaks_by_exit_code(repo: Path) -> None:
    write_log(repo, reads(2))
    assert scriptkit.run_script(POLICY, NAME, repo, json.dumps(payload(repo, "Read", READ)))[0] == 4
    write_log(repo, [])
    assert scriptkit.run_script(POLICY, NAME, repo, json.dumps(payload(repo, "Read", READ))) == (0, "")
