"""hardening-flags: what the gate refuses, asks about and leaves alone, in each scoped file type."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
from policies import hardflagskit, scriptkit
from policies.hardening_flags_cases import CARGO, CMAKE, KERNEL, MAKE, PRAGMA, RUST, SHELL, UNSCANNED
from policies.hardflagskit import NAME

mod = hardflagskit.load_gate()
ENTRIES = mod.rules.load()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CHOCK_AGENT_COMMIT", "CLAUDECODE", "AI_AGENT"):
        monkeypatch.delenv(name, raising=False)


def found(path: str, text: str, event: str = "commit") -> list[str]:
    items = mod.findings({"event": event, "writes": {path: text}}, ENTRIES)
    return sorted(item["key"] for item in items)


@pytest.mark.parametrize(
    ("path", "text", "keys"),
    CMAKE + MAKE + SHELL + CARGO + RUST + KERNEL + UNSCANNED,
)
def test_cases(path: str, text: str, keys: list[str]) -> None:
    assert found(path, text) == sorted(keys)


@pytest.mark.parametrize(
    ("path", "line", "waived"),
    [
        ("Makefile", f"X = -no-pie # {PRAGMA}", True),
        ("CMakeLists.txt", f"add_compile_options(-no-pie) # {PRAGMA}", True),
        ("Cargo.toml", f"x = ['-no-pie'] # {PRAGMA}", True),
        ("build.rs", f'let a = "-no-pie"; // {PRAGMA}', True),
        ("build.rs", f'let a = "-no-pie"; /* {PRAGMA} */', True),
        ("x.config", f"# CONFIG_STACKPROTECTOR is not set # {PRAGMA}", True),
        ("x.config", f"CONFIG_STACKPROTECTOR=n # {PRAGMA}", True),
        ("build.sh", f"cc -no-pie # {PRAGMA}", True),
        ("Makefile", f"X = -no-pie // {PRAGMA}", False),
        ("build.rs", f'let a = "-no-pie"; # {PRAGMA}', False),
        ("CMakeLists.txt", f'add_compile_options("-no-pie" "{PRAGMA}")', False),
        ("Makefile", "X = -no-pie # pragma: allowlist other-flag", False),
    ],
)
def test_waiver_is_a_comment_on_the_same_line(path: str, line: str, waived: bool) -> None:
    assert (found(path, line + "\n") == []) is waived
    assert found(path, line + "\n", "tool_use") != []


def test_waiver_events() -> None:
    text = f"X = -no-pie # {PRAGMA}\n"
    assert found("Makefile", text, "commit") == []
    assert found("Makefile", text, "ci") == []
    for event in ("tool_use", "stop", "push", ""):
        assert found("Makefile", text, event) == ["no-pie"]


@pytest.mark.parametrize("value", ["1", "true", "yes", "anything"])
def test_agent_commit_never_waives(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("CHOCK_AGENT_COMMIT", value)
    assert found("Makefile", f"X = -no-pie # {PRAGMA}\n") == ["no-pie"]


@pytest.mark.parametrize("value", ["", "0", "false", "No", "OFF", " "])
def test_a_person_marker_still_waives(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("CHOCK_AGENT_COMMIT", value)
    assert found("Makefile", f"X = -no-pie # {PRAGMA}\n") == []


@pytest.mark.parametrize("name", ["CLAUDECODE", "AI_AGENT"])
def test_agent_markers_never_waive(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setenv(name, "1" if name == "CLAUDECODE" else "claude-code_agent")
    assert found("Makefile", f"X = -no-pie # {PRAGMA}\n") == ["no-pie"]
    monkeypatch.setenv("CHOCK_AGENT_COMMIT", "0")
    assert found("Makefile", f"X = -no-pie # {PRAGMA}\n") == []


@pytest.mark.parametrize(
    "config",
    [
        "agent_commit_env: MY_AGENT\n",
        "agent_commit_env: [A, MY_AGENT]\n",
        "agent_commit_env:\n  # c\n\n  - 'MY_AGENT'\n",
    ],
)
def test_configured_agent_env_never_waives(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, config: str) -> None:
    (tmp_path / ".chock").mkdir()
    (tmp_path / ".chock" / "config.yaml").write_text(config, encoding="utf-8")
    monkeypatch.setenv("MY_AGENT", "1")
    payload = {"event": "commit", "repo_root": str(tmp_path), "writes": {"Makefile": f"X = -no-pie # {PRAGMA}\n"}}
    assert [i["key"] for i in mod.findings(payload, ENTRIES)] == ["no-pie"]
    monkeypatch.delenv("MY_AGENT")
    assert mod.findings(payload, ENTRIES) == []


def test_unreadable_agent_config_is_no_marker(tmp_path: Path) -> None:
    assert mod.agent_commit(tmp_path) is False
    (tmp_path / ".chock").mkdir()
    (tmp_path / ".chock" / "config.yaml").write_bytes(b"\xff\xfe")
    assert mod.agent_commit(tmp_path) is False


def test_pragma_on_another_line_does_not_waive() -> None:
    assert found("Makefile", f"# {PRAGMA}\nX = -no-pie\n") == ["no-pie"]
    assert found("Makefile", f"X = \\\n  -no-pie \\\n  -O2 # {PRAGMA}\n") == ["no-pie"]
    assert found("Makefile", f"X = -O2 \\\n  -no-pie # {PRAGMA}\n") == []


def test_finding_shape_and_lines() -> None:
    items = mod.findings({"event": "commit", "writes": {"Makefile": "A = 1\nB = \\\n  -no-pie\n"}}, ENTRIES)
    assert items == [{"key": "no-pie", "path": "Makefile", "line": 3, "message": "block: " + items[0]["message"][7:]}]
    assert items[0]["message"].endswith(": -no-pie")


def test_no_writes_no_findings() -> None:
    assert mod.findings({"event": "commit"}, ENTRIES) == []


def test_every_entry_has_a_hit_and_a_tier() -> None:
    seen = {key for _, text, keys in CMAKE + MAKE + SHELL + CARGO + RUST + KERNEL for key in keys}
    assert {entry.id for entry in ENTRIES} == seen
    assert {entry.tier for entry in ENTRIES} == {"block", "ask"}


def run(stdin: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, str(scriptkit.script_path("hardening-flags", NAME))],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def payload(**writes: str) -> str:
    return json.dumps({"event": "commit", "writes": {k.replace("_", "/"): v for k, v in writes.items()}})


def test_exit_codes_block_ask_allow() -> None:
    code, out, err = run(json.dumps({"event": "commit", "writes": {"Makefile": "X = -no-pie\n"}}))
    assert code == 1
    assert json.loads(out)["findings"][0]["key"] == "no-pie"
    assert "Makefile:1" in err
    assert "pragma: allowlist hardening-flag" in err
    code, out, err = run(
        json.dumps({"event": "commit", "writes": {"Cargo.toml": "[profile.release]\noverflow-checks = false\n"}})
    )
    assert (code, json.loads(out)["findings"][0]["key"]) == (3, "rust-overflow-checks-release")
    assert "hardening-flags:" in err
    code, out, err = run(json.dumps({"event": "commit", "writes": {"Makefile": "X = -O2\n"}}))
    assert (code, json.loads(out), err) == (0, {"findings": []}, "")


def test_block_wins_over_ask() -> None:
    writes = {"Cargo.toml": "[profile.release]\noverflow-checks = false\n", "Makefile": "X = -no-pie\n"}
    assert run(json.dumps({"event": "commit", "writes": writes}))[0] == 1


@pytest.mark.parametrize(
    "stdin",
    [
        "null",
        "[]",
        "5",
        '{"writes": null}',
        '{"writes": {"Makefile": null}}',
        '{"writes": {"Makefile": 5}}',
        "[" * 100000,
    ],
)
def test_odd_payload_is_undecided_not_a_crash(stdin: str) -> None:
    code, _out, err = run(stdin)
    assert code == 2, err
    assert "Traceback" not in err


def test_empty_payload_allows() -> None:
    assert run("{}")[0] == 0


def test_bad_stdin_is_undecided() -> None:
    code, out, err = run("not json")
    assert (code, out) == (2, "")
    assert "not the gate JSON" in err


def test_unusable_table_is_undecided(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def broken(*_args: object) -> list:
        raise mod.TableError("flags", ["no good"])

    monkeypatch.setattr(mod.rules, "load", broken)
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    assert mod.main() == 2
    assert "refusing rather than allowing" in capsys.readouterr().err

    def missing(*_args: object) -> list:
        raise FileNotFoundError("flags.json")

    monkeypatch.setattr(mod.rules, "load", missing)
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    assert mod.main() == 2


def test_the_shipped_table_loads_and_is_dated() -> None:
    doc = mod.rules.data_table.read(mod.rules.TABLE)
    assert doc["kind"] == "curated"
    assert len(doc["entries"]) == len(ENTRIES)


def test_the_gate_is_fast_on_hostile_lines() -> None:
    start = time.monotonic()
    found("Cargo.toml", "profile.release " * 20000)
    found("Cargo.toml", "profile . release " * 20000)
    assert time.monotonic() - start < 10

    start = time.monotonic()
    text = ("-U_FORTIFY_SOURCE " * 4000 + "\n") * 5 + "X = " + "-z " * 20000 + "\n" + "[" * 5000 + "\n"
    found("Makefile", text)
    found("CMakeLists.txt", text)
    found("Cargo.toml", text)
    found("build.rs", text)
    assert time.monotonic() - start < 20
