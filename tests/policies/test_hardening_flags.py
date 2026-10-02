"""hardening-flags: what the gate refuses, asks about and leaves alone, in each scoped file type."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
from policies import scriptkit
from policies.hardening_flags_cases import CARGO, CMAKE, KERNEL, MAKE, PRAGMA, RUST, SHELL, UNSCANNED

NAME = "hardening-flags-gate.py"


def load_gate() -> object:
    """Import the gate with its own shipped chock_scan copy: tests/chock_scan shadows that name in a full run."""
    saved = {k: v for k, v in sys.modules.items() if k == "chock_scan" or k.startswith("chock_scan.")}
    for key in saved:
        del sys.modules[key]
    try:
        return scriptkit.load("hardening-flags", NAME)
    finally:
        for key in [k for k in sys.modules if k == "chock_scan" or k.startswith("chock_scan.")]:
            del sys.modules[key]
        sys.modules.update(saved)


mod = load_gate()
ENTRIES = mod.rules.load()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHOCK_AGENT_COMMIT", raising=False)


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
    assert found(path, line + "\n", "tool_use") != [] or not any(line)


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


def table(tmp_path: Path, entries: object) -> Path:
    path = tmp_path / "data" / "flags.json"
    path.parent.mkdir()
    doc = {
        "schema": 1,
        "kind": "curated",
        "as_of": "2026-10-02",
        "source": "https://example.invalid/x",
        "entries": entries,
    }
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


GOOD = {"id": "a-flag", "tier": "block", "langs": ["c"], "pattern": "-x", "what": "turns x off"}


@pytest.mark.parametrize(
    ("entries", "problem"),
    [
        ([], "non-empty list"),
        ("nope", "non-empty list"),
        ([5], "fields must be"),
        ([{**GOOD, "extra": 1}], "fields must be"),
        ([{k: v for k, v in GOOD.items() if k != "what"}], "fields must be"),
        ([{**GOOD, "id": "Bad_Id"}], "unique kebab-case"),
        ([{**GOOD, "id": 7}], "unique kebab-case"),
        ([GOOD, GOOD], "unique kebab-case"),
        ([{**GOOD, "tier": "warn"}], "tier must be"),
        ([{**GOOD, "langs": []}], "langs must be"),
        ([{**GOOD, "langs": ["cobol"]}], "langs must be"),
        ([{**GOOD, "langs": "c"}], "langs must be"),
        ([{**GOOD, "what": " "}], "what must say"),
        ([{**GOOD, "what": 3}], "what must say"),
        ([{**GOOD, "pattern": "("}], "does not compile"),
        ([{**GOOD, "pattern": 5}], "does not compile"),
        ([{**GOOD, "pattern": "x*"}], "empty string"),
        ([{**GOOD, "section": "["}], "does not compile"),
        ([{**GOOD, "section": "^$"}], "empty string"),
    ],
)
def test_a_bad_table_is_refused(tmp_path: Path, entries: object, problem: str) -> None:
    with pytest.raises(mod.TableError, match=problem):
        mod.rules.load(table(tmp_path, entries))


def test_a_good_table_loads_with_a_section(tmp_path: Path) -> None:
    loaded = mod.rules.load(table(tmp_path, [{**GOOD, "section": "^profile$"}]))
    assert [(e.id, e.tier, bool(e.section)) for e in loaded] == [("a-flag", "block", True)]


def test_sections_and_hits() -> None:
    assert mod.rules.section_of("[profile.release]", "x") == "profile.release"
    assert mod.rules.section_of('[[bin."a b"]]', "x") == "bin.ab"
    assert mod.rules.section_of("name = 1", "x") == "x"
    entry = ENTRIES[0]
    assert list(mod.rules.hits(ENTRIES, frozenset({"kernel"}), "-fno-stack-protector", "")) == []
    assert [e.id for e, _ in mod.rules.hits(ENTRIES, frozenset({"c"}), "-fno-stack-protector", "")] == [entry.id]


def test_the_gate_is_fast_on_hostile_lines() -> None:
    start = time.monotonic()
    text = ("-U_FORTIFY_SOURCE " * 4000 + "\n") * 5 + "X = " + "-z " * 20000 + "\n" + "[" * 5000 + "\n"
    found("Makefile", text)
    found("CMakeLists.txt", text)
    found("Cargo.toml", text)
    found("build.rs", text)
    assert time.monotonic() - start < 20
