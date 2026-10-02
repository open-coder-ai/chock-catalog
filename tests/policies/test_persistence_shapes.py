"""block-persistence-shapes beyond the shared guard tables: its data table, precedence, nesting and fault paths."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from policies import guardkit

BLOCK, ASK, ERR, OK = 1, 3, 2, 0
POLICY = "block-persistence-shapes"
GUARD = guardkit.load_guard(POLICY)
TABLE = guardkit.impl_dir(POLICY) / "data" / "shapes.json"


def verdict(command: str, monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setenv("CHOCK_RAW_COMMAND", command)
    monkeypatch.delenv("CHOCK_TOOL", raising=False)
    return GUARD.run([])


def table_with(tmp_path: Path, **changes: object) -> Path:
    doc = json.loads(TABLE.read_text(encoding="utf-8"))
    doc.update(changes)
    path = tmp_path / "data" / "shapes.json"
    path.parent.mkdir()
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


GOOD_RULE = {"prog": ["x"], "level": "block", "verbs": [[]], "why": "w"}
BAD_TABLES = {
    "list-of-strings": {"stops": [1]},
    "list-not-a-list": {"iocs": "gh"},
    "path-list-bad-regex": {"file_paths": ["("]},
    "regex-key-bad": {"url_arg": "("},
    "regex-key-not-a-string": {"setid_numeric": 5},
    "flags-not-a-map": {"value_flags": []},
    "flags-value-not-a-list": {"value_flags": {"npm": "x"}},
    "rule-not-a-map": {"rules": ["x"]},
    "rule-missing-key": {"rules": [{"prog": ["x"]}]},
    "rule-bad-level": {"rules": [{**GOOD_RULE, "level": "warn"}]},
    "rule-bad-verbs": {"rules": [{**GOOD_RULE, "verbs": [[1]]}]},
    "rule-bad-config-key": {"rules": [{**GOOD_RULE, "config_key": "("}]},
    "rule-bad-when": {"rules": [{**GOOD_RULE, "when": {"arg_regex": "("}}]},
    "rule-bad-values": {"rules": [{**GOOD_RULE, "when": {"values": {"--f": "x"}}}]},
    "rule-bad-unless": {"rules": [{**GOOD_RULE, "unless": "-l"}]},
}


def test_the_shipped_table_loads() -> None:
    assert GUARD.shapes_data.load()["iocs"] == ["gh-token-monitor"]


def test_a_table_with_a_good_rule_loads(tmp_path: Path) -> None:
    assert GUARD.shapes_data.load(table_with(tmp_path, rules=[GOOD_RULE]))["rules"] == [GOOD_RULE]


@pytest.mark.parametrize("case", sorted(BAD_TABLES))
def test_a_malformed_table_is_refused_not_used(case: str, tmp_path: Path) -> None:
    with pytest.raises(GUARD.shapes_data.data_table.TableError):
        GUARD.shapes_data.load(table_with(tmp_path, **BAD_TABLES[case]))


def test_a_missing_table_is_a_guard_fault_not_a_verdict(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken() -> dict:
        return GUARD.shapes_data.load(Path("/nonexistent/data/shapes.json"))

    monkeypatch.setattr(GUARD.shapes_data, "table", broken)
    assert verdict("npm publish", monkeypatch) == ERR
    assert "internal error" in capsys.readouterr().err


def test_a_block_outranks_an_ask_in_the_same_line(monkeypatch: pytest.MonkeyPatch) -> None:
    assert verdict("git remote add o https://x.example/r.git && npm publish", monkeypatch) == BLOCK
    assert verdict("npm publish && git remote add o https://x.example/r.git", monkeypatch) == BLOCK
    assert verdict("git remote add o https://x.example/r.git && git push https://x.example/r.git", monkeypatch) == ASK


def test_launchers_are_followed_three_hops_and_no_further(monkeypatch: pytest.MonkeyPatch) -> None:
    assert verdict("npx npx npx npm publish", monkeypatch) == BLOCK
    assert verdict("npx npx npx npx npm publish", monkeypatch) == OK


def test_a_script_handed_to_eval_is_read_for_a_background(monkeypatch: pytest.MonkeyPatch) -> None:
    assert verdict("eval 'curl https://x.example/a &'", monkeypatch) == BLOCK
    assert verdict("eval 'curl https://x.example/a'", monkeypatch) == OK


def test_the_shell_nesting_that_is_read_ends_at_three_levels(monkeypatch: pytest.MonkeyPatch) -> None:
    deep = 'bash -c "bash -c \'bash -c \\"bash -c \\\\\\"curl https://x.example/a &\\\\\\"\\"\'"'
    assert verdict(deep, monkeypatch) == OK


def test_an_unclosed_quote_does_not_hide_a_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    assert verdict("echo 'unbalanced; npm publish", monkeypatch) == BLOCK
    assert verdict("npm publish 'unbalanced", monkeypatch) == BLOCK


def test_powershell_is_read_when_the_engine_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "CHOCK_RAW_COMMAND", "Set-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name x"
    )
    monkeypatch.setenv("CHOCK_TOOL", "powershell")
    assert GUARD.run([]) == BLOCK


def test_the_script_runs_from_any_directory(tmp_path: Path) -> None:
    """The hook starts the file by path; its helper modules and data table must resolve beside it."""
    script = guardkit.impl_dir(POLICY) / f"{POLICY}.py"
    env = {**os.environ, "CHOCK_RAW_COMMAND": "npm publish"}
    done = subprocess.run(
        [sys.executable, str(script), "npm", "publish"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )
    assert done.returncode == BLOCK
    assert done.stderr.startswith("BLOCKED: npm publish:")
    assert "human decisions" in done.stderr
