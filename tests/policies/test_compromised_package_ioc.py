"""compromised-package-ioc: the gate's findings, its exit codes, and its refusal when the table cannot be used."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from policies import scriptkit
from policies.iockit import GATE, POLICY, gate, keys, table

LOCK = json.dumps({"lockfileVersion": 3, "packages": {"node_modules/axios": {"version": "1.14.1"}}})


def test_the_manifest_declares_a_blocking_script_gate_at_commit_and_tool_use() -> None:
    manifest = scriptkit.manifest(POLICY)
    gate_spec = manifest["hook"]["gate"]
    assert (gate_spec["kind"], gate_spec["on"], gate_spec["action"]) == ("script", ["commit", "tool_use"], "block")
    assert gate_spec["params"] == {"script": GATE}
    assert manifest["security"]["content_instructions"] == "never-obey"
    assert "rollout observe" in " ".join(manifest["description"].split())


def test_findings_key_each_kind_by_what_is_listed_never_by_line() -> None:
    writes = {
        "a\\package-lock.json": LOCK,
        "package.json": json.dumps({"dependencies": {"postmark-mcp": "^1.0.0", "x": "npm:axios@1.14.1"}}),
        ".github/workflows/ci.yml": "steps:\n  - uses: tj-actions/changed-files@V45\n  - uses: actions/checkout@v4\n",
        "src/SETUP_BUN.js": None,
        "Cargo.toml": "[dependencies\n",
        "README.md": "axios 1.14.1\n",
    }
    assert keys(writes) == [
        "ioc-action|tj-actions/changed-files|v45",
        "unparseable",
        "ioc|npm|axios|1.14.1",
        "ioc|npm|postmark-mcp|*",
        "ioc|npm|axios|1.14.1",
        "ioc-file|setup_bun.js",
    ]
    found = gate.findings({"writes": writes}, table.load())
    assert found[2]["path"] == "a/package-lock.json"
    assert "axios maintainer account takeover, 2026-03-31, source elastic-axios" in found[2]["message"]


def test_clean_manifests_report_nothing() -> None:
    writes = {"package.json": json.dumps({"dependencies": {"axios": "1.14.0"}}), "go.sum": "", "x.txt": "debug 4.4.2"}
    assert keys(writes) == []
    assert keys({}) == []


def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], stdin: str) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = gate.main()
    out = capsys.readouterr()
    return code, out.out, out.err


def test_main_refuses_with_a_findings_document_and_the_alternative(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run(monkeypatch, capsys, json.dumps({"event": "commit", "writes": {"package-lock.json": LOCK}}))
    assert code == 1
    assert json.loads(out)["findings"][0]["key"] == "ioc|npm|axios|1.14.1"
    assert "package-lock.json:1: npm axios@1.14.1 is a known-malicious release" in err
    assert "reviewed pull request" in err


def test_main_allows_with_an_empty_document(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run(monkeypatch, capsys, json.dumps({"event": "tool_use", "writes": {"a.py": "x"}}))
    assert (code, json.loads(out), err) == (0, {"findings": []}, "")


def test_main_refuses_input_that_is_not_the_gate_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run(monkeypatch, capsys, "not json")
    assert (code, out) == (2, "")
    assert "stdin is not the gate JSON" in err


def test_main_refuses_everything_when_the_table_cannot_be_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "ioc.json").write_text('{"schema": 1}', encoding="utf-8")
    monkeypatch.setattr(table, "PATH", folder / "ioc.json")
    monkeypatch.setattr(table.load, "__defaults__", (folder / "ioc.json",))
    code, out, err = run(monkeypatch, capsys, json.dumps({"event": "commit", "writes": {}}))
    assert (code, out) == (2, "")
    assert "the IOC table cannot be used, so nothing is allowed" in err
    assert "missing envelope keys" in err


def test_the_shipped_script_runs_as_a_process_and_refuses(tmp_path: Path) -> None:
    payload = json.dumps({"event": "commit", "writes": {"requirements.txt": "litellm==1.82.8\n"}})
    proc = scriptkit.run_script_full(POLICY, GATE, tmp_path, payload)
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["findings"][0]["key"] == "ioc|pypi|litellm|1.82.8"
