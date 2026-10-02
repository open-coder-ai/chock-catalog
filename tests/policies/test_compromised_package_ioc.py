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
        "unparseable|" + gate._digest("[dependencies\n"),
        "ioc|npm|axios|1.14.1",
        "ioc|npm|postmark-mcp|*",
        "ioc|npm|axios|1.14.1",
        "ioc-file|setup_bun.js",
    ]
    found = gate.findings({"writes": writes}, table.load())
    assert found[2]["path"] == "a/package-lock.json"
    assert "axios maintainer account takeover, 2026-03-31, source elastic-axios" in found[2]["message"]


def test_clean_manifests_report_nothing() -> None:
    writes = {
        "package.json": json.dumps({"dependencies": {"axios": "1.14.0"}}),
        "go.sum": "",
        "composer.json": " \n",
        "x.txt": "debug 4.4.2",
    }
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


def test_a_byte_order_mark_is_read_through_as_npm_pip_and_composer_do() -> None:
    bom = "\ufeff"
    writes = {
        "package.json": bom + json.dumps({"dependencies": {"axios": "1.14.1"}}),
        "composer.json": bom + json.dumps({"require": {"intercom/intercom-php": "5.0.2"}}),
        "requirements.txt": bom + "litellm==1.82.7\n",
        ".github/workflows/a.yml": bom + "  - uses: tj-actions/changed-files@v45\n",
    }
    assert sorted(keys(writes)) == [
        "ioc-action|tj-actions/changed-files|v45",
        "ioc|npm|axios|1.14.1",
        "ioc|packagist|intercom/intercom-php|5.0.2",
        "ioc|pypi|litellm|1.82.7",
    ]
    assert keys({"package.json": bom}) == []


@pytest.mark.parametrize("text", ["litellm==1.82.7\x00\n", "requests==2.0\x00\n", "\ufffd\ufffdlitellm\n"])
def test_text_that_did_not_decode_is_unreadable_not_silent(text: str) -> None:
    assert keys({"requirements.txt": text}) == ["unparseable|" + gate._digest(text)]


def test_an_undecodable_comment_in_a_file_that_reads_is_not_a_refusal() -> None:
    assert keys({"Gemfile": "# Jos\ufffd\ngem 'rails'\ngem 'puma'\n"}) == []


def test_an_unreadable_file_edited_while_unreadable_is_new() -> None:
    head = keys({"package.json": "{"})
    new = keys({"package.json": '{"dependencies": {"axios": "1.14.1"'})
    assert head[0].startswith("unparseable|")
    assert new[0].startswith("unparseable|")
    assert head != new


def test_an_alias_is_judged_by_what_its_anchor_names() -> None:
    head = "x: &a actions/checkout@v4\nsteps:\n  - uses: *a\n"
    new = "x: &a tj-actions/changed-files@v45\nsteps:\n  - uses: *a\n"
    assert keys({".github/workflows/a.yml": head}) == []
    assert keys({".github/workflows/a.yml": new}) == ["ioc-action|tj-actions/changed-files|v45"]


@pytest.mark.parametrize(
    "text",
    [
        "x: &a tj-actions/changed-files@v45\ny: &a actions/checkout@v4\nsteps:\n  - uses: *a\n",
        "x: &a\n  tj-actions/changed-files@v45\nsteps:\n  - uses: *a\n",
        "# &a actions/checkout@v4\nX: &a\n  tj-actions/changed-files@v45\nsteps:\n  - uses: *a\n",
        "D: see &a actions/checkout@v4\nsteps:\n  - uses: *a\n",
        "steps:\n  - run: |\n      echo &a actions/checkout@v4\n  - uses: *a\n",
    ],
)
def test_an_alias_this_gate_cannot_resolve_is_keyed_by_the_whole_file(text: str) -> None:
    assert keys({".github/workflows/a.yml": text}) == ["unparseable-uses|" + gate._digest(text)]


def test_a_short_listed_commit_matches_a_full_pin() -> None:
    text = "  - uses: reviewdog/action-setup@f0d342d24037bb11d26b9bd8496e0808ba32e9ec\n"
    assert keys({".github/workflows/a.yml": text}) == [
        "ioc-action|reviewdog/action-setup|f0d342d24037bb11d26b9bd8496e0808ba32e9ec"
    ]


@pytest.mark.parametrize("stdin", ["[]", '{"writes": []}'])
def test_main_refuses_json_of_the_wrong_shape(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], stdin: str
) -> None:
    code, out, err = run(monkeypatch, capsys, stdin)
    assert (code, out) == (2, "")
    assert "stdin is not the gate JSON" in err
