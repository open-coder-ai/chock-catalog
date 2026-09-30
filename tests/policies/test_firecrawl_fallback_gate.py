"""firecrawl-fallback-only: the tool_call gate that warns on Firecrawl before any native fetch failed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import scriptkit, toolcallkit
from policies.toolcallkit import payload, record, write_log

POLICY = "firecrawl-fallback-only"
NAME = "firecrawl-fallback-gate.py"
TOOL = "mcp__Firecrawl__firecrawl_scrape"
mod = scriptkit.load(POLICY, NAME)
WEB = {"url": "https://example.com/a"}
FAILED = [
    [record("WebFetch", "post", "error", **WEB)],
    [record("WebSearch", "post", "error")],
    [record("Bash", "post", "error", command="curl -sS https://example.com")],
    [record("Bash", "post", "error", command="/usr/bin/wget https://example.com")],
    [record("WebFetch", "pre", **WEB), record("WebFetch", "post", "ok", **WEB), record("WebSearch", "post", "error")],
]
NOT_FAILED = [
    [],
    [record("WebFetch", "post", "ok", **WEB)],
    [record("WebFetch", "pre", **WEB)],
    [record("Bash", "post", "error", command="make test")],
    [record("Bash", "post", "error", command="")],
    [record("Bash", "post", "ok", command="curl -sS https://example.com")],
    [record("Read", "post", "error", path="a.py")],
]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return toolcallkit.make_repo(tmp_path)


def test_the_manifest_declares_a_warn_script_gate_on_firecrawl_tools() -> None:
    manifest = scriptkit.manifest(POLICY)
    gate = manifest["hook"]["gate"]
    assert (gate["kind"], gate["on"], gate["action"]) == ("script", ["tool_call"], "warn")
    assert gate["params"] == {"script": NAME, "tools": ["mcp__*Firecrawl__*"]}
    assert manifest["enforcement"] == "advise"


@pytest.mark.parametrize("records", FAILED)
def test_a_failed_native_fetch_lets_firecrawl_through(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], records: list[dict]
) -> None:
    write_log(repo, records)
    assert toolcallkit.fire(mod, monkeypatch, capsys, payload(repo, TOOL, WEB)) == (0, "")


@pytest.mark.parametrize("records", NOT_FAILED)
def test_no_failed_native_fetch_warns_and_never_blocks(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], records: list[dict]
) -> None:
    write_log(repo, records)
    code, err = toolcallkit.fire(mod, monkeypatch, capsys, payload(repo, TOOL, WEB))
    assert code == 4
    assert "fallback" in err


def test_the_current_calls_own_record_is_not_a_failure(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write_log(repo, [record("WebFetch", "post", "error", call="now", **WEB)])
    assert toolcallkit.fire(mod, monkeypatch, capsys, payload(repo, TOOL, WEB))[0] == 4


def test_a_missing_or_damaged_log_warns_rather_than_blocks(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert toolcallkit.fire(mod, monkeypatch, capsys, payload(repo, TOOL, WEB))[0] == 4
    (repo / ".chock" / "state").mkdir()
    (repo / ".chock" / "state" / f"{toolcallkit.SESSION}.jsonl").write_text("{not json\n[1]\n", encoding="utf-8")
    assert toolcallkit.fire(mod, monkeypatch, capsys, payload(repo, TOOL, WEB))[0] == 4


def test_an_install_without_the_session_reader_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bare = toolcallkit.make_repo(tmp_path, vendored=False)
    monkeypatch.delitem(__import__("sys").modules, "chock_session", raising=False)
    monkeypatch.setattr("sys.path", [p for p in __import__("sys").path if not p.endswith(".chock/bin")])
    assert toolcallkit.fire(mod, monkeypatch, capsys, payload(bare, TOOL, WEB))[0] == 4


def test_run_as_a_process_it_speaks_by_exit_code(repo: Path) -> None:
    write_log(repo, [record("WebFetch", "post", "error", **WEB)])
    assert scriptkit.run_script(POLICY, NAME, repo, json.dumps(payload(repo, TOOL, WEB)))[0] == 0
    write_log(repo, [])
    code, err = scriptkit.run_script(POLICY, NAME, repo, json.dumps(payload(repo, TOOL, WEB)))
    assert (code, "fallback" in err) == (4, True)
