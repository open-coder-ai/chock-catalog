"""Waivers and the HEAD baseline: only new findings are refused, and a waiver is a human's."""

from __future__ import annotations

from pathlib import Path

import pytest
from agentic_code_security.conftest import commit, run_gate
from policies import gatekit, scriptkit

TLS = "comms-tls-verify-disabled"
BAD_LINE = "requests.get(u, verify=False)"
PLAIN = "import requests\n\n"
REFUSE, PASS = 1, 0
PATH = "agent/tls.py"
NAME = "agentic-code-security"


def at_pre_tool_use(repo: Path, writes: dict[str, str]) -> int:
    """The engine's verdict as the agent writes: the baseline is the file on disk."""
    return gatekit.judge(NAME, repo, gatekit.PRE_TOOL_USE, writes)[0]


def at_stop(repo: Path, writes: dict[str, str]) -> int:
    """The engine's verdict at the turn's end: disk holds the writes, so the baseline is HEAD."""
    scriptkit.write(repo, writes)
    return gatekit.judge(NAME, repo, gatekit.STOP, writes)[0]


def at_commit(repo: Path, writes: dict[str, str]) -> tuple[int, str]:
    """The engine's verdict on the staged writes, against HEAD."""
    scriptkit.write(repo, writes)
    scriptkit.git(repo, "add", "-A")
    return gatekit.judge(NAME, repo, gatekit.COMMIT)


def waived_py(rule: str = TLS) -> str:
    return f"{PLAIN}{BAD_LINE}  # chock: allow {rule}\n"


def test_a_waiver_is_honoured_at_commit(tmp_path: Path) -> None:
    assert run_gate(tmp_path, {PATH: waived_py()})[0] == PASS


def test_a_waiver_names_the_rule_it_waives(tmp_path: Path) -> None:
    assert run_gate(tmp_path, {PATH: waived_py("some-other-rule")})[0] == REFUSE


def test_a_waiver_can_name_several_rules(tmp_path: Path) -> None:
    text = f"import ssl\nimport requests\n\nc = ssl.CERT_NONE; {BAD_LINE}  # chock: allow comms-ssl-context-unverified, {TLS}\n"
    assert run_gate(tmp_path, {PATH: text})[0] == PASS


def test_a_js_waiver_uses_slashes(tmp_path: Path) -> None:
    line = "const a = new https.Agent({ rejectUnauthorized: false });"
    assert run_gate(tmp_path, {"a.js": f"{line}\n"})[0] == REFUSE
    assert run_gate(tmp_path, {"a.js": f"{line} // chock: allow comms-node-tls-disabled\n"})[0] == PASS


def test_a_yaml_or_toml_waiver_uses_hash(tmp_path: Path) -> None:
    yml = 'env:\n  NODE_TLS_REJECT_UNAUTHORIZED: "0"  # chock: allow comms-node-tls-disabled\n'
    assert run_gate(tmp_path, {"ci/env.yaml": yml})[0] == PASS
    toml = '[mcp_servers.r]\nurl = "http://mcp.example.com/mcp"  # chock: allow supply-mcp-remote-http\n'
    assert run_gate(tmp_path, {".codex/config.toml": toml})[0] == PASS


def test_a_waiver_on_the_comment_line_above_is_honoured(tmp_path: Path) -> None:
    text = f"{PLAIN}# chock: allow {TLS}\n{BAD_LINE}\n"
    assert run_gate(tmp_path, {PATH: text})[0] == PASS


def test_a_waiver_two_lines_above_or_after_code_is_not_a_waiver(tmp_path: Path) -> None:
    far = f"{PLAIN}# chock: allow {TLS}\n\n{BAD_LINE}\n"
    assert run_gate(tmp_path, {PATH: far})[0] == REFUSE
    code_line = f"{PLAIN}x = 1  # chock: allow {TLS}\n{BAD_LINE}\n"
    assert run_gate(tmp_path, {PATH: code_line})[0] == REFUSE


def test_json_has_no_comments_so_no_waiver(tmp_path: Path) -> None:
    body = '{"mcpServers": {"r": {\n// chock: allow supply-mcp-remote-http\n"url": "http://mcp.example.com/sse"}}}\n'
    code, err = run_gate(tmp_path, {".mcp.json": body})
    assert code == REFUSE
    assert "supply-mcp-remote-http" in err


def test_the_selection_file_is_how_json_is_waived(tmp_path: Path) -> None:
    body = '{"mcpServers": {"r": {"url": "http://mcp.example.com/sse"}}}\n'
    allow = {"version": 1, "packs": {"supply": {"rules": {"supply-mcp-remote-http": "allow"}}}}
    assert run_gate(tmp_path, {".mcp.json": body}, allow)[0] == PASS


def test_an_agent_added_waiver_is_refused_at_tool_use(tmp_path: Path) -> None:
    code, err = run_gate(tmp_path, {PATH: waived_py()}, event="tool_use")
    assert code == REFUSE
    assert TLS in err
    assert "never the agent's" in err


def test_an_agent_added_waiver_is_refused_at_the_turns_end(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: f"{PLAIN}requests.get(u)\n"})
    assert run_gate(tmp_path, {PATH: waived_py()}, event="stop")[0] == REFUSE


def test_a_waiver_a_human_committed_is_honoured_for_the_agent(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: waived_py()})
    edited = waived_py() + "other = 1\n"
    assert run_gate(tmp_path, {PATH: edited}, event="tool_use")[0] == PASS
    assert run_gate(tmp_path, {PATH: edited}, event="stop")[0] == PASS


def test_a_committed_waiver_pasted_elsewhere_is_refused_for_the_agent(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: waived_py()})
    twice = waived_py() + f"requests.post(u, verify=False)  # chock: allow {TLS}\n"
    code, err = run_gate(tmp_path, {PATH: twice}, event="tool_use")
    assert code == REFUSE
    assert f"{PATH}:4:" in err


def test_a_committed_waiver_on_a_line_the_agent_changed_is_refused(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: waived_py()})
    moved = f"{PLAIN}requests.post(u, verify=False)  # chock: allow {TLS}\n"
    assert run_gate(tmp_path, {PATH: moved}, event="tool_use")[0] == REFUSE


def test_the_agent_is_judged_on_what_it_adds_not_the_whole_file(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: f"{PLAIN}{BAD_LINE}\n"})
    same = f"{PLAIN}{BAD_LINE}\nx = 1\n"
    assert at_pre_tool_use(tmp_path, {PATH: same}) == PASS
    assert at_stop(tmp_path, {PATH: same}) == PASS
    added = f"{PLAIN}{BAD_LINE}\nrequests.post(u, verify=False)\n"
    assert at_pre_tool_use(tmp_path, {PATH: added}) == REFUSE


def test_a_commit_refuses_only_what_is_new(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: f"{PLAIN}{BAD_LINE}\n"})
    assert at_commit(tmp_path, {PATH: f"{PLAIN}{BAD_LINE}\nx = 1\n"})[0] == PASS
    added = f"{PLAIN}{BAD_LINE}\nrequests.post(u, verify=False)\nx = 1\n"
    code, err = at_commit(tmp_path, {PATH: added})
    assert code == REFUSE
    assert f"{PATH}:4:" in err
    assert f"{PATH}:3:" not in err


def test_a_finding_moved_to_another_line_is_still_not_new(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: f"{PLAIN}{BAD_LINE}\n"})
    assert at_stop(tmp_path, {PATH: f"{PLAIN}y = 2\n\n{BAD_LINE}\n"}) == PASS


def test_a_copy_of_a_committed_finding_is_new(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: f"{PLAIN}{BAD_LINE}\n"})
    assert at_commit(tmp_path, {PATH: f"{PLAIN}{BAD_LINE}\n{BAD_LINE}\n"})[0] == REFUSE


def test_a_new_file_is_all_new(tmp_path: Path) -> None:
    commit(tmp_path, {"other.py": "x = 1\n"})
    assert at_commit(tmp_path, {PATH: f"{PLAIN}{BAD_LINE}\n"})[0] == REFUSE


def test_a_path_outside_the_repository_has_no_head(tmp_path: Path) -> None:
    commit(tmp_path, {"other.py": "x = 1\n"})
    outside = str(tmp_path.parent / "elsewhere.py")
    assert run_gate(tmp_path, {outside: f"{PLAIN}{BAD_LINE}\n"})[0] == REFUSE


def test_an_absolute_path_inside_the_repository_reads_its_head_for_the_waiver(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: waived_py()})
    inside = str(tmp_path / PATH)
    assert run_gate(tmp_path, {inside: waived_py() + "x = 1\n"}, event="tool_use")[0] == PASS


@pytest.mark.parametrize("event", ["tool_use", "stop"])
def test_clean_agent_writes_pass_without_the_waiver_notice(tmp_path: Path, event: str) -> None:
    code, err = run_gate(tmp_path, {"a.py": "x = 1\n"}, event=event)
    assert (code, err) == (PASS, "")
