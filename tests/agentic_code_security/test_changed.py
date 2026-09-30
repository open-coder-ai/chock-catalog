"""The gate judges what a change adds: an old violation in a touched file passes, a new one is refused."""

from __future__ import annotations

from pathlib import Path

import pytest
from agentic_code_security.conftest import commit, run_gate
from agentic_gate import changed, mcp
from agentic_gate.model import FileText, Finding

REFUSE, PASS = 1, 0
EVENTS = ["commit", "tool_use"]
HEAD_LINES = "import subprocess\nfrom langchain.tools import tool\n\n\n@tool\ndef run(cmd: str) -> str:\n"
TLS = "import requests\n\nrequests.get(u, verify=False)\n"
PATH = "agents/tool.py"


def tool(*body: str) -> str:
    return HEAD_LINES + "".join(f"    {line}\n" for line in body)


OLD_FLOW = tool("command = cmd", "return subprocess.run(command, shell=True)")
CLEAN_FLOW = tool("command = 'ls'", "return subprocess.run(command, shell=True)")


def cfg(*servers: str) -> str:
    return '{\n  "mcpServers": {\n' + ",\n".join(servers) + "\n  }\n}\n"


def server(name: str, command: str, arg: str) -> str:
    return f'    "{name}": {{\n      "command": "{command}",\n      "args": ["-y", "{arg}"]\n    }}'


@pytest.mark.parametrize("event", [*EVENTS, "stop"])
def test_an_old_violation_beside_an_unrelated_new_line_passes(tmp_path: Path, event: str) -> None:
    commit(tmp_path, {"a.py": TLS, PATH: OLD_FLOW})
    assert run_gate(tmp_path, {"a.py": TLS + "x = 1\n"}, event=event)[0] == PASS
    assert run_gate(tmp_path, {PATH: OLD_FLOW + "\n\ndef one() -> int:\n    return 1\n"}, event=event)[0] == PASS


@pytest.mark.parametrize("event", EVENTS)
def test_a_new_violation_is_refused_and_a_clean_edit_is_not(tmp_path: Path, event: str) -> None:
    commit(tmp_path, {"a.py": "import requests\n"})
    code, err = run_gate(tmp_path, {"a.py": TLS}, event=event)
    assert (code, "a.py:3:" in err) == (REFUSE, True)
    assert run_gate(tmp_path, {"a.py": "import requests\nx = 1\n"}, event=event)[0] == PASS


@pytest.mark.parametrize("event", EVENTS)
def test_a_new_file_is_judged_whole(tmp_path: Path, event: str) -> None:
    commit(tmp_path, {"README.txt": "x\n"})
    assert run_gate(tmp_path, {"a.py": TLS}, event=event)[0] == REFUSE
    assert run_gate(tmp_path, {"a.py": "x = 1\n"}, event=event)[0] == PASS


def test_at_tool_use_the_baseline_is_the_disk_not_head(tmp_path: Path) -> None:
    commit(tmp_path, {"a.py": "import requests\n"})
    (tmp_path / "a.py").write_text(TLS, encoding="utf-8")
    assert run_gate(tmp_path, {"a.py": TLS + "x = 1\n"}, event="tool_use")[0] == PASS
    assert run_gate(tmp_path, {"a.py": TLS + "x = 1\n"}, event="commit")[0] == REFUSE


def test_at_the_turns_end_the_baseline_is_head_because_disk_holds_the_write(tmp_path: Path) -> None:
    commit(tmp_path, {"a.py": TLS})
    doubled = TLS + "requests.post(u, verify=False)\n"
    (tmp_path / "a.py").write_text(doubled, encoding="utf-8")
    assert run_gate(tmp_path, {"a.py": doubled}, event="tool_use")[0] == REFUSE


@pytest.mark.parametrize("event", EVENTS)
def test_a_line_that_completes_a_flow_into_an_old_sink_is_refused(tmp_path: Path, event: str) -> None:
    commit(tmp_path, {PATH: CLEAN_FLOW})
    code, err = run_gate(tmp_path, {PATH: OLD_FLOW}, event=event)
    assert (code, f"{PATH}:8:" in err) == (REFUSE, True)


@pytest.mark.parametrize("event", EVENTS)
def test_a_new_sink_fed_by_an_old_source_is_refused(tmp_path: Path, event: str) -> None:
    commit(tmp_path, {PATH: tool("command = cmd", "print(command)")})
    after = tool("command = cmd", "print(command)", "subprocess.run(command, shell=True)")
    assert run_gate(tmp_path, {PATH: after}, event=event)[0] == REFUSE


@pytest.mark.parametrize("hop", ["moved = command", "moved: str = command", "moved = ''\n    moved += command"])
def test_a_new_hop_between_source_and_sink_is_part_of_the_flow(tmp_path: Path, hop: str) -> None:
    before = tool("command = cmd", "moved = 'ls'", "return subprocess.run(moved, shell=True)")
    after = tool("command = cmd", hop, "return subprocess.run(moved, shell=True)")
    commit(tmp_path, {PATH: before})
    assert run_gate(tmp_path, {PATH: after}, event="commit")[0] == REFUSE


def test_an_edit_to_an_assignment_the_flow_does_not_touch_leaves_it_old(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: tool("n = 1", "command = cmd", "return subprocess.run(command, shell=True)")})
    after = tool("n = 2", "command = cmd", "return subprocess.run(command, shell=True)")
    assert run_gate(tmp_path, {PATH: after}, event="commit")[0] == PASS


def test_a_changed_signature_is_part_of_the_flow(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: OLD_FLOW.replace("cmd: str", "cmd: int")})
    assert run_gate(tmp_path, {PATH: OLD_FLOW}, event="commit")[0] == REFUSE


def test_a_new_line_that_builds_the_sql_of_an_old_execute_is_refused(tmp_path: Path) -> None:
    before = "def f(cur, uid):\n    q = 'select 1'\n    cur.execute(q)\n"
    commit(tmp_path, {"db.py": before})
    after = before.replace("'select 1'", "f'select {uid}'")
    assert run_gate(tmp_path, {"db.py": after}, event="commit")[0] == REFUSE


def test_a_new_line_that_binds_the_memory_client_makes_old_calls_findings(tmp_path: Path) -> None:
    before = "from mem0 import Memory\n\nmemory = build()\nmemory.add('x')\n"
    commit(tmp_path, {"m.py": before})
    selection = {"version": 1, "packs": {"prompt-memory": {"verdict": "deny"}}}
    assert run_gate(tmp_path, {"m.py": before.replace("build()", "Memory()")}, selection, "commit")[0] == REFUSE
    assert run_gate(tmp_path, {"m.py": before + "y = 1\n"}, selection, "commit")[0] == PASS


def test_a_change_on_a_later_line_of_a_multi_line_call_is_a_change_to_its_finding(tmp_path: Path) -> None:
    def agent(mode: str) -> str:
        return f'a = UserProxyAgent(\n    "u",\n    human_input_mode="{mode}",\n    code_execution_config=cfg,\n)\n'

    commit(tmp_path, {"p.py": agent("ALWAYS")})
    assert run_gate(tmp_path, {"p.py": agent("NEVER")}, event="commit")[0] == REFUSE
    commit(tmp_path, {"q.py": agent("NEVER")})
    assert run_gate(tmp_path, {"q.py": agent("NEVER") + "x = 1\n"}, event="commit")[0] == PASS


def test_a_server_entry_is_judged_whole_and_an_added_server_leaves_the_old_one_alone(tmp_path: Path) -> None:
    old = cfg(server("x", "npx", "@scope/pkg"))
    commit(tmp_path, {"cfg/.mcp.json": old})
    added = cfg(server("x", "npx", "@scope/pkg"), server("y", "npx", "@scope/other@1.2.3"))
    assert run_gate(tmp_path, {"cfg/.mcp.json": added}, event="commit")[0] == PASS
    edited = cfg(server("x", "npx", "@scope/pkg").replace('"-y", ', '"-y", "-q", '))
    assert run_gate(tmp_path, {"cfg/.mcp.json": edited}, event="commit")[0] == REFUSE


def test_the_lines_of_an_mcp_entry() -> None:
    text = FileText("a/.mcp.json", cfg(server("x", "npx", "p"), server("y", "npx", "q")))
    first, second = mcp.servers(text)
    assert (mcp.block(text, first), mcp.block(text, second)) == ((3, 4, 5, 6), (7, 8, 9, 10))
    unclosed = FileText("a/.mcp.json", '{"mcpServers": {"x": {"args": ["{"]}}}\n')
    assert mcp.block(unclosed, mcp.Server("x", {})) == (1,)
    assert mcp.block(unclosed, mcp.Server("gone", {})) == (1,)


def test_the_lines_of_a_toml_entry() -> None:
    body = '[mcp_servers.x]\ncommand = "npx"\n[mcp_servers.x.env]\nA = "1"\n\n[mcp_servers.y]\ncommand = "b"\n'
    text = FileText("a/.codex/config.toml", body)
    first, second = mcp.servers(text)
    assert (mcp.block(text, first), mcp.block(text, second)) == ((1, 2, 3, 4, 5), (6, 7))
    assert mcp.block(text, mcp.Server("y", {})) == (6, 7)


def test_new_lines_counts_copies_and_ignores_indentation_and_a_trailing_comma() -> None:
    assert changed.new_lines(["a", "b"], None) == {1, 2}
    assert changed.new_lines(["a", "a", "b"], "a\nb\n") == {2}
    assert changed.new_lines(["  a,", "b"], "a\n  b,\n") == set()


def test_a_statement_is_its_lines_and_a_compound_statement_is_its_header() -> None:
    body = (
        "@deco\ndef f(a,\n      b):\n    x = call(1,\n             2)\n    if x: y = 1\n    for i in z:\n        pass\n"
    )
    text = FileText("a.py", body)
    assert changed.statement(text, 5) == range(4, 6)
    assert changed.statement(text, 2) == range(1, 4)
    assert changed.statement(text, 1) == range(1, 4)
    assert changed.statement(text, 6) == range(6, 7)
    assert changed.statement(text, 7) == range(7, 8)
    assert changed.statement(text, 99) == range(99, 100)


def test_a_statement_longer_than_the_limit_and_other_files_stand_for_the_line() -> None:
    long = FileText("a.py", "x = [\n" + "".join(f"    {i},\n" for i in range(70)) + "]\n")
    assert changed.statement(long, 3) == range(3, 4)
    assert changed.statement(FileText("a.py", "def ("), 1) == range(1, 2)
    assert changed.statement(FileText("a.yaml", "a: [1,\n  2]\n"), 1) == range(1, 2)


def test_only_new_keeps_a_finding_that_is_a_diff_whatever_it_touched() -> None:
    text = FileText("a.py", "x = 1\ny = 2\n")
    plain, diff = Finding("r", "a.py", 1, "x", "m"), Finding("r", "a.py", 1, "x", "m", by_diff=True)
    assert changed.only_new([plain, diff], text, text.text) == [diff]
    assert changed.only_new([plain], text, "x = 1\n") == []
    assert changed.only_new([plain], text, "y = 2\n") == [plain]


def test_the_baseline_reads_disk_only_at_tool_use(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("disk", encoding="utf-8")
    head = {"a.txt": "head", "gone.txt": "head"}.get
    assert changed.baseline(tmp_path, "a.txt", "new", "tool_use", head) == "disk"
    assert changed.baseline(tmp_path, "a.txt", "disk", "tool_use", head) == "head"
    assert changed.baseline(tmp_path, "a.txt", "new", "commit", head) == "head"
    assert changed.baseline(tmp_path, "gone.txt", "new", "tool_use", head) == "head"
    assert changed.baseline(tmp_path, "none.txt", "new", "tool_use", head) is None
    assert changed.on_disk(tmp_path, "none.txt") is None
