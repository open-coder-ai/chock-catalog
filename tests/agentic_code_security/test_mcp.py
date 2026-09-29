"""Agent and MCP configs are read structurally: the parsed document decides, not the line layout."""

from __future__ import annotations

import json

import pytest
from agentic_code_security.conftest import ALL_DENY
from agentic_gate import mcp
from agentic_gate.engine import evaluate
from agentic_gate.model import FileText


def judged(path: str, text: str) -> list[tuple[str, int]]:
    return [(f.rule_id, f.line_no) for f in evaluate({path: text}, ALL_DENY, lambda _p: None, human=True)]


def servers_of(path: str, text: str) -> list[str]:
    return [s.name for s in mcp.servers(FileText(path, text))]


PRETTY = """{
  "mcpServers": {
    "ok": {
      "command": "node",
      "args": ["./ok.js"]
    },
    "fs": {
      "command": "npx",
      "args": [
        "-y",
        "@scope/server-fs",
        "/work"
      ]
    }
  }
}
"""


def test_a_pretty_printed_args_array_puts_the_finding_on_the_package_line() -> None:
    assert judged(".mcp.json", PRETTY) == [("supply-mcp-unpinned-package", 11)]


def test_the_same_server_on_one_line_is_the_same_finding() -> None:
    body = json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@scope/server-fs"]}}}) + "\n"
    assert [rule for rule, _ in judged(".mcp.json", body)] == ["supply-mcp-unpinned-package"]


@pytest.mark.parametrize(
    "path",
    [
        ".mcp.json",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        "claude_desktop_config.json",
        ".gemini/settings.json",
        "cline_mcp_settings.json",
    ],
)
def test_every_known_client_config_is_read(path: str) -> None:
    assert servers_of(path, PRETTY) == ["ok", "fs"]


def test_the_codex_toml_config_is_read_and_other_toml_is_not() -> None:
    toml = '[mcp_servers.git]\ncommand = "uvx"\nargs = ["mcp-server-git"]\n'
    assert servers_of(".codex/config.toml", toml) == ["git"]
    assert servers_of("pyproject.toml", toml) == []
    assert servers_of("settings.json", PRETTY) == []


def test_server_tables_nested_in_a_larger_document_are_found() -> None:
    projects = [{"path": "/x", "mcpServers": {"a": {"command": "uvx", "args": ["pkg"]}}}]
    body = json.dumps({"projects": projects, "servers": {"b": 1}})
    assert servers_of(".mcp.json", body) == ["a"]


def test_a_line_comment_in_a_jsonc_config_is_tolerated() -> None:
    body = '{\n  // the filesystem server\n  "mcpServers": {"fs": {"command": "npx", "args": ["-y", "pkg"]}}\n}\n'
    assert [rule for rule, _ in judged(".vscode/mcp.json", body)] == ["supply-mcp-unpinned-package"]


@pytest.mark.parametrize("body", ["{not json", "[1, 2]", '{"mcpServers": []}', '{"mcpServers": {"a": 3}}', ""])
def test_a_config_that_does_not_parse_or_has_no_servers_is_silent(body: str) -> None:
    assert judged(".mcp.json", body) == []


def test_a_toml_config_that_does_not_parse_is_silent() -> None:
    assert judged(".codex/config.toml", "[mcp_servers\n") == []


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (["npx", "-y", "pkg@1.2.3"], ("npx", "pkg@1.2.3")),
        (["npx", "--yes", "--registry", "https://r.example", "pkg"], ("npx", "pkg")),
        (["npx", "-p", "pkg@1.0.0", "bin"], ("npx", "pkg@1.0.0")),
        (["npx", "--package=pkg", "bin"], ("npx", "pkg")),
        (["C:\\tools\\npx.cmd", "pkg"], ("npx", "pkg")),
        (["/usr/bin/bunx", "pkg"], ("bunx", "pkg")),
        (["uvx", "--from", "pkg==1.0", "tool"], ("uvx", "pkg==1.0")),
        (["uvx", "--from=pkg", "tool"], ("uvx", "pkg")),
        (["uvx", "--python", "3.12", "--with", "extra", "tool"], ("uvx", "tool")),
        (["uvx", "--isolated", "tool"], ("uvx", "tool")),
        (["pipx", "run", "--spec", "pkg==1.0", "tool"], ("pipx", "pkg==1.0")),
        (["pipx", "run", "tool"], ("pipx", "tool")),
    ],
)
def test_launch_finds_the_package_a_command_fetches(command: list[str], expected: tuple[str, str]) -> None:
    assert mcp.launch(command) == expected


@pytest.mark.parametrize(
    "command",
    [[], ["node", "server.js"], ["pipx", "install", "x"], ["pipx"], ["npx"], ["npx", "-y"], ["uvx", "--from"]],
)
def test_launch_is_none_when_nothing_is_fetched(command: list[str]) -> None:
    assert mcp.launch(command) is None


@pytest.mark.parametrize(
    ("tool", "spec", "pinned"),
    [
        ("npx", "pkg@1.2.3", True),
        ("npx", "@scope/pkg@1.2.3", True),
        ("npx", "pkg@1.2.3-beta.1", True),
        ("npx", "pkg", False),
        ("npx", "@scope/pkg", False),
        ("npx", "pkg@next", False),
        ("npx", "pkg@^1.2.3", False),
        ("npx", "pkg@1", False),
        ("uvx", "pkg==1.2.3", True),
        ("uvx", "pkg@1.2.3", True),
        ("uvx", "pkg[extra]==1.2", True),
        ("uvx", "pkg", False),
        ("uvx", "pkg>=1.0", False),
        ("pipx", "pkg==2", True),
    ],
)
def test_an_exact_version_is_what_pins(tool: str, spec: str, pinned: bool) -> None:
    assert mcp.is_pinned(mcp.Launch(tool, spec)) is pinned


@pytest.mark.parametrize(
    ("spec", "by_name"),
    [
        ("pkg", True),
        ("./server.js", False),
        ("/abs/x", False),
        ("~/x", False),
        ("file:../x", False),
        ("github:o/r", False),
        ("https://h/x.tgz", False),
        ("git+https://h/r", False),
        ("C:\\x", False),
    ],
)
def test_only_a_registry_package_is_fetched_by_name(spec: str, by_name: bool) -> None:
    assert mcp.is_fetched_by_name(mcp.Launch("npx", spec)) is by_name


def test_a_command_written_as_one_string_or_as_a_list_is_read() -> None:
    string = json.dumps({"mcpServers": {"a": {"command": "npx -y pkg"}}})
    listed = json.dumps({"mcpServers": {"a": {"command": ["uvx", "pkg"]}}})
    bare = json.dumps({"mcpServers": {"a": {"url": "https://x.example/mcp"}}})
    assert [r for r, _ in judged(".mcp.json", string)] == ["supply-mcp-unpinned-package"]
    assert [r for r, _ in judged(".mcp.json", listed)] == ["supply-mcp-unpinned-package"]
    assert judged(".mcp.json", bare) == []
    assert mcp.argv(mcp.Server("x", {})) == []


def test_the_finding_sits_on_the_servers_own_line_when_the_value_is_not_found() -> None:
    body = '{\n  "mcpServers": {\n    "srv": {\n      "command": "npx",\n      "args": ["-y", "pkg"]\n    }\n  }\n}\n'
    text = FileText(".mcp.json", body)
    server = mcp.servers(text)[0]
    assert mcp.line_for(text, server, "not-there") == 3
    assert mcp.line_for(text, server, '"pkg"') == 5
    assert mcp.line_for(FileText(".mcp.json", "{}"), server, "x") == 1
