"""verify-mcp-allowlist: JSONC, repeated keys and the Claude settings switches in the script gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import mcpkit

mod = mcpkit.gate()
FS, EVIL = mcpkit.FS, mcpkit.EVIL
HEAD = {".chock/mcp-allowlist.json": mcpkit.allowlist_text(mcpkit.FS_ALLOWED, mcpkit.REMOTE_ALLOWED)}
JSON_PATHS = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".windsurf/mcp_config.json",
    ".roo/mcp.json",
    ".kiro/settings/mcp.json",
    "claude_desktop_config.json",
    ".gemini/settings.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/settings.team.json",
]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return mcpkit.repo_with(tmp_path, head=HEAD)


def payload(repo: Path, writes: dict[str, str], event: str = "commit") -> dict:
    return {"event": event, "repo_root": str(repo), "writes": writes}


def found(repo: Path, writes: dict[str, str], event: str = "commit") -> list[dict]:
    return mod.findings(payload(repo, writes, event))


def rules_of(items: list[dict]) -> list[str]:
    return [item["key"].split("|")[0] for item in items]


def test_comments_and_trailing_commas_do_not_hide_a_server(repo: Path) -> None:
    text = '// note\n{\n  /* block */ "mcpServers": {\n    "x": {"command": "npx", "args": ["-y", "evil@latest",],}, // why\n  },\n}\n'
    assert sorted(rules_of(found(repo, {".mcp.json": text}))) == ["allowlist", "unpinned"]
    assert found(repo, {".mcp.json": "\ufeff" + mcpkit.mcp({"filesystem": FS})}) == []


def test_a_repeated_server_name_judges_every_value(repo: Path) -> None:
    text = (
        '{"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "evil@latest"]}, "filesystem": '
        + json.dumps(FS)
        + "}}"
    )
    items = found(repo, {".mcp.json": text})
    assert "duplicate-key" in rules_of(items)
    assert {"allowlist", "unpinned"} <= set(rules_of(items))
    both = '{"mcpServers": ' + json.dumps({"a": EVIL}) + ', "mcpServers": ' + json.dumps({"filesystem": FS}) + "}"
    assert {"duplicate-key", "allowlist"} <= set(rules_of(found(repo, {".mcp.json": both})))
    assert "duplicate-key" in rules_of(found(repo, {".mcp.json": '{"note": 1, "note": 2}'}))
    elsewhere = '{"other": {"a": 1, "a": 2}, "mcpServers": {}}'
    assert rules_of(found(repo, {".mcp.json": elsewhere})) == ["duplicate-key"]


def test_the_duplicate_key_finding_changes_with_the_hidden_value(repo: Path) -> None:
    def key(hidden: str) -> str:
        text = (
            '{"mcpServers": {"filesystem": {"command": "x", "args": ["'
            + hidden
            + '"]}, "filesystem": '
            + json.dumps(FS)
            + "}}"
        )
        return next(i["key"] for i in found(repo, {".mcp.json": text}) if i["key"].startswith("duplicate-key"))

    assert key("one") != key("two")


def test_enable_all_project_servers_is_refused_unless_false(repo: Path) -> None:
    for value in (True, "true", 1, "false", None):
        items = found(repo, {".claude/settings.json": json.dumps({"enableAllProjectMcpServers": value})})
        assert rules_of(items) == ["enable-all"], value
    assert found(repo, {".claude/settings.json": json.dumps({"enableAllProjectMcpServers": False})}) == []
    assert found(repo, {".mcp.json": json.dumps({"enableAllProjectMcpServers": True})}) == []


def test_an_enabled_project_server_must_be_on_the_allowlist(repo: Path) -> None:
    settings = {"enabledMcpjsonServers": ["filesystem", "docs", "evil"]}
    items = found(repo, {".claude/settings.local.json": json.dumps(settings)})
    assert [i["key"] for i in items] == ["enabled|evil"]
    assert "'evil'" in items[0]["message"]


@pytest.mark.parametrize("value", ["filesystem", [1], {"a": 1}, None])
def test_an_enabled_list_that_is_not_names_is_refused(repo: Path, value: object) -> None:
    items = found(repo, {".claude/settings.json": json.dumps({"enabledMcpjsonServers": value})})
    assert rules_of(items) == ["enabled-unreadable"]


def test_a_claude_settings_file_with_no_mcp_content_passes(repo: Path) -> None:
    settings = {"permissions": {"allow": ["Bash(git status)"]}, "enabledMcpjsonServers": []}
    assert found(repo, {".claude/settings.json": json.dumps(settings)}) == []
