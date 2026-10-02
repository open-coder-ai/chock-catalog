"""verify-mcp-allowlist: the script gate reading every MCP client config and judging its servers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import mcpkit, scriptkit

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


@pytest.mark.parametrize("path", JSON_PATHS)
def test_json_configs_are_recognised_in_any_case_and_slash(path: str) -> None:
    for spelled in (path, path.upper(), "pkg/" + path, "a\\b\\" + path.replace("/", "\\"), "./" + path.title()):
        config = mod.configs.config_for(spelled)
        assert config is not None
        assert config.kind == "json"
    assert mod.configs.config_for(path).claude is path.startswith(".claude/")


@pytest.mark.parametrize(
    ("path", "kind", "containers"),
    [
        (".zed/settings.json", "json", ("context_servers",)),
        ("opencode.json", "json", ("mcp",)),
        ("sub/OpenCode.jsonc", "json", ("mcp",)),
        (".codex/config.toml", "toml", ("mcp_servers",)),
        (".CODEX\\config.TOML", "toml", ("mcp_servers",)),
    ],
)
def test_client_specific_configs_name_their_own_server_table(path: str, kind: str, containers: tuple) -> None:
    config = mod.configs.config_for(path)
    assert (config.kind, config.containers) == (kind, containers)


@pytest.mark.parametrize(
    "path",
    [
        "package.json",
        "mcp.json",
        "x.mcp.json",
        ".codex/config.json",
        "config.toml",
        ".cursor/settings.json",
        ".claude/hooks.json",
        "settings.json",
        ".claude/settings.yaml",
    ],
)
def test_other_files_are_not_mcp_configs(path: str) -> None:
    assert mod.configs.config_for(path) is None


@pytest.mark.parametrize("tail", [".", " ", "..", ". ."])
def test_trailing_dots_and_spaces_are_dropped_as_windows_drops_them(tail: str) -> None:
    assert mod.configs.config_for(".mcp.json" + tail) is not None
    assert mod.configs.config_for(".codex\\config.toml" + tail) is not None
    assert mod.configs.is_dedicated(".cursor/mcp.json" + tail)
    assert mod.is_allowlist(".chock/mcp-allowlist.json" + tail)
    assert mod.configs.config_for(".mcp.json.bak") is None


def test_only_files_that_hold_nothing_but_servers_are_dedicated() -> None:
    dedicated = mod.configs.is_dedicated
    assert all(
        dedicated(p)
        for p in (
            ".mcp.json",
            ".CURSOR/MCP.json",
            "a\\.vscode\\mcp.json",
            "claude_desktop_config.json",
            ".kiro/settings/mcp.json",
        )
    )
    assert not any(
        dedicated(p)
        for p in (
            ".claude/settings.json",
            ".zed/settings.json",
            "opencode.json",
            ".codex/config.toml",
            ".gemini/settings.json",
            "x.mcp.json",
        )
    )


@pytest.mark.parametrize("path", [p for p in JSON_PATHS if not p.startswith(".claude/")])
def test_the_allowlisted_pinned_server_passes_in_every_config(repo: Path, path: str) -> None:
    for event in ("commit", "tool_use", "agent-commit", "stop"):
        assert found(repo, {path: mcpkit.mcp({"filesystem": FS})}, event) == []
        assert found(repo, {path: mcpkit.mcp({"filesystem": FS}, "servers")}, event) == []


@pytest.mark.parametrize("path", JSON_PATHS)
def test_an_unlisted_server_is_refused_in_every_config(repo: Path, path: str) -> None:
    pinned = {"command": "npx", "args": ["-y", "evil-mcp@1.0.0"]}
    items = found(repo, {path: mcpkit.mcp({"evil": pinned})})
    assert rules_of(items) == ["allowlist"]
    assert items[0]["path"] == path
    assert "'evil'" in items[0]["message"]


def test_each_client_s_own_shape_is_read(repo: Path) -> None:
    zed = {"context_servers": {"filesystem": {"command": {"path": "npx", "args": mcpkit.FS_ARGS, "env": {}}}}}
    zed_bad = {"context_servers": {"x": {"command": {"path": "npx", "args": ["-y", "evil"], "env": {"A_KEY": "lit"}}}}}
    opencode = {"mcp": {"filesystem": {"type": "local", "command": ["npx", *mcpkit.FS_ARGS]}}}
    opencode_bad = {
        "mcp": {"x": {"type": "remote", "url": "http://a.example.invalid/", "headers": {"Authorization": "Bearer lit"}}}
    }
    gemini_bad = {"mcpServers": {"x": {"httpUrl": "http://a.example.invalid/"}}}
    assert found(repo, {".zed/settings.json": json.dumps(zed)}) == []
    assert found(repo, {"opencode.json": json.dumps(opencode)}) == []
    assert sorted(rules_of(found(repo, {".zed/settings.json": json.dumps(zed_bad)}))) == [
        "allowlist",
        "secret",
        "unpinned",
    ]
    assert sorted(rules_of(found(repo, {"opencode.json": json.dumps(opencode_bad)}))) == ["allowlist", "secret", "url"]
    assert sorted(rules_of(found(repo, {".gemini/settings.json": json.dumps(gemini_bad)}))) == ["allowlist", "url"]
    assert found(repo, {"opencode.json": json.dumps({"mcpServers": {"x": EVIL}})}) == []


def toml(name: str, body: str) -> str:
    return f"[mcp_servers.{name}]\n{body}\n"


def test_codex_toml_tables_are_judged(repo: Path) -> None:
    ok = toml(
        "filesystem", 'command = "npx"\nargs = ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/work"]'
    )
    assert found(repo, {".codex/config.toml": ok}) == []
    remote = toml(
        "docs",
        'url = "https://mcp.example.invalid/mcp"\nbearer_token_env_var = "DOCS_TOKEN"\n[mcp_servers.docs.env_http_headers]\nX-Key = "DOCS_KEY"',
    )
    assert found(repo, {".codex/config.toml": remote}) == []
    bad = toml(
        "x",
        'command = "npx"\nargs = ["-y", "p"]\n[mcp_servers.x.env]\nAPI_KEY = "lit"\n[mcp_servers.x.http_headers]\nAuthorization = "lit"',
    )
    assert sorted(rules_of(found(repo, {".codex/config.toml": bad}))) == ["allowlist", "secret", "secret", "unpinned"]
    assert found(repo, {".codex/config.toml": 'model = "x"\nmcp_servers = 3\n'}) == []


def test_comments_and_trailing_commas_do_not_hide_a_server(repo: Path) -> None:
    text = '// note\n{\n  /* block */ "mcpServers": {\n    "x": {"command": "npx", "args": ["-y", "evil@latest",],}, // why\n  },\n}\n'
    assert sorted(rules_of(found(repo, {".mcp.json": text}))) == ["allowlist", "unpinned"]
    assert found(repo, {".mcp.json": "﻿" + mcpkit.mcp({"filesystem": FS})}) == []


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


@pytest.mark.parametrize(
    ("path", "text"),
    [
        (".mcp.json", '{"mcpServers": {'),
        (".mcp.json", "{}}"),
        (".mcp.json", '{"a": NaN}'),
        (".mcp.json", '{"__proto__": 1}'),
        (".codex/config.toml", "[mcp_servers.x\ncommand = "),
        (".codex/config.toml", "[a]\nb = 1\n[a]\nc = 2\n"),
    ],
)
def test_a_config_that_cannot_be_parsed_is_refused_as_unverifiable(repo: Path, path: str, text: str) -> None:
    items = found(repo, {path: text})
    assert len(items) == 1
    assert "cannot be verified" in items[0]["message"]
    assert items[0]["key"].startswith("unreadable|")


def test_a_server_entry_that_is_not_an_object_is_refused(repo: Path) -> None:
    items = found(repo, {".mcp.json": mcp_text({"evil": "not-an-object", "other": ["x"], "bad": {"command": 3}})})
    assert rules_of(items) == ["unreadable-entry"] * 3
    assert all("cannot be verified" in i["message"] for i in items)


def mcp_text(servers: dict) -> str:
    return mcpkit.mcp(servers)


def test_files_that_are_not_mcp_configs_and_configs_without_servers_pass(repo: Path) -> None:
    writes = {
        "package.json": mcpkit.mcp({"evil": EVIL}),
        "src/app.py": "x = 1\n",
        ".mcp.json": "[]",
        ".cursor/mcp.json": '{"mcpServers": 3}',
        "claude_desktop_config.json": "{}",
    }
    assert found(repo, writes) == []


def test_the_line_names_where_the_server_is_declared(repo: Path) -> None:
    text = json.dumps({"mcpServers": {"evil": EVIL}}, indent=2)
    (item,) = (i for i in found(repo, {".mcp.json": text}) if i["key"].startswith("allowlist"))
    assert item["line"] == 3
    (item,) = found(repo, {".mcp.json": "{"})
    assert item["line"] == 1


def test_the_same_server_in_two_files_is_two_findings(repo: Path) -> None:
    writes = {".mcp.json": mcpkit.mcp({"evil": EVIL}), ".cursor/mcp.json": mcpkit.mcp({"evil": EVIL})}
    assert [i["path"] for i in found(repo, writes)].count(".mcp.json") == 2
    assert len(found(repo, writes)) == 4


def test_a_backslash_path_is_reported_with_forward_slashes(repo: Path) -> None:
    (item,) = (i for i in found(repo, {".cursor\\mcp.json": mcpkit.mcp({"evil": FS})}) if "allowlist" in i["key"])
    assert item["path"] == ".cursor/mcp.json"


def test_keys_are_secret_free_and_change_with_the_entry(repo: Path) -> None:
    secret = {
        "command": "npx",
        "args": ["-y", "evil@latest", "--token", "SECRET-VALUE-123"],
        "env": {"API_KEY": "SECRET-ENV-9"},
    }
    items = found(repo, {".mcp.json": mcpkit.mcp({"evil": secret})})
    assert "SECRET" not in json.dumps(items)
    other = found(repo, {".mcp.json": mcpkit.mcp({"evil": {**secret, "env": {"API_KEY": "x"}}})})
    assert {i["key"] for i in items}.isdisjoint(i["key"] for i in other)


def test_the_manifest_declares_the_script_gate_beside_the_guard() -> None:
    manifest = scriptkit.manifest(mcpkit.POLICY)
    gate = manifest["hook"]["gate"]
    assert gate["kind"] == "script"
    assert {"commit", "tool_use"} <= set(gate["on"])
    assert gate["params"] == {"script": "verify-mcp-allowlist_gate.py"}
    assert manifest["artifact"] == "rule"
    assert scriptkit.script_path(mcpkit.POLICY, f"{mcpkit.POLICY}.py").is_file()
