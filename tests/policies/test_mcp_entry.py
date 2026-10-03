"""verify-mcp-allowlist: allowlist matching, entry reading and the curated tables."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import mcpkit

g = mcpkit.gate()
rules, entry, allowlist, tables = g.rules, g.entry, g.allowlist, g.rules.tables
D = mcpkit.DIGEST


def server(config: dict, name: str = "s") -> object:
    return entry.from_config(name, config)


def rule_names(config: dict, allowed: tuple = ()) -> list[str]:
    return [rule for rule, _ in rules.judge(server(config), allowed)]


def allowed(*items: dict) -> tuple:
    return allowlist.parse(mcpkit.allowlist_text(*items))


PIN = ["pkg@1.0.0"]
FS = mcpkit.FS_ALLOWED
REMOTE = mcpkit.REMOTE_ALLOWED


@pytest.mark.parametrize(
    ("config", "name", "want"),
    [
        (mcpkit.FS, "filesystem", []),
        (mcpkit.FS, "other", ["allowlist"]),
        (mcpkit.FS, "Filesystem", ["allowlist"]),
        ({"command": "npx", "args": [*mcpkit.FS_ARGS, "/"]}, "filesystem", ["allowlist"]),
        ({"command": "npx", "args": mcpkit.FS_ARGS[:2]}, "filesystem", ["allowlist"]),
        ({"command": "npx", "args": mcpkit.FS_ARGS, "env": {"LOG": "1"}}, "filesystem", []),
        ({"command": "./npx", "args": mcpkit.FS_ARGS}, "filesystem", ["allowlist"]),
        ({"command": "/opt/evil/npx", "args": mcpkit.FS_ARGS}, "filesystem", ["allowlist"]),
        ({"command": "NPX", "args": mcpkit.FS_ARGS}, "filesystem", ["allowlist"]),
        (
            {"command": "npx", "args": mcpkit.FS_ARGS, "url": "https://mcp.example.invalid/"},
            "filesystem",
            ["allowlist"],
        ),
        ({"url": "https://mcp.example.invalid/sse"}, "docs", []),
        ({"url": "https://MCP.example.invalid./sse"}, "docs", []),
        ({"url": "https://mcp.example.invalid:8443/sse"}, "docs", []),
        ({"httpUrl": "https://mcp.example.invalid/sse", "serverUrl": "https://evil.invalid/"}, "docs", ["allowlist"]),
        ({"url": "https://evil.invalid/sse"}, "docs", ["allowlist"]),
        ({"url": "https://mcp.example.invalid.evil.invalid/sse"}, "docs", ["allowlist"]),
        ({"url": "https://sub.mcp.example.invalid/sse"}, "docs", ["allowlist"]),
        ({"url": "https://evil.invalid\\@mcp.example.invalid/"}, "docs", ["allowlist"]),
        ({"command": "npx", "args": PIN}, "docs", ["allowlist"]),
        ({"command": "npx", "args": PIN, "url": "https://mcp.example.invalid/"}, "docs", ["allowlist"]),
    ],
)
def test_a_server_matches_its_allowlist_entry_exactly(config: dict, name: str, want: list[str]) -> None:
    assert [r for r in rule_names_named(config, name, allowed(FS, REMOTE)) if r == "allowlist"] == want


def rule_names_named(config: dict, name: str, allow: tuple) -> list[str]:
    return [rule for rule, _ in rules.judge(entry.from_config(name, config), allow)]


def test_a_wildcard_host_matches_subdomains_only() -> None:
    wild = allowed({"name": "docs", "url_host": "*.example.invalid"})
    assert rule_names_named({"url": "https://a.example.invalid/"}, "docs", wild) == []
    assert rule_names_named({"url": "https://example.invalid/"}, "docs", wild) == ["allowlist"]


def test_an_allowed_entry_never_waives_a_structural_finding() -> None:
    loose = allowed({"name": "s", "launcher": "npx", "spec": "-y pkg@latest"})
    assert rule_names_named({"command": "npx", "args": ["-y", "pkg@latest"]}, "s", loose) == ["unpinned"]


def test_two_entries_of_one_name_each_approve_their_own_spec() -> None:
    both = allowed({**FS, "spec": "-y a@1.0.0"}, {**FS, "spec": "-y a@2.0.0"})
    for version in ("1.0.0", "2.0.0"):
        assert rule_names_named({"command": "npx", "args": ["-y", f"a@{version}"]}, "filesystem", both) == []
    assert rule_names_named({"command": "npx", "args": ["-y", "a@3.0.0"]}, "filesystem", both) == ["allowlist"]


@pytest.mark.parametrize(
    "config",
    [
        {"command": "npx", "args": "not-a-list"},
        {"command": 3},
        {"command": "npx", "args": [["nested"]]},
        {"command": "npx", "env": "x"},
        {"command": "npx", "env": {"A": ["x"]}},
        {"command": "npx x 'unbalanced"},
        {"url": {"nested": 1}},
    ],
)
def test_a_value_of_the_wrong_shape_is_an_entry_error(config: dict) -> None:
    with pytest.raises(entry.EntryError):
        entry.from_config("s", config)


@pytest.mark.parametrize("config", ["text", 3, None, [], True])
def test_an_entry_that_is_not_an_object_is_an_entry_error(config: object) -> None:
    with pytest.raises(entry.EntryError):
        entry.from_config("s", config)


@pytest.mark.parametrize(
    ("config", "launcher", "args"),
    [
        ({"command": "npx", "args": ["-y", "p", 1]}, "npx", ("-y", "p", "1")),
        ({"command": ["npx", "-y", "p"]}, "npx", ("-y", "p")),
        ({"command": ["npx"], "args": ["-y"]}, "npx", ("-y",)),
        ({"command": []}, "", ()),
        ({"command": {"path": "npx", "args": ["-y", "p"]}}, "npx", ("-y", "p")),
        ({"command": {"path": "npx"}, "args": ["-y"]}, "npx", ("-y",)),
        ({"command": {"source": "extension"}}, "", ()),
        ({"command": "npx -y p"}, "npx", ("-y", "p")),
        ({"command": "npx -y p", "args": ["q"]}, "npx -y p", ("q",)),
        ({"command": "C:\\Program Files\\x.exe"}, "C:\\Program", ("Files\\x.exe",)),
        ({"url": "https://a.example.invalid/"}, "", ()),
    ],
)
def test_a_command_is_read_in_every_shape_clients_accept(config: dict, launcher: str, args: tuple) -> None:
    read = entry.from_config("s", config)
    assert (read.launcher, read.args) == (launcher, args)


def test_zed_environment_lives_in_the_command_object() -> None:
    read = entry.from_config("s", {"command": {"path": "npx", "env": {"A_TOKEN": "x"}}, "env": {"B": "1"}})
    assert read.env == (("A_TOKEN", "x"), ("B", "1"))


def test_any_change_to_an_entry_changes_its_digest() -> None:
    base = {"command": "npx", "args": ["-y", "p@1.0.0"]}
    digests = {
        entry.from_config("s", base).digest(),
        entry.from_config("s", {**base, "args": ["-y", "p@1.0.1"]}).digest(),
        entry.from_config("s", {**base, "env": {"A": "1"}}).digest(),
        entry.from_config("s", {**base, "headers": {"A": "1"}}).digest(),
        entry.from_config("s", {**base, "url": "https://a.example.invalid/"}).digest(),
        entry.from_config("s", {**base, "apiKey": "x"}).digest(),
        entry.from_config("s", {**base, "command": "uvx"}).digest(),
    }
    assert len(digests) == 7
    assert entry.from_config("other-name", base).digest() == entry.from_config("s", base).digest()


@pytest.mark.parametrize(
    ("kind", "payload", "problem"),
    [
        ("options", {"options": "x", "option_values": [], "env_keys": []}, "options must be a list"),
        ("options", {"options": [], "option_values": [""], "env_keys": []}, "option_values must be a list"),
        ("options", {"options": [], "option_values": [], "env_keys": [1]}, "env_keys must be a list"),
        ("floors", {"floors": "x"}, "floors must be a list"),
        ("floors", {"floors": ["x"]}, "floors must be a list"),
        ("floors", {"floors": [{"package": "a", "ecosystem": "npm"}]}, "each floor needs"),
        ("floors", {"floors": [{"package": "a", "ecosystem": "gem", "min": "1"}]}, "each floor needs"),
        ("floors", {"floors": [{"package": "a", "ecosystem": "npm", "min": 1}]}, "each floor needs"),
    ],
)
def test_a_malformed_table_is_refused_by_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, payload: dict, problem: str
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    envelope = {"schema": 1, "kind": "curated", "as_of": "2026-10-02", "source": "a citation in words"}
    name = "mcp-option-denylist.json" if kind == "options" else "mcp-version-floors.json"
    (data / name).write_text(json.dumps({**envelope, **payload}), encoding="utf-8")
    monkeypatch.setattr(tables, "DATA", data)
    tables.denylist.cache_clear()
    tables.floors.cache_clear()
    try:
        with pytest.raises(g.rules.tables.data_table.TableError, match=problem):
            (tables.denylist if kind == "options" else tables.floors)()
    finally:
        tables.denylist.cache_clear()
        tables.floors.cache_clear()


def test_null_and_boolean_values_are_read_as_text() -> None:
    read = entry.from_config("s", {"command": "npx", "args": [True, None], "env": {"A": None, "B": False}})
    assert read.args == ("true", "")
    assert read.env == (("A", ""), ("B", "false"))
