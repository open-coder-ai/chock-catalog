"""verify-mcp-allowlist: the script gate that judges every written MCP client config against the guard's allowlist."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from policies import gatekit, guardkit, scriptkit

POLICY = "verify-mcp-allowlist"
NAME = "verify-mcp-allowlist_gate.py"
mod = scriptkit.load(POLICY, NAME)
guard = mod.load_guard()
guardkit.forget_shellparse()
CRASH = ("traceback (most recent call last)", "syntax error", "syntaxerror", "unexpected eof")
OK_SOURCE = guard.ALLOWED_MCP_SERVERS["filesystem"].split()
EVIL = {"command": "npx", "args": ["-y", "evil-mcp"]}
FILESYSTEM = {"command": OK_SOURCE[0], "args": OK_SOURCE[1:]}


def mcp(servers: dict, key: str = "mcpServers") -> str:
    return json.dumps({key: servers})


def toml(name: str, command: str = "npx", args: str = '"-y", "evil-mcp"') -> str:
    return f'[mcp_servers.{name}]\ncommand = "{command}"\nargs = [{args}]\n'


def payload(repo: Path, writes: dict[str, str], event: str = "commit") -> dict:
    return {"event": event, "repo_root": str(repo), "writes": writes}


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"README.md": "x\n"})


def test_the_manifest_declares_the_script_gate_beside_the_guard() -> None:
    manifest = scriptkit.manifest(POLICY)
    gate = manifest["hook"]["gate"]
    assert (gate["kind"], gate["on"], gate["params"]) == ("script", ["commit", "tool_use"], {"script": NAME})
    assert manifest["artifact"] == "rule"
    assert scriptkit.script_path(POLICY, f"{POLICY}.py").is_file()


@pytest.mark.parametrize(
    "path",
    [
        ".mcp.json",
        "pkg/.mcp.json",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        "claude_desktop_config.json",
        ".gemini/settings.json",
        "a\\.mcp.json",
    ],
)
def test_json_configs_are_recognised(path: str) -> None:
    assert mod.config_kind(path) == "json"


def test_toml_and_other_files_are_told_apart() -> None:
    assert mod.config_kind(".codex/config.toml") == "toml"
    for other in (
        "package.json",
        "mcp.json",
        "x.mcp.json",
        ".codex/config.json",
        "config.toml",
        ".cursor/settings.json",
    ):
        assert mod.config_kind(other) is None


def test_the_allowlisted_server_passes_in_every_config(repo: Path) -> None:
    writes = {
        ".mcp.json": mcp({"filesystem": FILESYSTEM}),
        ".cursor/mcp.json": mcp({"filesystem": FILESYSTEM}),
        ".vscode/mcp.json": mcp({"filesystem": FILESYSTEM}, "servers"),
        "claude_desktop_config.json": mcp({"filesystem": FILESYSTEM}),
        ".gemini/settings.json": mcp({"filesystem": FILESYSTEM}),
        ".codex/config.toml": toml("filesystem", OK_SOURCE[0], ", ".join(f'"{a}"' for a in OK_SOURCE[1:])),
    }
    for event in ("commit", "tool_use"):
        assert mod.findings(payload(repo, writes, event), guard) == []


@pytest.mark.parametrize(
    ("path", "text"),
    [
        (".mcp.json", mcp({"evil": EVIL})),
        (".cursor/mcp.json", mcp({"evil": EVIL})),
        (".vscode/mcp.json", mcp({"evil": EVIL}, "servers")),
        ("claude_desktop_config.json", mcp({"evil": {"url": "https://mcp.example.invalid/sse"}})),
        (".gemini/settings.json", mcp({"evil": EVIL})),
        (".codex/config.toml", toml("evil")),
        (".mcp.json", mcp({"filesystem": EVIL})),
        (".mcp.json", mcp({"evil": "not-an-object"})),
    ],
)
@pytest.mark.parametrize("event", ["commit", "tool_use", "agent-commit"])
def test_an_unlisted_server_is_refused(repo: Path, path: str, text: str, event: str) -> None:
    found = mod.findings(payload(repo, {path: text}, event), guard)
    assert len(found) == 1
    assert found[0].startswith(f"{path}: ")


def test_a_server_already_committed_never_blocks_a_commit(tmp_path: Path) -> None:
    held = scriptkit.init_repo(tmp_path / "h", {".mcp.json": mcp({"evil": EVIL})})
    both = mcp({"evil": EVIL, "filesystem": FILESYSTEM})
    assert mod.findings(payload(held, {".mcp.json": both}), guard) == []
    assert mod.findings(payload(held, {".mcp.json": mcp({"evil": EVIL})}), guard) == []


def test_a_server_already_committed_never_blocks_a_stop_or_an_untouched_rewrite(tmp_path: Path) -> None:
    held = scriptkit.init_repo(tmp_path / "h", {".mcp.json": mcp({"evil": EVIL})})
    same = {".mcp.json": mcp({"evil": EVIL})}
    both = {".mcp.json": mcp({"evil": EVIL, "filesystem": FILESYSTEM})}
    assert mod.findings(payload(held, same, "tool_use"), guard) == []
    scriptkit.write(held, both)
    assert mod.findings(payload(held, both, "tool_use"), guard) == []


def test_a_new_unlisted_server_is_refused_at_stop_and_tool_use(tmp_path: Path) -> None:
    held = scriptkit.init_repo(tmp_path / "h", {".mcp.json": mcp({"evil": EVIL})})
    worse = {"command": "npx", "args": ["-y", "worse-mcp"]}
    written = {".mcp.json": mcp({"evil": EVIL, "worse": worse})}
    assert len(mod.findings(payload(held, written, "tool_use"), guard)) == 1
    scriptkit.write(held, written)
    found = mod.findings(payload(held, written, "tool_use"), guard)
    assert len(found) == 1
    assert "'worse'" in found[0]


def test_the_baseline_at_pretooluse_is_the_file_on_disk_not_head(tmp_path: Path) -> None:
    held = scriptkit.init_repo(tmp_path / "h", {".mcp.json": mcp({"filesystem": FILESYSTEM})})
    scriptkit.write(held, {".mcp.json": mcp({"evil": EVIL})})
    both = {".mcp.json": mcp({"evil": EVIL, "filesystem": FILESYSTEM})}
    assert mod.findings(payload(held, both, "tool_use"), guard) == []
    assert len(mod.findings(payload(held, both), guard)) == 1


def test_a_changed_server_is_refused_at_tool_use(tmp_path: Path) -> None:
    held = scriptkit.init_repo(tmp_path / "h", {".mcp.json": mcp({"evil": EVIL})})
    changed = {"command": "npx", "args": ["-y", "evil-mcp", "--flag"]}
    assert len(mod.findings(payload(held, {".mcp.json": mcp({"evil": changed})}, "tool_use"), guard)) == 1


def test_a_renamed_unchanged_server_is_judged_by_its_new_name(tmp_path: Path) -> None:
    held = scriptkit.init_repo(tmp_path / "h", {".mcp.json": mcp({"evil": EVIL})})
    renamed = {".mcp.json": mcp({"evil2": EVIL})}
    for event in ("commit", "tool_use"):
        assert len(mod.findings(payload(held, renamed, event), guard)) == 1


def test_a_new_config_file_is_judged_whole_at_tool_use(repo: Path) -> None:
    assert len(mod.findings(payload(repo, {".mcp.json": mcp({"evil": EVIL})}, "tool_use"), guard)) == 1


def test_an_edit_to_a_config_with_only_listed_servers_passes(tmp_path: Path) -> None:
    held = scriptkit.init_repo(tmp_path / "h", {".mcp.json": mcp({"filesystem": FILESYSTEM})})
    edited = {".mcp.json": json.dumps({"mcpServers": {"filesystem": FILESYSTEM}, "note": "x"})}
    for event in ("commit", "tool_use"):
        assert mod.findings(payload(held, edited, event), guard) == []


def test_a_second_unlisted_server_and_an_altered_one_are_refused_at_commit(tmp_path: Path) -> None:
    held = scriptkit.init_repo(tmp_path / "h", {".mcp.json": mcp({"evil": EVIL})})
    worse = {"command": "npx", "args": ["-y", "worse-mcp"]}
    assert len(mod.findings(payload(held, {".mcp.json": mcp({"evil": EVIL, "worse": worse})}), guard)) == 1
    changed = {"command": "npx", "args": ["-y", "evil-mcp", "--flag"]}
    assert len(mod.findings(payload(held, {".mcp.json": mcp({"evil": changed})}), guard)) == 1


def test_a_head_that_cannot_be_read_grandfathers_nothing(tmp_path: Path) -> None:
    broken = scriptkit.init_repo(tmp_path / "b", {".mcp.json": "{"})
    assert len(mod.findings(payload(broken, {".mcp.json": mcp({"evil": EVIL})}), guard)) == 1


@pytest.mark.parametrize(
    ("path", "text"),
    [(".mcp.json", '{"mcpServers": {'), (".codex/config.toml", "[mcp_servers.x\ncommand = ")],
)
def test_a_config_that_cannot_be_parsed_is_refused_as_unverifiable(repo: Path, path: str, text: str) -> None:
    found = mod.findings(payload(repo, {path: text}), guard)
    assert len(found) == 1
    assert "cannot be verified" in found[0]


def test_files_that_are_not_mcp_configs_and_configs_without_servers_pass(repo: Path) -> None:
    writes = {
        "package.json": mcp({"evil": EVIL}),
        "src/app.py": "x = 1\n",
        ".mcp.json": "[]",
        ".cursor/mcp.json": '{"mcpServers": 3}',
        ".codex/config.toml": 'model = "x"\n',
        "claude_desktop_config.json": "{}",
    }
    assert mod.findings(payload(repo, writes), guard) == []


def test_a_toml_mcp_servers_value_that_is_not_a_table_holds_no_servers(repo: Path) -> None:
    assert mod.findings(payload(repo, {".codex/config.toml": "mcp_servers = 3\n"}), guard) == []


def test_the_launch_line_is_never_printed(repo: Path) -> None:
    secret = {"command": "npx", "args": ["-y", "evil-mcp", "--token", "SECRET-VALUE-123"]}
    code, err = scriptkit.run_script(
        POLICY, NAME, repo, json.dumps(payload(repo, {".mcp.json": mcp({"evil": secret})}, "tool_use"))
    )
    assert code == 1
    assert "SECRET-VALUE-123" not in err
    assert "evil" in err


def test_the_script_run_as_a_process_refuses_and_allows(repo: Path) -> None:
    code, err = scriptkit.run_script(POLICY, NAME, repo, json.dumps(payload(repo, {".mcp.json": mcp({"evil": EVIL})})))
    assert code == 1
    assert err.startswith("verify-mcp-allowlist: MCP server config refused")
    assert "allowlist" in err
    assert not any(marker in err.lower() for marker in CRASH)
    assert scriptkit.run_script(POLICY, NAME, repo, json.dumps(payload(repo, {"a.txt": "x"}))) == (0, "")


def test_a_fault_exits_two_and_says_so(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert mod.main() == 2
    err = capsys.readouterr().err
    assert "internal error" in err
    assert not any(marker in err.lower() for marker in CRASH)


def test_the_gate_through_chock_s_runner_at_tool_use_and_commit(repo: Path) -> None:
    evil = {".mcp.json": mcp({"evil": EVIL})}
    code, err = gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, evil)
    assert code == 1
    assert "evil" in err
    assert gatekit.judge(POLICY, repo, gatekit.STOP, evil)[0] == 1
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {".mcp.json": mcp({"filesystem": FILESYSTEM})}) == (0, "")
    scriptkit.write(repo, {".mcp.json": mcp({"evil": EVIL})})
    scriptkit.git(repo, "add", "-A")
    assert gatekit.judge(POLICY, repo, gatekit.COMMIT)[0] == 1
