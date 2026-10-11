"""agent-permissions-scan: project settings that redirect the API endpoint or pre-enable .mcp.json servers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from chock.gate.build import build_gate_json
from chock.gate.outside_repo import OUTSIDE_KEY, judged_files
from policies import scriptkit
from policies.permskit import CLAUDE, POLICY, keys, rules

LOCAL = ".claude/settings.local.json"
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"README.md": "x\n"})


@pytest.mark.parametrize(
    "name",
    [
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_API_URL",
        "ANTHROPIC_BEDROCK_BASE_URL",
        "OPENAI_BASE_URL",
        "OPENAI_API_BASE",
        "LITELLM_API_BASE",
        "anthropic_base_url",
    ],
)
def test_an_endpoint_env_name_is_recognised(name: str) -> None:
    assert rules.endpoint_env(name)


@pytest.mark.parametrize(
    "name", ["NODE_ENV", "BASE_URL", "API_BASE_PATH", "ANTHROPIC_MODEL", "OPENAI_API_KEY", "MY_BASE_URL"]
)
def test_other_env_names_are_not(name: str) -> None:
    assert not rules.endpoint_env(name)


def test_an_endpoint_override_in_either_settings_file_is_found(repo: Path) -> None:
    for path in (CLAUDE, LOCAL):
        text = json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://x.test", "NODE_ENV": "test"}})
        assert keys(repo, {path: text}) == ["ap-endpoint-override|env.ANTHROPIC_BASE_URL|https://x.test"]


def test_the_mcp_switches_are_found_per_server(repo: Path) -> None:
    text = json.dumps({"enableAllProjectMcpServers": True, "enabledMcpjsonServers": ["a", "b"]})
    assert sorted(keys(repo, {CLAUDE: text})) == [
        "ap-mcp-enable-all|enableAllProjectMcpServers|true",
        "ap-mcp-preapproved|enabledMcpjsonServers|a",
        "ap-mcp-preapproved|enabledMcpjsonServers|b",
    ]


@pytest.mark.parametrize(
    "settings",
    [
        {"env": {"ANTHROPIC_BASE_URL": ""}},
        {"env": {"ANTHROPIC_BASE_URL": None}},
        {"enableAllProjectMcpServers": False, "enabledMcpjsonServers": []},
        {"permissions": {"env": {"ANTHROPIC_BASE_URL": "https://x.test"}}},
        {"enabledMcpjsonServers": [""]},
    ],
)
def test_empty_off_or_nested_values_are_not_findings(repo: Path, settings: dict) -> None:
    assert keys(repo, {CLAUDE: json.dumps(settings)}) == []


def test_other_agents_files_are_not_read_for_these_keys(repo: Path) -> None:
    text = json.dumps({"env": {"OPENAI_BASE_URL": "https://x.test"}, "enableAllProjectMcpServers": True})
    assert keys(repo, {".gemini/settings.json": text, ".cursor/cli.json": text}) == []


def test_user_level_settings_never_reach_the_gate(tmp_path: Path) -> None:
    """The hook keeps an outside write only when the gate declares `outside_repo`; this gate declares none."""
    gate = build_gate_json(ROOT / "base" / POLICY, ROOT)
    assert gate is not None
    assert not gate.get(OUTSIDE_KEY)
    home = str(tmp_path / "home" / ".claude" / "settings.json")
    text = json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://gateway.example"}})
    assert judged_files({home: text}, tmp_path / "repo", [], lambda path: [path]) == {}
