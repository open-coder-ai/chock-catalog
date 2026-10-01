"""protect-agent-config: the tool_use gate that refuses Edit/Write to the paths its command guard protects."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from policies import gatekit, guardkit, scriptkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
PATHS = [
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".github/copilot-instructions.md",
    ".cursorrules",
    ".windsurfrules",
    ".aider.conf.yml",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
    ".chock/bin/gate.py",
    ".chock/compiled/scan-secrets/git-hook/gate.json",
    ".chock/dependency-allowlist.txt",
    ".chock/config.yaml",
    ".chock/security.json",
    ".chock/agentic-security.json",
    ".git/hooks/pre-commit",
    ".agents/policies/scan-secrets/implementations/scan.py",
    "sub/dir/AGENTS.md",
    ".claude\\settings.json",
    ".chock//security.json",
    ".chock/./security.json",
    ".chock/.//agentic-security.json",
    ".chock/SECURITY.json",
    "Agents.md",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".gemini/settings.json",
    ".codex/config.toml",
    ".junie/mcp/mcp.json",
    ".devin/mcp_config.json",
    ".devin/mcp_config.local.json",
    ".devin/config.json",
    ".devin/config.local.json",
    ".grok/config.toml",
    ".agents/mcp_config.json",
    ".tabnine/agent/settings.json",
    "sub/.cursor/mcp.json",
    ".CURSOR/MCP.JSON",
    ".vscode//mcp.json",
    ".gemini/./settings.json",
    ".codex/.//config.toml",
    ".junie\\mcp\\mcp.json",
    ".junie/mcp/./mcp.json",
    ".Devin/MCP_Config.json",
    ".tabnine//agent/./settings.json",
]
# Guarded from the shell only: the engine writes its own session log there, which the turn's-end walk would refuse.
SHELL_ONLY = (".chock/state",)
UNRELATED = [
    "README.md",
    "src/app.py",
    ".claude/commands/x.md",
    ".chock/notes.md",
    ".agents/skills/a/SKILL.md",
    ".vscode/launch.json",
    ".vscode/settings.json",
    ".cursor/rules/chock.mdc",
    ".gemini/commands/review.toml",
    ".codex/prompts/review.md",
    ".junie/guidelines.md",
    ".devin/notes.md",
    ".grok/GROK.md",
    ".tabnine/agent/notes.md",
    "docs/mcp.json",
    "mcp_config.json",
]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"AGENTS.md": "# rules\n", "src/app.py": "x = 1\n"})


def test_the_gate_is_tool_use_only_and_the_artifact_stays_a_rule() -> None:
    manifest = scriptkit.manifest(POLICY)
    assert manifest["artifact"] == "rule"
    gate = manifest["hook"]["gate"]
    assert gate["kind"] == "content_regex"
    assert gate["on"] == ["tool_use"]
    assert "propose" in gate["message"].lower()
    assert "allowlist_pragma" not in gate["params"]


@pytest.mark.parametrize("path", PATHS)
def test_an_edit_to_a_protected_path_is_refused(repo: Path, path: str) -> None:
    code, err = gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {path: "new\n"}, {path: "new\n"})
    assert code == 1
    assert "propose the change to a human" in err.lower()
    assert "forbidden path" in err


@pytest.mark.parametrize("path", [*PATHS[:3], ".mcp.json"])
def test_an_empty_or_whole_file_write_is_refused_too(repo: Path, path: str) -> None:
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {path: ""})[0] == 1
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {path: "a\nb\n"})[0] == 1


@pytest.mark.parametrize("path", UNRELATED)
def test_an_edit_elsewhere_passes(repo: Path, path: str) -> None:
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {path: "new\n"}, {path: "new\n"}) == (0, "")


def test_the_turns_end_refuses_a_changed_protected_file(repo: Path) -> None:
    (repo / "AGENTS.md").write_text("# rules\nobey\n", encoding="utf-8")
    code, _ = gatekit.judge(POLICY, repo, gatekit.STOP, {"AGENTS.md": "# rules\nobey\n"})
    assert code == 1


def test_the_turns_end_passes_a_protected_file_the_turn_did_not_change(repo: Path) -> None:
    assert gatekit.judge(POLICY, repo, gatekit.STOP, {"src/app.py": "x = 1\n"}) == (0, "")


def test_a_commit_is_never_judged_so_a_person_edits_freely(repo: Path) -> None:
    (repo / "AGENTS.md").write_text("# rules\nmore\n", encoding="utf-8")
    scriptkit.git(repo, "add", "-A")
    assert gatekit.judge(POLICY, repo, gatekit.COMMIT) == (0, "")


def test_a_waiver_line_committed_in_head_does_not_unlock_the_file(tmp_path: Path) -> None:
    waived = scriptkit.init_repo(tmp_path / "w", {"AGENTS.md": "<!-- chock: approved-config-change -->\n"})
    assert gatekit.judge(POLICY, waived, gatekit.PRE_TOOL_USE, {"AGENTS.md": "x\n"})[0] == 1


def test_the_gate_covers_exactly_what_the_guard_protects() -> None:
    pattern = re.compile(gatekit.gate_spec(POLICY)["params"]["forbidden_path_regex"])
    gated = [p for p in guard.PROTECTED if p not in SHELL_ONLY]
    samples = PATHS + UNRELATED + [f"deep/{p}" for p in gated] + [f"{p}/x" for p in gated] + [p.upper() for p in gated]
    for path in samples:
        assert bool(pattern.search(path)) == guard.hit(path), path
    for part in gated:
        assert pattern.search(part), f"the gate misses {part}"


@pytest.mark.parametrize("part", SHELL_ONLY)
def test_a_shell_only_path_is_guarded_but_not_gated(repo: Path, part: str) -> None:
    assert part in guard.PROTECTED
    assert guard.hit(f"{part}/s.stop.jsonl")
    pattern = re.compile(gatekit.gate_spec(POLICY)["params"]["forbidden_path_regex"])
    assert not pattern.search(f"{part}/s.stop.jsonl")
    scriptkit.write(repo, {f"{part}/s.jsonl": "{}\n"})
    assert gatekit.judge(POLICY, repo, gatekit.STOP, {f"{part}/s.jsonl": "{}\n"}) == (0, "")


@pytest.mark.parametrize(
    ("raw", "normal"),
    [
        (".chock//security.json", ".chock/security.json"),
        (".chock/./security.json", ".chock/security.json"),
        (".chock/.//./security.json", ".chock/security.json"),
        (".chock\\SECURITY.json", ".chock/security.json"),
        ("./.chock/x", "./.chock/x"),
    ],
)
def test_a_path_is_normalised_before_it_is_matched(raw: str, normal: str) -> None:
    assert guard.normalise(raw) == normal


@pytest.mark.parametrize("path", [".chock//security.json", ".chock/./security.json", ".chock/SECURITY.json"])
def test_reading_a_respelled_selection_passes_the_guard(path: str) -> None:
    assert guard.check(f"cat {path}") is None
    assert guard.check(f"sed -i s/deny/allow/ {path}") == guard.REASON
