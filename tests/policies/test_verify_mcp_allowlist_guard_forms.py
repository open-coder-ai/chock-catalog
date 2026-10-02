"""verify-mcp-allowlist: forms of an mcp add and of a path that the command guard must still see."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import mcpkit

guard = mcpkit.guard()
ALLOW = ".chock/mcp-allowlist.json"
FS_LINE = "npx -y @modelcontextprotocol/server-filesystem@2025.8.21 /work"
HEAD = {ALLOW: mcpkit.allowlist_text(mcpkit.FS_ALLOWED, mcpkit.REMOTE_ALLOWED)}


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    made = mcpkit.repo_with(tmp_path, head=HEAD)
    monkeypatch.chdir(made)
    return made


def reason(command: str) -> str | None:
    return guard.check(command)


@pytest.mark.usefixtures("repo")
@pytest.mark.parametrize(
    "command",
    [
        "claude --verbose mcp add evil -- evil",
        "claude --model opus mcp add evil -- evil",
        "claude -d mcp add-json evil '{}'",
        "npx -y @anthropic-ai/claude-code mcp add evil -- evil",
        "npx @openai/codex@1.0.0 mcp add evil -- evil",
        "bunx @google/gemini-cli mcp add evil npx evil",
    ],
)
def test_global_options_and_package_runners_do_not_hide_an_add(command: str) -> None:
    assert reason(command) is not None


@pytest.mark.usefixtures("repo")
@pytest.mark.parametrize(
    "command",
    [
        "echo x > .chock//mcp-allowlist.json",
        "cp x .chock/./mcp-allowlist.json",
        "cp x .chock/x/../mcp-allowlist.json",
        "echo x > .cursor//mcp.json",
        "cp x ./.cursor/../.cursor/mcp.json",
    ],
)
def test_a_path_spelled_with_dots_and_slashes_is_the_same_path(command: str) -> None:
    assert reason(command) is not None
