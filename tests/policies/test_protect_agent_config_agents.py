"""protect-agent-config: the project config of Kilo Code, opencode, Factory Droid, Amp, Continue and Goose is protected."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
gate_script = guardkit.load_guard(POLICY, "protect-agent-config-gate")
pathset = guardkit.load_guard(POLICY, "pathset")

# Each path is a file the vendor's docs name as project config, or one inside a folder they do.
REFUSED = [
    ".kilocode/rules/style.md",
    ".kilocode/workflows/release.md",
    ".kilocode/mcp.json",
    ".kilo/kilo.jsonc",
    ".kilo/rules/formatting.md",
    "kilo.json",
    "kilo.jsonc",
    "opencode.json",
    "opencode.jsonc",
    "packages/web/opencode.json",
    ".opencode/plugins/audit.ts",
    ".opencode/agents/review.md",
    ".opencode/commands/test.md",
    ".factory/settings.json",
    ".factory/settings.local.json",
    ".factory/hooks.json",
    ".factory/hooks/hooks.json",
    ".factory/mcp.json",
    ".factory/droids/reviewer.md",
    ".amp/settings.json",
    ".amp/settings.jsonc",
    ".amp/skills/deploy/SKILL.md",
    ".continue/mcpServers/db.yaml",
    ".continue/rules/style.md",
    ".continuerc.json",
    ".goosehints",
    "src/.goosehints",
    "/home/dev/.factory/settings.json",
    "~/.continue/config.yaml",
    ".OPENCODE/Plugins/x.ts",
    ".Factory/HOOKS.json",
    "OpenCode.JSON",
    "opencode.json:stream",
]
# Names that only look like them, and neighbours of the protected folders.
OPEN = [
    "docs/opencode.json.md",
    "docs/kilo.json.md",
    "opencode.json5",
    "myopencode.json",
    "src/opencode.ts",
    "src/amp.ts",
    "amplify.yml",
    "x.amp/a.txt",
    "src/continue.py",
    "continue/notes.md",
    "factory/settings.json",
    "kilocode/rules/a.md",
    "docs/goose-hints.md",
]


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    for name in (".git", "src", "docs"):
        (root / name).mkdir(parents=True)
    monkeypatch.chdir(root)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return root


def shell(path: str) -> str:
    """The write of a path as a shell command; a name with a space or a backslash is quoted."""
    return f"echo x > '{path}'" if re.search(r"[ \\]", path) else f"echo x > {path}"


@pytest.mark.parametrize("path", REFUSED)
def test_a_shell_write_to_agent_config_is_refused(path: str) -> None:
    assert guard.check(shell(path)) == guard.REASON, path


@pytest.mark.parametrize("path", REFUSED)
def test_the_edit_write_gate_refuses_the_same_file(_repo_root: Path, path: str) -> None:
    assert gate_script.judge(_repo_root, path) == "block", path


@pytest.mark.parametrize("path", OPEN)
def test_a_look_alike_stays_open(_repo_root: Path, path: str) -> None:
    assert pathset.verdict(path) == "", path
    assert guard.check(shell(path)) is None, path
    assert gate_script.judge(_repo_root, path) == "", path


@pytest.mark.parametrize(
    "raw",
    [
        "rm -rf .opencode",
        "rm -rf .kilocode",
        "rm -rf .factory",
        "rm -rf .amp",
        "rm -rf .continue",
        "mv .kilo old",
        "cd .factory && echo x > mcp.json",
        "cp evil.ts .opencode/plugins/",
        "sed -i s/ask/allow/ opencode.json",
    ],
)
def test_removing_moving_or_writing_into_the_folders_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize(
    "raw",
    [
        "cat opencode.json",
        "jq . .factory/mcp.json",
        "ls -la .opencode .kilocode .kilo .amp .continue",
        "grep -rn mcpServers .continue",
        "head .goosehints",
        "git log -p -- .factory/settings.json",
        "chock sync --repo .",
        "chock sync",
        "echo 'see opencode.json and .amp/settings.json'",
        "git commit -m 'document .factory/hooks.json'",
        "mkdir .opencode",
        "npm run build",
    ],
)
def test_reads_sync_and_text_that_names_them_pass(raw: str) -> None:
    assert guard.check(raw) is None, raw


def test_a_goosehints_file_under_docs_asks() -> None:
    assert pathset.verdict("docs/.goosehints") == pathset.ASK
    assert guard.check("echo x > docs/.goosehints") == guard.ASK
