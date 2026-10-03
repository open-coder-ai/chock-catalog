"""protect-agent-config v2: the Edit/Write gate protects whole agent folders, follows links, and asks about docs/ instruction files."""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest
from policies import gatekit, guardkit, scriptkit

POLICY = "protect-agent-config"
gate_script = guardkit.load_guard(POLICY, "protect-agent-config-gate")

FOLDERS = [
    ".claude/commands/x.md",
    ".chock/notes.md",
    ".agents/skills/a/SKILL.md",
    ".cursor/rules/chock.mdc",
    ".gemini/commands/review.toml",
    ".codex/prompts/review.md",
    ".junie/guidelines.md",
    ".devin/notes.md",
    ".grok/GROK.md",
    ".tabnine/agent/notes.md",
    ".windsurf/rules/chock.md",
    ".codex/hooks.md",
    ".agents/hooks.md",
    ".github/copilot/prompts/a.md",
    ".github/copilot-setup-steps.yml",
]
RESPELLED = [
    ".CLAUDE/Commands/x.md",
    ".Cursor/RULES/x.mdc",
    ".GITHUB/Copilot/x.md",
    ".AGENTS/Skills/a/SKILL.md",
    "src/../.claude/commands/x.md",
    "./.claude/commands/x.md",
    ".claude//commands/x.md",
    ".claude/./commands/x.md",
    ".claude/x/../commands/x.md",
    "a/b/../../.claude/x",
    ".claude\\commands\\x.md",
    ".CLAUDE\\Commands\\x.md",
    "deep/er/.claude/x",
    ".claude.\\x",
    ".claude /x",
]
OPEN = [
    "src/app.py",
    "README.md",
    "docs/guide.md",
    ".github/workflows/ci.yml",
    ".github/ISSUE_TEMPLATE/x.md",
    ".vscode/settings.json",
    "claude/x.md",
    "my.claude/x.md",
    ".claudex/x.md",
    ".agent/x.md",
    "src/chock/x.py",
]
DOCS = [
    "docs/AGENTS.md",
    "docs/CLAUDE.md",
    "docs/GEMINI.md",
    "DOCS/agents.md",
    "site/docs/sub/AGENTS.md",
    "docs/.cursorrules",
]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"AGENTS.md": "# rules\n", "src/app.py": "x = 1\n"})


def judge(repo: Path, path: str, event: str = gatekit.PRE_TOOL_USE) -> tuple[int, str]:
    return gatekit.judge(POLICY, repo, event, {path: "new\n"}, {path: "new\n"})


@pytest.mark.parametrize("path", [*FOLDERS, *RESPELLED])
def test_a_write_anywhere_in_an_agent_folder_is_refused_however_it_is_spelled(repo: Path, path: str) -> None:
    code, err = judge(repo, path)
    assert code == 1, path
    assert "propose the change to a human" in err.lower()
    assert f"{path}: forbidden path" in err


@pytest.mark.parametrize("path", OPEN)
def test_a_write_outside_every_protected_folder_passes(repo: Path, path: str) -> None:
    assert judge(repo, path) == (0, "")


def test_the_gate_reads_a_path_from_the_repository_folder(repo: Path) -> None:
    assert gate_script.relative(repo, f"{repo}/src/../src/app.py") == "src/app.py"
    assert gate_script.relative(repo, "/srv/elsewhere/x") == "/srv/elsewhere/x"
    assert gate_script.relative(repo, "../other/x") == "../other/x"
    assert gate_script.judge(repo, f"{repo}/.claude/commands/x.md") == "block"
    assert gate_script.judge(repo, f"{repo}/docs/AGENTS.md") == "ask"
    assert gate_script.judge(repo, f"{repo}/src/app.py") == ""


def test_an_absolute_path_inside_the_repository_is_read_from_the_repository(repo: Path) -> None:
    assert judge(repo, f"{repo}/.claude/commands/x.md")[0] == 1
    assert judge(repo, f"{repo}/src/app.py") == (0, "")
    assert judge(repo, "/srv/elsewhere/src/app.py") == (0, "")
    assert judge(repo, "/srv/elsewhere/.claude/x")[0] == 1


@pytest.mark.parametrize("path", DOCS)
def test_an_instruction_file_under_docs_asks_a_person(repo: Path, path: str) -> None:
    code, err = judge(repo, path)
    assert code == 3
    assert "instruction file under docs/" in err
    assert f"{path}: instruction file under docs/" in err


def test_the_turns_end_only_reminds_about_an_ask(repo: Path) -> None:
    (repo / "docs").mkdir()
    (repo / "docs/AGENTS.md").write_text("# about\n", encoding="utf-8")
    assert gatekit.judge(POLICY, repo, gatekit.STOP, {"docs/AGENTS.md": "# about\n"})[0] == 4


def test_a_block_outranks_an_ask_in_the_same_turn(repo: Path) -> None:
    writes = {"docs/AGENTS.md": "a\n", "AGENTS.md": "b\n"}
    code, err = gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, writes, writes)
    assert code == 1
    assert "AGENTS.md: forbidden path" in err
    assert "docs/AGENTS.md: forbidden path" not in err


@pytest.mark.parametrize(
    "path", ["docs/.claude/settings.json", ".claude/docs/AGENTS.md", "mydocs/AGENTS.md", "docs.old/CLAUDE.md"]
)
def test_only_an_instruction_file_below_a_docs_folder_asks(repo: Path, path: str) -> None:
    assert judge(repo, path)[0] == 1


@pytest.mark.parametrize("path", [".chock/state/s.stop.jsonl", ".chock/log/gate.jsonl", ".CHOCK/State/s.jsonl"])
def test_the_files_the_engine_writes_itself_are_not_gated(repo: Path, path: str) -> None:
    assert judge(repo, path) == (0, "")


@pytest.mark.parametrize(
    "path", ["deep/.chock/state/s.jsonl", ".chock/state/../config.yaml", ".chock/log/../bin/gate.py", ".chock/statex/a"]
)
def test_a_path_that_only_starts_like_the_engines_own_is_gated(repo: Path, path: str) -> None:
    assert judge(repo, path)[0] == 1


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
class TestLinks:
    @pytest.fixture
    def linked(self, tmp_path: Path) -> Path:
        root = scriptkit.init_repo(
            tmp_path / "l",
            {
                "AGENTS.md": "# rules\n",
                ".claude/settings.json": "{}\n",
                ".claude/commands/c.md": "c\n",
                "src/real.txt": "x\n",
                "docs/guide.md": "g\n",
            },
        )
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        links = {
            "notes.md": "AGENTS.md",
            "cfg": ".claude",
            "deeper": ".claude/commands",
            "chain1": "chain2",
            "chain2": "AGENTS.md",
            "dangle": ".claude/missing.md",
            "docs/AGENTS.md": "../AGENTS.md",
            "innocent": "src/real.txt",
            "out": str(outside),
            "loop1": "loop2",
            "loop2": "loop1",
        }
        for name, target in links.items():
            (root / name).symlink_to(target)
        scriptkit.git(root, "add", "-A")
        scriptkit.git(root, "commit", "-q", "-m", "links")
        return root

    @pytest.mark.parametrize(
        "path",
        [
            "notes.md",
            "cfg/commands/a.md",
            "cfg/new.md",
            "chain1",
            "dangle",
            "docs/AGENTS.md",
            "loop1",
            "src/../notes.md",
            "deeper/../settings.json",
            "deeper/x/../../settings.json",
        ],
    )
    def test_a_write_through_a_tracked_link_to_a_protected_path_is_refused(self, linked: Path, path: str) -> None:
        assert judge(linked, path)[0] == 1, path

    @pytest.mark.parametrize("path", ["innocent", "out/a.txt", "src/real.txt", "docs/guide.md", "src/new.txt"])
    def test_a_link_to_an_ordinary_file_or_out_of_the_repository_passes(self, linked: Path, path: str) -> None:
        assert judge(linked, path) == (0, "")

    def test_a_path_too_wide_or_too_long_to_read_is_refused(
        self, linked: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(gate_script, "follow", lambda *_args: None)
        assert gate_script.judge(linked, "src/app.py") == "block"


def test_the_gate_reads_its_writes_from_standard_input(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def feed(writes: dict[str, str]) -> int:
        monkeypatch.setattr(
            sys, "stdin", io.StringIO(json.dumps({"event": "tool_use", "repo_root": str(repo), "writes": writes}))
        )
        return gate_script.main()

    assert feed({"src/app.py": "x\n"}) == 0
    assert feed({".claude/a.md": "x\n", "docs/AGENTS.md": "x\n"}) == 1
    assert "docs/AGENTS.md" not in capsys.readouterr().err.split("forbidden path", 1)[0]
    assert feed({"docs/AGENTS.md": "x\n"}) == 3


def test_the_script_runs_as_a_process_the_way_a_hook_runner_starts_it(repo: Path) -> None:
    def start(writes: dict[str, str]) -> tuple[int, str]:
        stdin = json.dumps({"event": "tool_use", "repo_root": str(repo), "writes": writes})
        return scriptkit.run_script(POLICY, "protect-agent-config-gate.py", repo, stdin)

    assert start({"src/app.py": "x\n"}) == (0, "")
    assert start({".cursor/rules/a.mdc": "x\n"})[0] == 1
    assert start({"docs/CLAUDE.md": "x\n"})[0] == 3
