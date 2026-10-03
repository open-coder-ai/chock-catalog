"""protect-agent-config v2: an instruction file under docs/ is an ask, not a block."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from policies import guardkit
from policies.guard_cases_docs import ALLOWED, ASKED, BLOCKED, NAMES

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
pathset = guardkit.load_guard(POLICY, "pathset")


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    for name in (".git", ".claude", "docs/sub", "site/docs", "src", "mydocs", "docs.old", "documents"):
        (root / name).mkdir(parents=True)
    monkeypatch.chdir(root)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return root


@pytest.mark.parametrize("raw", ASKED)
def test_a_write_to_an_instruction_file_under_docs_asks_a_person(raw: str) -> None:
    assert guard.check(raw) == guard.ASK


@pytest.mark.parametrize("raw", BLOCKED)
def test_anything_else_protected_still_blocks_even_beside_a_docs_file(raw: str) -> None:
    assert guard.check(raw) in (guard.REASON, guard.BLIND), raw
    assert guard.check(raw) != guard.ASK


@pytest.mark.parametrize("raw", ALLOWED)
def test_a_read_or_an_ordinary_docs_page_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None


@pytest.mark.parametrize("name", NAMES)
def test_every_instruction_file_name_is_asked_under_docs_and_blocked_elsewhere(name: str) -> None:
    assert guard.check(f"echo x > docs/{name}") == guard.ASK
    assert guard.check(f"echo x > {name}") == guard.REASON
    assert pathset.verdict(f"docs/{name}") == "ask"
    assert pathset.verdict(name) == "block"


def test_an_ask_exits_3_and_a_block_exits_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CHOCK_RAW_COMMAND", "echo x > docs/AGENTS.md")
    assert guard.run([]) == 3
    assert capsys.readouterr().err.startswith("ASK: ")
    monkeypatch.setenv("CHOCK_RAW_COMMAND", "echo x > AGENTS.md")
    assert guard.run([]) == 1
    assert capsys.readouterr().err.startswith("BLOCKED: ")
    monkeypatch.setenv("CHOCK_RAW_COMMAND", "cat docs/AGENTS.md")
    assert guard.run([]) == 0


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_link_can_raise_a_docs_page_to_a_block_but_never_lower_a_block_to_an_ask(_repo_root: Path) -> None:
    (_repo_root / "AGENTS.md").write_text("x\n", encoding="utf-8")
    (_repo_root / "docs/AGENTS.md").symlink_to("../AGENTS.md")
    assert guard.check("echo x > docs/AGENTS.md") == guard.REASON
    (_repo_root / "docs/GEMINI.md").write_text("x\n", encoding="utf-8")
    (_repo_root / "pages").symlink_to("docs")
    assert guard.check("echo x > pages/GEMINI.md") == guard.REASON  # spelled outside docs/, so the name blocks
    (_repo_root / "docs/CLAUDE.md").symlink_to("../.claude")
    assert guard.check("echo x > docs/CLAUDE.md/a.md") == guard.REASON
