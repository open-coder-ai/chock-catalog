"""protect-agent-config: what a security review of the path-resolving guard found, and the ordinary commands beside it."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guardkit
from policies.guard_cases_review import ALLOWED, REFUSED
from policies.guard_corpus_ordinary import ASKED, ORDINARY

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / "src").mkdir()
    monkeypatch.chdir(root)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return root


@pytest.mark.parametrize("raw", REFUSED)
def test_a_form_the_review_found_is_refused(raw: str) -> None:
    assert guard.check(raw.replace("@ROOT@", "repo")) == guard.REASON


@pytest.mark.parametrize("raw", ALLOWED)
def test_its_ordinary_twin_is_allowed(raw: str) -> None:
    assert guard.check(raw.replace("@ROOT@", "repo")) is None


@pytest.mark.parametrize("raw", ORDINARY)
def test_an_ordinary_development_command_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None


@pytest.mark.parametrize("raw", ASKED)
def test_a_write_to_a_path_that_is_not_known_asks_a_person(raw: str) -> None:
    assert guard.check(raw) == guard.REASON


def test_the_directory_the_hook_runs_in_is_the_start(_repo_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (_repo_root / ".cursor").mkdir()
    monkeypatch.chdir(_repo_root / ".cursor")
    assert guard.check("echo x > mcp.json") == guard.REASON
    assert guard.check("echo x > ../.cursor/rules.txt") == guard.REASON
    assert guard.check("echo x > ../src/rules.txt") is None
    monkeypatch.chdir(_repo_root / "src")
    assert guard.check("echo x > mcp.json") is None


def test_a_directory_the_hook_names_is_the_start_when_the_runner_gives_one(
    _repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CHOCK_HOOK_CWD", str(_repo_root / ".cursor"))
    assert guard.check("echo x > mcp.json") == guard.REASON
    monkeypatch.setenv("CHOCK_HOOK_CWD", str(_repo_root / "src"))
    assert guard.check("echo x > mcp.json") is None
    assert guard.check("echo x > ../.mcp.json") == guard.REASON


def test_the_nesting_of_shells_fed_by_standard_input_is_limited(_repo_root: Path) -> None:
    script = "echo done > out.txt"
    for level in range(6):
        script = f"sh <<L{level}\n{script}\nL{level}"
    assert guard.check(script) == guard.REASON


def test_a_brace_list_is_expanded_into_its_words() -> None:
    text = guardkit.load_guard(POLICY, "pathtext")
    assert text.braces("a{b,c}d") == ["abd", "acd"]
    assert text.braces("{1..3}") == ["1", "2", "3"]
    assert text.braces("{3..1}") == ["1", "2", "3"]
    assert text.braces("{a..c}.x") == ["a.x", "b.x", "c.x"]
    assert text.braces("{c..a}") == ["a", "b", "c"]
    assert text.braces("{a,{b,c}}") == ["a", "b", "c"]
    assert text.braces("{,.bak}") == ["", ".bak"]
    assert text.braces("{}") == ["{}"]
    assert text.braces("{a,b") == ["{a,b"]
    assert text.braces("${X}{a,b}") == ["${X}a", "${X}b"]
    assert len(text.braces("{1..9999}")) == 129
    assert text.braces("{1..9999}")[-1] == text.SUBST  # what a long range leaves out is read as unknown text
    assert text.braces("{-500..5}")[-1] == text.SUBST
    assert text.braces("{a,b}{1..3}") == ["a1", "a2", "a3", "b1", "b2", "b3"]


def test_ansi_c_quoting_is_decoded() -> None:
    text = guardkit.load_guard(POLICY, "pathtext")
    assert text.ansi_c("\\x2ecursor\\056\\u002e\\U0000002e") == ".cursor..."
    assert text.ansi_c("a\\tb\\n\\\\\\'\\0z") == "a\tb\n\\'z"
    assert text.ansi_c("\\x00\\q") == "q"
