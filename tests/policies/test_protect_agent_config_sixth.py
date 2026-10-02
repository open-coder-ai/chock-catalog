"""protect-agent-config: sixth review round -- mktemp trust past traps and indirect names, git alias bodies, escape decoding."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guard_cases_sixth as sixth
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
escape = guardkit.load_guard(POLICY, "pathescape")
subst = guardkit.load_guard(POLICY, "pathsubst")
conf = guardkit.load_guard(POLICY, "pathconf")

REFUSED = [c for name in dir(sixth) if name.endswith("_REFUSED") for c in getattr(sixth, name)]
ALLOWED = [c for name in dir(sixth) if name.endswith("_ALLOWED") for c in getattr(sixth, name)]


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in (".git", ".git/hooks", ".claude", ".cursor", ".chock", ".github", "src", "docs"):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


@pytest.mark.parametrize("raw", REFUSED)
def test_a_form_the_sixth_review_found_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize("raw", ALLOWED)
def test_its_ordinary_twin_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize(
    ("text", "mode", "printed", "known", "stop"),
    [
        ("\\0056mcp", "echo", ".mcp", True, False),
        ("\\0056mcp", "b", ".mcp", True, False),
        ("\\0056mcp", "fmt", "\x056mcp", True, False),
        ("\\0056mcp", "ansi", "\x056mcp", True, False),
        ("\\056", "b", ".", True, False),
        ("\\56", "echo", "\\56", True, False),
        ("\\056", "fmt", ".", True, False),
        ("\\56", "ansi", ".", True, False),
        ("\\0", "echo", "", True, False),
        ("\\x2e\\x2E\\x2", "b", "..\x02", True, False),
        ("\\u002e\\U0000002e", "echo", "..", True, False),
        ("\\x", "b", "\\x", False, False),
        ("\\uD800", "b", "\\uD800", False, False),
        ("\\UFFFFFFFF", "ansi", "\\UFFFFFFFF", False, False),
        ("a\\cb", "echo", "a", True, True),
        ("a\\cb", "fmt", "a\\cb", True, False),
        ("a\\cAb\\c?", "ansi", "a\x01b\x7f", True, False),
        ("a\\c", "ansi", "ac", True, False),
        ("\\q\\", "b", "\\q\\", False, False),
        ("\\q", "ansi", "q", False, False),
        ("\\\"\\'\\?", "fmt", "\"'?", True, False),
        ("\\\"\\'\\?", "b", "\\\"\\'\\?", False, False),
        ("\\n\\t\\\\\\e", "b", "\n\t\\\x1b", True, False),
        ("a\\0b", "ansi", "a\x00b".replace("\x00", ""), True, False),
    ],
)
def test_escapes_are_decoded_as_bash_reads_them(text: str, mode: str, printed: str, known: bool, stop: bool) -> None:
    got = escape.decode(text, mode)
    assert (got.text, got.known, got.stop) == (printed, known, stop)


@pytest.mark.parametrize(
    ("name", "args", "binds"),
    [
        ("trap", ["x=y", "DEBUG"], True),
        ("trap", ["--", "x=y", "DEBUG"], True),
        ("trap", ["rm -f $t", "EXIT"], False),
        ("trap", ["-p"], False),
        ("trap", ["-", "INT"], False),
        ("trap", [], False),
        ("read", ["-p", "$prompt", "y"], False),
        ("read", ["$n"], True),
        ("mapfile", ["-C", "$cb", "y"], False),
        ("mapfile", ["-C", "$cb", "$n"], True),
        ("printf", ["-v", "$n", "x"], True),
        ("declare", ["-n", "r=$n"], True),
        ("declare", ["r=$n"], False),
        ("for", ["$n", "in", "a"], True),
        ("getopts", ["ab", "$n"], True),
        ("getopts", ["$opts", "y"], False),
        ("unset", ["$n"], True),
        ("let", ["$n=1"], True),
        ("echo", ["$n"], False),
    ],
)
def test_a_binder_given_a_name_by_expansion_binds_a_variable_the_line_does_not_name(
    name: str, args: list[str], binds: bool
) -> None:
    line = " ".join([name, *args])
    seen = subst.bindings(f"x=$(mktemp); {line}")
    assert seen.rebound("x") is binds, line


@pytest.mark.parametrize(
    ("key", "value", "harmless"),
    [
        ("alias.x", "rebase -xsh", False),
        ("alias.x", "rebase", False),
        ("alias.x", "merge -s sh", False),
        ("alias.x", "merge --strategy=sh", False),
        ("alias.x", "merge --no-ff", True),
        ("alias.x", "status -s", True),
        ("alias.x", "log --max-count=3 --oneline", True),
        ("alias.x", "log --ext-diff", False),
        ("alias.x", "config core.pager sh", False),
        ("alias.x", "clone --upload-pack=sh a b", False),
        ("alias.x", "init --template=t", False),
        ("alias.x", "archive --exec=sh", False),
        ("alias.x", "commit --amend --no-edit", True),
    ],
)
def test_an_alias_value_that_can_run_a_program_is_not_harmless(key: str, value: str, harmless: bool) -> None:
    assert conf.harmless_alias(key, value) is harmless
