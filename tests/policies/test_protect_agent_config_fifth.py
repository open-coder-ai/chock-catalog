"""protect-agent-config: fifth review round -- git config forms, decoy producers, dynamic prefixes, mktemp, Windows roots."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from policies import guard_cases_fifth as fifth
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
SCRIPT = guardkit.impl_dir(POLICY) / "protect-agent-config.py"
conf = guardkit.load_guard(POLICY, "pathconf")
feed = guardkit.load_guard(POLICY, "pathfeed")
subst = guardkit.load_guard(POLICY, "pathsubst")
words = guardkit.load_guard(POLICY, "pathwords")

REFUSED = [
    *fifth.GIT_EDIT_REFUSED,
    *fifth.GIT_OPTION_REFUSED,
    *fifth.GIT_SUBCOMMAND_REFUSED,
    *fifth.GIT_ALIAS_REFUSED,
    *fifth.FEED_REFUSED,
    *fifth.DYNAMIC_PREFIX_REFUSED,
    *fifth.MKTEMP_REFUSED,
]
ALLOWED = [*fifth.GIT_CONFIG_ALLOWED, *fifth.FEED_ALLOWED, *fifth.DYNAMIC_PREFIX_ALLOWED, *fifth.MKTEMP_ALLOWED]
WINDOWS = r"C:\Users\me\repo"
WINDOWS_REFUSED = [
    r"robocopy src C:\Users\me\repo /E",
    r"robocopy src C:\Users\me\repo\ /E",
    r"robocopy src c:/users/me/repo /MIR",
    r"robocopy src C:\Users\me /E",
    r"robocopy src C:\ /MIR",
    r"robocopy src C:\ /E",
    r"robocopy src \ /MIR",
    r"robocopy src C:\Users\me\repo\.claude /E",
    r"xcopy src C:\Users\me\repo\ /E",
    r'xcopy src "C:\Users\me\repo"',
    r"xcopy src\* C:\Users\me\repo",
    r"rd /s /q C:\Users\me\repo",
    r"rd /s C:\Users",
    r"rd /s /q C:\Users\me\repo\.claude",
    r"rd /s /q %CD%",
    r"del C:\Users\me\repo\AGENTS.md",
    r"copy src\x C:\Users\me\repo\.mcp.json",
    r"echo x > C:\Users\me\repo\.mcp.json",
    r"echo x > c:\USERS\me\REPO\.MCP.JSON",
    r"echo x > C:\Users\me\repo\.git\hooks\pre-commit",
    r"Remove-Item -Recurse -Force C:\Users\me\repo",
    r"Remove-Item -Recurse -Force C:\Users",
    r"cp x C:/Users/me/repo/.cursor/mcp.json",
    r"move src C:\Users\me\repo\AGENTS.md",
]
WINDOWS_ALLOWED = [
    r"robocopy src C:\Users\me\repo\build /E",
    r"robocopy src C:\Users\me\repo\build /MIR",
    r"robocopy src C:\Users\me\other /E",
    r"robocopy src D:\ /MIR",
    r"robocopy src D:\Users\me\repo /E",
    r"xcopy src C:\Users\me\other /E",
    r"xcopy src C:\Users\me\repo\build\ /E",
    r"rd /s /q C:\Users\me\repo\build",
    r"rd /s /q C:\Users\me\other",
    r"echo x > C:\Users\me\repo\notes.txt",
    r"copy src\x C:\Users\me\repo\src\x",
    r"Remove-Item -Recurse -Force C:\Users\me\repo\build",
]


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in (".git", ".git/hooks", ".claude", ".cursor", ".chock", ".github", "src", "docs"):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


@pytest.mark.parametrize("raw", REFUSED)
def test_a_form_the_fifth_review_found_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize("raw", ALLOWED)
def test_its_ordinary_twin_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize("raw", WINDOWS_REFUSED)
def test_a_windows_native_path_at_the_repository_or_above_it_is_refused(
    raw: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CHOCK_HOOK_CWD", WINDOWS)
    assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize("raw", WINDOWS_ALLOWED)
def test_a_windows_native_path_below_the_repository_or_elsewhere_is_allowed(
    raw: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CHOCK_HOOK_CWD", WINDOWS)
    assert guard.check(raw) is None, raw


def test_a_windows_root_is_read_as_windows_reads_it(monkeypatch: pytest.MonkeyPatch) -> None:
    assert list(words.ancestors(WINDOWS)) == [WINDOWS, r"C:\Users\me", r"C:\Users", "C:\\"]
    assert list(words.ancestors("C:/Users/me")) == ["C:/Users/me", "C:/Users", "C:/"]
    monkeypatch.setenv("CHOCK_HOOK_CWD", WINDOWS)
    assert guard.check(r"robocopy src C:\Users\me\repo /E") == guard.REASON
    monkeypatch.setenv("CHOCK_HOOK_CWD", "C:/Users/me/repo")
    assert guard.check("rd /s /q C:/Users/me/repo") == guard.REASON


def test_a_mktemp_variable_line_of_thousands_is_read_in_linear_time(_repo_root: Path) -> None:
    """Run as a hook runs it, outside the coverage tracer, which slows a python loop several times over."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("COV", "COVERAGE"))}
    for raw in (
        "x=$(mktemp); " + "; ".join(f"echo y{i} > $x" for i in range(4000)),
        "; ".join(f"x{i}=$(mktemp); echo y > $x{i}" for i in range(400)),
    ):
        start = time.monotonic()
        done = subprocess.run(
            [sys.executable, str(SCRIPT)],
            env={**env, "CHOCK_RAW_COMMAND": raw, "CHOCK_HOOK_CWD": str(_repo_root)},
            capture_output=True,
            check=False,
            cwd=_repo_root,
            timeout=60,
        )
        assert done.returncode == 0
        assert time.monotonic() - start < 2


@pytest.mark.parametrize(
    ("args", "flags", "rest", "files"),
    [
        (["--edi"], {"--edit"}, [], []),
        (["-ef", ".git/config"], {"--edit"}, [], [".git/config"]),
        (["-fe", "x"], {"--edit"}, ["x"], ["e"]),
        (["-fexample.cfg"], set(), [], ["example.cfg"]),
        (["-f"], set(), [], []),
        (["-lz"], {"--list"}, [], []),
        (["--fil", "a", "k", "v"], {"--file"}, ["k", "v"], ["a"]),
        (["--file=a"], {"--file"}, [], ["a"]),
        (["--file"], {"--file"}, [], []),
        (["--ge"], {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--get-color", "--get-colorbool"}, [], []),
        (["--get", "-", "--", "-e"], {"--get"}, ["-", "-e"], []),
        (["--unknown", "-x"], set(), [], []),
    ],
)
def test_git_config_options_are_read_by_prefix_and_bundle(
    args: list[str], flags: set[str], rest: list[str], files: list[str]
) -> None:
    found = conf._options(args)
    assert (found[0], found[1], found[2]) == (flags, rest, files)


@pytest.mark.parametrize(
    ("key", "value", "harmless"),
    [
        ("alias.co", "checkout", True),
        ("ALIAS.lg", "log --oneline", True),
        ("alias.co", "", False),
        ("alias.co", "!sh", False),
        ("alias.co", " !sh", False),
        ("alias.co", "-c core.pager=x log", False),
        ("alias.co", "foo", False),
        ("alias.co", "$X", False),
        ("alias.co", "rebase --exec x", False),
        ("alias.co", "rebase -x x", False),
        ("alias.co", "submodule foreach x", False),
        ("core.pager", "log", False),
    ],
)
def test_only_an_alias_of_a_plain_git_command_runs_no_program(key: str, value: str, harmless: bool) -> None:
    assert conf.harmless_alias(key, value) is harmless


@pytest.mark.parametrize(
    ("fmt", "args", "printed"),
    [
        ("%s\\n", ["a", "b"], "a\nb\n"),
        ("echo hi", ["ignored"], "echo hi"),
        ("%s %s", ["a"], "a "),
        ("%%%s", ["a"], "%a"),
        ("%5.2s|", ["a"], "a|"),
        ("%b", ["x\\ty"], "x\ty"),
        ("%s", [], ""),
        ("a\\tb", [], "a\tb"),
    ],
)
def test_printf_applies_its_format_to_its_arguments(fmt: str, args: list[str], printed: str) -> None:
    assert feed.render(fmt, args)[0] == printed


def _cmd(name: str, *args: str, writes: list[str] | None = None, reads: list[str] | None = None) -> SimpleNamespace:
    return SimpleNamespace(name=name, args=list(args), env={}, writes=writes or [], reads=reads or [], doc="")


@pytest.mark.parametrize(
    ("cmd", "printed", "exact"),
    [
        (_cmd("echo", "-n", "a", "b"), ["a b"], True),
        (_cmd("echo", "-e", "a\\nb"), ["a\\nb", "a\nb"], True),
        (_cmd("echo", "$X"), ["$X"], False),
        (_cmd("echo", "a", writes=["f"]), ["a"], False),
        (_cmd("printf", "%s\\n", "a"), ["a\n"], True),
        (_cmd("printf", "--", "%s", "a"), ["a"], True),
        (_cmd("printf", "%s", "$A"), ["$A"], False),
        (_cmd("printf", "-v", "x", "%s", "a"), [], True),
        (_cmd("printf"), [], True),
        (_cmd("cat", reads=["__d__"]), ["body"], True),
        (_cmd("cat", "-n", reads=["__d__"]), ["body"], True),
        (_cmd("cat", "file", reads=["__d__"]), ["body"], False),
        (_cmd("cat", reads=["file"]), [], False),
        (_cmd("cat"), [], False),
    ],
)
def test_a_producer_is_exact_only_when_the_line_shows_all_its_text(
    cmd: SimpleNamespace, printed: list[str], exact: bool
) -> None:
    assert feed.shown(cmd, {"__d__": "body"}) == (printed, exact)


def test_the_strings_of_any_other_producer_are_each_a_candidate_script() -> None:
    cmds = [_cmd("echo", "hi"), _cmd("echo", "echo x > f"), _cmd("cat", "--", reads=["__d__", "f"])]
    assert feed.strings(cmds, {"__d__": "a; b"}) == ["echo x > f", "a; b"]


@pytest.mark.parametrize(
    ("text", "name", "rebound"),
    [
        ("x=$(mktemp); echo y > $x", "x", False),
        ("x=$(mktemp); echo x=$x; echo y > $x", "x", False),
        ('x=$(mktemp); echo "x: $x"', "x", False),
        ("x=$(mktemp); x=$(mktemp)", "x", True),
        ("x=$(mktemp); x+=a", "x", True),
        ("x=$(mktemp); x=a cmd", "x", True),
        ("x=$(mktemp); declare -n x=y", "x", True),
        ("x=$(mktemp); declare -n r=x", "x", True),
        ("x=$(mktemp); declare -n r=y", "x", False),
        ("x=$(mktemp); declare -n r=y", "r", True),
        ("x=$(mktemp); declare x", "x", False),
        ("x=$(mktemp); declare --foo -- x", "x", False),
        ("x=$(mktemp); eval 'x=a'", "x", True),
        ("x=$(mktemp); eval 'eval \"x=a\"'", "x", True),
        ("x=$(mktemp); eval 'echo hi'", "x", False),
        ('x=$(mktemp); eval "$a"', "x", True),
        ("x=$(mktemp); eval 'eval eval eval eval eval eval eval x=a'", "x", True),
        ("x=$(mktemp); source f", "x", True),
        ("x=$(mktemp); (( x++ ))", "x", True),
        ("x=$(mktemp); (( n = 1 ))", "x", False),
        ("x=$(mktemp); select x in a; do :; done", "x", True),
        ("x=$(mktemp); mapfile -t arr < f", "x", False),
        ("x=$(mktemp); mapfile -t x < f", "x", True),
        ("x=$(mktemp); read -r a b", "x", False),
        ("x=$(mktemp); getopts ab x", "x", True),
        ("x=$(mktemp); getopts ab y", "x", False),
        ("x=$(mktemp); printf -v y a", "x", False),
        ("x=$(mktemp); printf a -v x", "x", False),
        ("x=$(mktemp); printf -v", "x", False),
        ("x=$(mktemp); printf -x -v x a", "x", True),
        ("x=$(mktemp); echo ${x:=a}", "x", True),
        ('x=$(mktemp); echo "${x:-a}"', "x", False),
        ("x=$(mktemp); x[1]=a", "x", True),
        ("x=$(mktemp); let n=1", "x", False),
        ("x=$(mktemp); let x=1", "x", True),
        ("x=$(mktemp); unset -v x", "x", True),
        ("x=$(mktemp); command read x", "x", True),
        ("x=$(mktemp) && while read y; do :; done", "x", False),
        ("x=$(mktemp); read -d '' y", "x", False),
        ("x=$(mktemp); echo 'unterminated", "x", False),
        ("echo y > $x", "x", True),
    ],
)
def test_a_variable_is_rebound_only_by_a_construct_that_binds_it(text: str, name: str, rebound: bool) -> None:
    assert subst.bindings(text).rebound(name) is rebound, text
