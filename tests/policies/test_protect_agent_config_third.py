"""protect-agent-config: bracket globs, nesting, git, Windows tools, wrappers, find -exec, mktemp, inline code."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from policies import guard_cases_third as third
from policies import guard_cases_wrappers as wrappers
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
match = guardkit.load_guard(POLICY, "pathmatch")
wrap = guardkit.load_guard(POLICY, "pathwrap")
SCRIPT = Path(guard.__file__)

REFUSED = [
    *third.GIT_CONFIG_REFUSED,
    *third.GIT_CLEAN_REFUSED,
    *third.WINDOWS_REFUSED,
    *third.MKTEMP_REFUSED,
    *third.UNKNOWN_START_REFUSED,
    *third.BASENAME_REFUSED,
    *wrappers.WRAPPERS_REFUSED,
    *wrappers.FIND_REFUSED,
    *wrappers.CODE_REFUSED,
]
ALLOWED = [
    *third.GIT_CONFIG_ALLOWED,
    *third.GIT_CLEAN_ALLOWED,
    *third.WINDOWS_ALLOWED,
    *third.MKTEMP_ALLOWED,
    *third.UNKNOWN_START_ALLOWED,
    *third.BASENAME_ALLOWED,
    *wrappers.WRAPPERS_ALLOWED,
    *wrappers.FIND_ALLOWED,
    *wrappers.CODE_ALLOWED,
]
LITERALS = [".mcp.json", ".claude/settings.json", ".claude", ".cursor", ".git/hooks", ".chock/bin", ".cursor/mcp.json"]
FORMS = ["echo x > {}", "rm {}", "rm -rf {}", "tee {}", "cp a {}", "mv a {}", "touch {}", "rm -r {}", "ln -s a {}"]


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in (".git", ".claude", ".cursor", ".chock", "src", "docs"):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


@pytest.mark.parametrize("raw", REFUSED)
def test_a_form_the_third_review_found_is_refused(raw: str) -> None:
    assert guard.check(raw), raw


@pytest.mark.parametrize("raw", ALLOWED)
def test_its_ordinary_twin_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize("literal", LITERALS)
@pytest.mark.parametrize("form", FORMS)
def test_a_leading_bracket_glob_is_judged_like_the_name_it_can_match(literal: str, form: str) -> None:
    for glob in (f"[.]{literal[1:]}", f"[!a]{literal[1:]}", f"[[:punct:]]{literal[1:]}", f"[.,]{literal[1:]}"):
        assert guard.check(form.format(glob)) == guard.check(form.format(literal)), glob


@pytest.mark.parametrize("literal", [".mcp.json", ".claude/settings.json", ".cursor/mcp.json"])
def test_every_writer_is_refused_through_a_leading_bracket_glob(literal: str) -> None:
    for form in FORMS:
        assert guard.check(form.format(f"[.]{literal[1:]}")) == guard.REASON, form


@pytest.mark.parametrize(
    "raw", ["echo x > [a]mcp.json", "rm [a-c]laude", "touch [x]y.txt", "rm -rf [.]venv", "rm [.]git/x"]
)
def test_a_bracket_that_cannot_reach_a_protected_name_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None


@pytest.mark.parametrize(
    ("glob", "text", "matches"),
    [
        ("[.]mcp.json", ".mcp.json", True),
        ("[.]mcp.json", "xmcp.json", False),
        ("[!a]mcp.json", ".mcp.json", True),
        ("[[:punct:]]mcp.json", ".mcp.json", True),
        ("[[:alpha:]]mcp.json", ".mcp.json", False),
        ("[[:alpha:]]mcp.json", "xmcp.json", True),
        ("[[:bogus:]]mcp.json", ".mcp.json", True),
        ("a/[.]b", "a/.b", True),
        ("[]]x", "]x", True),
        ("[a-c]x", ".x", False),
        ("*x", ".x", False),
        ("[z-a]x", ".x", True),
    ],
)
def test_a_bracket_expression_that_can_match_a_dot_matches_a_leading_dot(glob: str, text: str, matches: bool) -> None:
    assert bool(match.pattern(glob, loose=False).fullmatch(text)) == matches


def _nest(command: str, depth: int) -> str:
    for _ in range(depth):
        command = f"bash -c {shlex.quote(command)}"
    return command


@pytest.mark.parametrize("depth", range(1, 9))
def test_a_write_inside_nested_shells_is_refused_at_every_depth(depth: int) -> None:
    assert guard.check(_nest("echo x > .mcp.json", depth)) is not None


@pytest.mark.parametrize("depth", range(5, 9))
def test_a_script_nested_past_the_readers_limit_is_refused_with_its_own_reason(depth: int) -> None:
    for inner in ("echo hi", "echo x > .mcp.json", "make"):
        assert guard.check(_nest(inner, depth)) == guard.DEEP
    assert "nested too deep" in guard.DEEP


@pytest.mark.parametrize("depth", range(1, 5))
def test_a_harmless_script_within_the_limit_is_allowed(depth: int) -> None:
    assert guard.check(_nest("echo hi", depth)) is None


@pytest.mark.parametrize(
    "wrapper", ["sh -c", "bash -c", "zsh -c", "dash -c", "ksh -c", "eval", "sudo bash -c", "cmd /c"]
)
def test_every_wrapper_counts_toward_the_nesting_limit(wrapper: str) -> None:
    command = "echo hi"
    for _ in range(6):
        command = f"{wrapper} {shlex.quote(command)}"
    assert guard.check(command) == guard.DEEP


def test_a_substitution_does_not_reset_the_nesting_count() -> None:
    command = _nest("echo hi", 5)
    assert guard.check(f"echo $({command})") == guard.DEEP
    assert guard.check(f"echo `{command}`") == guard.DEEP
    assert guard.check(f"x=$(echo $(echo $({command})))") == guard.DEEP


def test_the_script_exits_one_for_a_script_nested_too_deep() -> None:
    env = {**os.environ, "CHOCK_RAW_COMMAND": _nest("echo hi", 6), "CHOCK_HOOK_CWD": str(Path.cwd())}
    done = subprocess.run([sys.executable, str(SCRIPT)], env=env, capture_output=True, text=True, check=False)
    assert done.returncode == 1
    assert "nested too deep" in done.stderr


def test_a_brace_list_longer_than_the_limit_is_not_cut_short() -> None:
    names = ",".join(f"f{i}" for i in range(200))
    assert guard.check(f"rm {{{names},.mcp.json}}") == guard.REASON
    assert guard.check("echo x > .devin/hooks.v{-500..5}.json") == guard.REASON
    assert guard.check("rm {a,b,c}") is None


@pytest.mark.parametrize(
    "raw",
    [
        "T=$(mktemp -d); echo x > $T/../.mcp.json",
        "T=$(mktemp -d); rm $T/../x.txt",
        "echo x > $(mktemp)/../out.txt",
        "T=$(mktemp -d); cd $T/..; echo x > mcp.json",
        "T=$(mktemp -p .cursor); echo x > $T",
        "T=$(mktemp .claude/settings.XXXXXX); echo x > $T",
        "T=$(mktemp --tmpdir=.cursor); echo x > $T",
        "T=$(mktemp -d); T=$T/..; echo x > $T/.mcp.json",
        "echo x > $(mktemp; echo .mcp.json)",
    ],
)
def test_a_path_that_leaves_a_mktemp_root_or_is_not_a_plain_mktemp_is_unknown(raw: str) -> None:
    assert guard.check(raw) == guard.REASON


@pytest.mark.parametrize(
    "raw",
    [
        "T=$(mktemp -d); echo x > $T/out.txt; rm -rf $T",
        "T=$(mktemp -d); mkdir -p $T/a/b; cp -r src $T/a/b/",
        "T=$(mktemp -d --suffix=.d); echo x > ${T}/y",
        "T=$(mktemp -t x.XXXXXX); echo x > $T",
        "T=$(mktemp ${TMPDIR}/x.XXXXXX); echo x > $T",
        'T=$(mktemp -d); echo x > "$T/mcp.json"',
        'T=$(mktemp -d); mv "$T" out',
    ],
)
def test_a_fresh_mktemp_path_and_what_lies_below_it_are_allowed(raw: str) -> None:
    assert guard.check(raw) is None


def test_a_destination_that_is_an_existing_directory_receives_the_basename(_repo_root: Path) -> None:
    assert guard.check("cp /srv/e/CLAUDE.md docs") == guard.REASON
    assert guard.check("mv /srv/e/AGENTS.md src") == guard.REASON
    assert guard.check("cp /srv/e/README.md docs") is None
    assert guard.check("cp /srv/e/CLAUDE.md newname.txt") is None
    assert guard.check("cp CLAUDE.md /srv/backup/") is None
    (_repo_root / "Docs").mkdir()
    assert guard.check("cp /srv/e/CLAUDE.md DOCS") == guard.REASON


def test_git_clean_judges_its_pathspecs_and_ignored_files() -> None:
    assert guard.check("git clean -fd -e keep -- .claude") == guard.REASON
    assert guard.check("git clean -fd -ekeep -x") == guard.REASON
    assert guard.check("git clean -fdn -e x -x") is None
    assert guard.check("git clean -fd -e x") is None
    assert guard.check("git clean -fd --exclude=x") is None
    assert guard.check("git clean --dry-run -fdx") is None
    assert guard.check("git clean -fdx .") == guard.REASON
    assert (
        guard.check("git clean -fd .") == guard.REASON
    )  # round four: the repository folder holds every protected path
    assert guard.check("git clean -fd src docs") is None


def test_the_env_split_string_is_judged_where_the_line_has_got_to() -> None:
    assert guard.check("cd .cursor && env -S 'tee mcp.json'") == guard.REASON
    assert guard.check("env -u X -S 'rm .mcp.json'") == guard.REASON
    assert guard.check("env -S'rm .mcp.json'") == guard.REASON
    assert guard.check("env --split-string='rm .mcp.json'") == guard.REASON
    assert guard.check("bash -c \"env -S 'rm .mcp.json'\"") == guard.REASON
    assert guard.check("env -S 'make all'") is None
    assert guard.check("env -i make") is None


@pytest.mark.parametrize(
    ("name", "args", "scripts", "unsure"),
    [
        ("flock", ["-n", "lock", "rm", "x"], ["rm x"], False),
        ("flock", ["lock", "-c", "rm x"], ["rm x"], False),
        ("flock", ["--weird", "lock", "ls"], ["ls"], True),
        ("strace", ["-fo", "log", "ls", "-l"], ["ls -l"], False),
        ("strace", ["-o", "log", "ls"], ["ls"], False),
        ("taskset", ["-c", "0", "make"], ["make"], False),
        ("chrt", ["-f", "10", "make"], ["make"], False),
        ("watch", ["-n", "1", "ls", "|", "wc"], ["ls | wc"], False),
        ("su", ["-", "user", "-c", "id"], ["id"], False),
        ("su", ["-l"], [], False),
        ("fish", ["-lc", "id"], ["id"], False),
        ("trap", ["--", "id", "EXIT"], ["id"], False),
        ("trap", ["-l"], [], False),
        ("trap", ["-", "EXIT"], [], False),
        ("coproc", ["ls", "-l"], ["ls -l"], False),
        ("fakeroot", ["--", "make"], ["make"], False),
        ("unshare", ["-r", "--fork", "make"], ["make"], False),
        ("busybox", ["ls"], ["ls"], False),
        ("busybox", ["--list"], [], True),
        ("make", ["x"], None, False),
    ],
)
def test_a_wrapper_gives_up_the_script_it_runs(
    name: str, args: list[str], scripts: list[str] | None, unsure: bool
) -> None:
    got = wrap.unwrap(name, args)
    assert (got if got is None else (got[0], got[1])) == (None if scripts is None else (scripts, unsure))


def test_an_option_the_guard_does_not_know_leaves_a_protected_name_in_the_line_refused() -> None:
    assert guard.check("strace --brand-new 1 cat .mcp.json") == guard.REASON
    assert guard.check("strace --brand-new 1 cat README.md") is None
    assert guard.check("unshare --brand-new 1 cat .claude/settings.json") == guard.REASON


def test_the_depth_of_a_find_exec_is_not_used_up_by_its_candidates() -> None:
    assert guard.check("find . -exec echo {} \\;") is None
    assert guard.check("find . -type f -exec grep -l x {} +") is None
    assert guard.check("find . -exec sh -c 'cat \"$0\"' {} \\;") is None
    assert guard.check("find . -exec sh -c 'rm \"$0\"' {} \\;") == guard.REASON
    assert guard.check("find . -name '*.md' -delete") == guard.REASON
    assert guard.check("find src -type f -exec foo {} +") is None
    assert guard.check("find . -exec foo {} +") == guard.REASON
    assert guard.check("find . -exec foo \\;") is None


def test_substitutions_nested_past_the_walks_limit_are_refused_when_they_could_write() -> None:
    assert guard.check("echo $(echo $(echo $(echo hi)))") is None
    assert guard.check("echo $(echo $(echo $(echo $(echo hi))))") is None
    assert guard.check("echo $(echo $(echo $(echo $(rm -f build.log))))") == guard.REASON
    assert guard.check("echo $(echo $(echo $(echo $(find . -delete))))") == guard.REASON
    assert guard.check("echo $(echo $(echo $(echo $(echo x > .mcp.json))))") == guard.REASON
