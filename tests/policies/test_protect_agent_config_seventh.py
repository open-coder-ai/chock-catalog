"""protect-agent-config: seventh review round -- `--` before a script, `$'..'` in a quoted script, function bodies, derived
variables and late namerefs, arrays and `+=`, abbreviated git options in alias bodies, format placeholders, unknown aliases."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guard_cases_seventh as seventh
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
subst = guardkit.load_guard(POLICY, "pathsubst")
conf = guardkit.load_guard(POLICY, "pathconf")
gitmod = guardkit.load_guard(POLICY, "pathgit")


WINDOWS = r"C:\Users\me\repo"


def _cases(suffix: str, *, windows: bool = False) -> list[str]:
    """The commands of every list of the case module that ends in `suffix`; the `WIN` lists are for a Windows root."""
    return [
        c
        for name in dir(seventh)
        if name.endswith(suffix) and name.startswith("WIN") == windows
        for c in getattr(seventh, name)
    ]


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in (".git", ".git/hooks", ".claude", ".cursor", ".chock", ".github", "src", "docs"):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


@pytest.mark.parametrize("raw", _cases("_REFUSED", windows=True))
def test_a_windows_form_the_seventh_review_found_is_refused(raw: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHOCK_HOOK_CWD", WINDOWS)
    assert guard.check(raw) in (guard.REASON, guard.BLIND), raw


@pytest.mark.parametrize("raw", _cases("_ALLOWED", windows=True))
def test_its_windows_twin_is_allowed(raw: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHOCK_HOOK_CWD", WINDOWS)
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize("raw", _cases("_REFUSED"))
def test_a_form_the_seventh_review_found_is_refused(raw: str) -> None:
    assert guard.check(raw) in (guard.REASON, guard.BLIND), raw


@pytest.mark.parametrize("raw", _cases("_ALLOWED"))
def test_its_ordinary_twin_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize(
    ("text", "name", "rebound"),
    [
        ("x=$(mktemp); declare -n r; r=x; r=y", "x", True),
        ("x=$(mktemp); r=x; declare -n r; r=y", "x", True),
        ("x=$(mktemp); declare -n r=y; y=x; r=z", "x", True),
        ("x=$(mktemp); declare -n a; declare -n b; a=b; b=x; a=z", "x", True),
        ("x=$(mktemp); declare -n r; r=$n; r=z", "x", True),
        ("x=$(mktemp); declare -n r; r=other", "x", False),
        ("x=$(mktemp); r=x; echo $r", "x", False),
        ("x=$(mktemp); f(){ x=y; }", "x", True),
        ("x=$(mktemp); { x=y; }", "x", True),
        ("x=$(mktemp); command -- read x", "x", True),
        ("x=$(mktemp); eval -- 'x=y'", "x", True),
    ],
)
def test_a_name_assigned_to_a_reference_is_bound_through_it(text: str, name: str, rebound: bool) -> None:
    assert subst.bindings(text).rebound(name) is rebound, text


@pytest.mark.parametrize(
    ("text", "name", "hidden"),
    [
        ("x=a; read x", "x", True),
        ("x=a; for x in b; do :; done", "x", True),
        ("x=a; printf -v x y", "x", True),
        ("x=a; eval 'read x'", "x", True),
        ("x=a; trap 'read x' EXIT", "x", True),
        ("x=a; x=b", "x", False),
        ("x=a; read y", "x", False),
    ],
)
def test_a_variable_set_by_input_the_line_does_not_show_is_hidden(text: str, name: str, hidden: bool) -> None:
    assert (name in subst.bindings(text).hidden) is hidden, text


@pytest.mark.parametrize(
    ("command", "word", "runs"),
    [
        ("ls-remote", "--u=sh", True),
        ("ls-remote", "--up=sh", True),
        ("ls-remote", "--upload-pack=sh", True),
        ("ls-remote", "--heads", False),
        ("archive", "--e=sh", True),
        ("archive", "--format=zip", False),
        ("push", "--e=sh", True),
        ("push", "--rec=sh", True),
        ("push", "--recurse-submodules=check", False),
        ("push", "--force-with-lease", False),
        ("fetch", "--upl", True),
        ("fetch", "-u", True),
        ("fetch", "--unshallow", False),
        ("fetch", "--update-head-ok", False),
        ("pull", "-x", True),
        ("pull", "--rebase", False),
        ("rebase", "--e=sh", True),
        ("rebase", "-x", True),
        ("rebase", "--empty=drop", False),
        ("clone", "--u=sh", True),
        ("clone", "--co=core.x=y", True),
        ("clone", "--te=t", True),
        ("clone", "-c", True),
        ("clone", "--depth", False),
        ("clone", "--recurse-submodules", False),
        ("init", "--t=t", True),
        ("init", "--te=t", True),
        ("init", "--bare", False),
        ("log", "--exe=sh", True),
        ("log", "--ex", False),
        ("log", "--oneline", False),
        ("log", "-e", False),
        ("log", "--", False),
    ],
)
def test_an_option_word_that_git_reads_as_a_program_option_is_recognised_by_any_prefix(
    command: str, word: str, runs: bool
) -> None:
    assert conf._runs_program(command, word) is runs, (command, word)


@pytest.mark.parametrize(
    ("value", "plain"),
    [
        ("log --format=%h*", "log --format="),
        ("log --pretty=format:'%h [%an]' --graph", "log --format= --graph"),
        ('log --pretty=tformat:"%h x" -3', "log --format= -3"),
        ("log --format='unclosed %h --exec=sh", "log --format= %h --exec=sh"),
        ("log --format='a'--exec=sh", "log --format=--exec=sh"),
        ('ls-remote "--upload-pack=sh" o', "ls-remote --upload-pack=sh o"),
        ("log --oneline", "log --oneline"),
    ],
)
def test_an_alias_value_is_read_as_git_splits_it(value: str, plain: str) -> None:
    assert conf._plain(value) == plain


@pytest.mark.parametrize(
    ("value", "harmless"),
    [
        ("log --pretty=format:'%h %ad | %s%d [%an]' --graph --date=short", True),
        ('log --format="%h [%an]"', True),
        ("log --graph --format=%h*", True),
        ("for-each-ref --sort=-committerdate refs/heads/", True),
        ("for-each-ref --format='%(refname:short) [%(objectname:short)]'", True),
        ("ls-tree -r HEAD", True),
        ("show-ref --heads", True),
        ("log *", False),
        ("log [ab]*", False),
        ("log --format=%h $x", False),
        ("log --format=%h --exec=sh", False),
        ("log --pretty=format:%h --exe=sh", False),
        ("ls-remote '--upload-pack=sh' o", False),
        ("clone --u=sh o d", False),
        ("for-each-ref refs/heads/*", False),
    ],
)
def test_an_alias_with_format_placeholders_runs_no_program(value: str, harmless: bool) -> None:
    assert conf.harmless_alias("alias.x", value) is harmless, value


@pytest.mark.parametrize(
    ("args", "short", "longs", "values"),
    [
        (["-x", "a", "b"], "x", ("--exec",), ["a"]),
        (["-xa", "b"], "x", ("--exec",), ["a"]),
        (["-ix", "a"], "x", ("--exec",), ["a"]),
        (["-x"], "x", ("--exec",), [""]),
        (["--exec=a", "b"], "x", ("--exec",), ["a"]),
        (["--exec", "a"], "x", ("--exec",), ["a"]),
        (["--exe", "a"], "x", ("--exec",), ["a"]),
        (["--exec"], "x", ("--exec",), [""]),
        (["--e", "a"], "x", ("--exec",), ["a"]),
        (["--ex", "-n"], "x", ("--exec",), ["-n"]),
        (["--ab", "a"], "x", ("--exec",), []),
        (["--empty=drop", "-X", "-i", "main"], "x", ("--exec",), []),
        (["--output=f", "--output", "g"], "", ("--output",), ["f", "g"]),
        (["--output-indicator-new=+", "-5", "-n"], "", ("--output",), []),
        (["--tree-filter", "a", "--msg-filter=b", "--env-filter"], "", ("--tree-filter", "--msg-filter"), ["a", "b"]),
    ],
)
def test_the_value_of_a_git_option_is_read_as_git_reads_it(
    args: list[str], short: str, longs: tuple[str, ...], values: list[str]
) -> None:
    assert gitmod._values(args, short, longs) == values


@pytest.mark.parametrize(
    ("sub", "args", "env", "texts"),
    [
        ("commit", [], {"GIT_EDITOR": "vim -c x", "other": "y"}, ["vim -c x"]),
        ("commit", [], {"EDITOR": "$(which vim)", "PAGER": "less"}, ["less"]),
        ("rebase", ["-x", "make", "--exec=t"], {}, ["make", "t"]),
        ("difftool", ["-x", "d", "--extcmd=e"], {}, ["d", "e"]),
        ("filter-branch", ["--tree-filter", "t", "HEAD"], {}, ["t"]),
        ("bisect", ["run", "sh", "-c", "a b"], {}, ["sh -c 'a b'"]),
        ("bisect", ["start"], {}, []),
        ("submodule", ["foreach", "--recursive", "git", "pull"], {}, ["git pull"]),
        ("submodule", ["update", "--init"], {}, []),
        ("log", ["-x", "--exec=a"], {}, []),
    ],
)
def test_the_programs_a_git_command_runs_are_the_ones_it_is_given(
    sub: str, args: list[str], env: dict[str, str], texts: list[str]
) -> None:
    assert gitmod._programs(sub, args, env) == texts


@pytest.mark.parametrize(
    ("path", "normal"),
    [
        (".Claude.\\Settings.json", ".claude/settings.json"),
        (".claude \\settings.json", ".claude/settings.json"),
        ("a. . /b", "a/b"),
        ("\\\\?\\C:\\x\\", "c:/x/"),
        ("//./C:/x", "c:/x"),
        ("a/../b/./c//d", "a/../b/c/d"),
        ("..././x", ".../x"),
        ("src/.", "src/."),
    ],
)
def test_a_path_is_matched_without_the_dots_spaces_and_device_prefix_windows_drops(path: str, normal: str) -> None:
    assert guard.normalise(path) == normal
