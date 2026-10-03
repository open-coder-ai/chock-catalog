"""protect-agent-config: fourth review round -- children of protected folders, mktemp variables, find -exec bodies."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guard_cases_fourth as fourth
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
subst = guardkit.load_guard(POLICY, "pathsubst")

REFUSED = [*fourth.CHILD_REFUSED, *fourth.MKTEMP_REBOUND_REFUSED, *fourth.FIND_REFUSED]
ALLOWED = [*fourth.CHILD_ALLOWED, *fourth.MKTEMP_REBOUND_ALLOWED, *fourth.FIND_ALLOWED]


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in (".git", ".git/hooks", ".claude", ".cursor", ".chock", ".github", "src", "docs"):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


@pytest.mark.parametrize("raw", REFUSED)
def test_a_form_the_fourth_review_found_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize("raw", ALLOWED)
def test_its_ordinary_twin_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize(
    ("body", "printed"),
    [
        ("echo .git/hooks", ".git/hooks"),
        ("echo 'a/b'", "a/b"),
        ('echo "a/b"', "a/b"),
        ("  pwd ", "$PWD"),
        ("git rev-parse --git-dir", "/srv/r/.git"),
        ("git rev-parse --git-common-dir", "/srv/r/.git"),
        ("git rev-parse --absolute-git-dir", "/srv/r/.git"),
        ("git rev-parse --show-toplevel", "/srv/r"),
        ("git rev-parse --git-path hooks", "/srv/r/.git/hooks"),
        ("echo -n x", None),
        ("echo a b", None),
        ("git rev-parse HEAD", None),
        ("git rev-parse --git-path $X", None),
        ("date", None),
    ],
)
def test_a_substitution_the_line_shows_is_read(body: str, printed: str | None) -> None:
    assert subst.resolver("/srv/r")(body) == printed


def test_a_repository_path_the_guard_cannot_write_into_text_is_left_unknown() -> None:
    read = subst.resolver("/srv/my repo")
    assert read("git rev-parse --git-dir") is None
    assert read("echo a") == "a"
    assert read("pwd") == "$PWD"


@pytest.mark.parametrize(
    ("name", "text", "rebound"),
    [
        ("x", "x=$(mktemp); echo y > $x", False),
        ("x", "x=$(mktemp); echo ${x}", False),
        ("x", "x=$(mktemp); rm -f $x", False),
        ("x", "x=$(mktemp); read x", True),
        ("x", "x=$(mktemp); printf -vx a", True),
        ("x", "x=$(mktemp); echo ${x:=a}", True),
        ("x", "x=$(mktemp); x=$(mktemp)", True),
        ("x", "echo y > $x", True),
        ("x", "x=$(mktemp); ls -x", False),
        ("x", "x=$(mktemp); cp a.x b", False),
        ("x", "x=$(mktemp); echo $xy", False),
    ],
)
def test_a_mktemp_variable_stays_fresh_only_while_nothing_else_names_it(name: str, text: str, rebound: bool) -> None:
    assert subst.bindings(text).rebound(name) is rebound


def test_dollar_pwd_follows_the_directory_it_was_read_in(_repo_root: Path) -> None:
    assert guard.check("cd src; H=$PWD/build; echo x > $H/out.txt") is None
    assert guard.check("cd src; H=$PWD/../.git/hooks; echo x > $H/pre-commit") == guard.REASON
    assert guard.check("cd .git && echo x > $PWD/hooks/pre-commit") == guard.REASON
    assert guard.check("cd src && echo x > ${PWD}/out.txt") is None
    assert guard.check("PWD=/srv/o; echo x > $PWD/pre-commit") is None
