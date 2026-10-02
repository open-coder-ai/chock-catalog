"""block-no-verify v2: hook managers' off switches, more subcommands, aliases, nested scripts, plumbing asks, fail-closed fallback."""

from __future__ import annotations

import shlex

import pytest
from policies import guardkit

BLOCK, ASK, OK = 1, 3, 0
GUARD = guardkit.load_guard("block-no-verify")

ROWS: list[tuple[str, int]] = [
    # the hook-skip long option on every subcommand that takes it, with git's unambiguous prefixes
    ("git cherry-pick --no-verify abc123", BLOCK),
    ("git revert --no-verif HEAD", BLOCK),
    ("git pull --no-verify origin main", BLOCK),
    ("git pull --no-veri", BLOCK),
    ("git pull -n origin main", OK),  # --no-stat
    ("git cherry-pick -n abc123", OK),  # --no-commit
    ("git revert -n HEAD", OK),
    ("git commit -anm wip", BLOCK),
    ("git am -3n fix.patch", BLOCK),
    # hook managers switched off from the environment of a hook-running command
    ("HUSKY=0 git commit -m x", BLOCK),
    ("HUSKY=false git push", BLOCK),
    ("HUSKY='$off' git push", BLOCK),
    ("HUSKY_SKIP_HOOKS=1 git commit -m x", BLOCK),
    ("SKIP=flake8,mypy git commit -m x", BLOCK),
    ("LEFTHOOK=0 git push origin main", BLOCK),
    ("LEFTHOOK_EXCLUDE=lint git commit -m x", BLOCK),
    ("PRE_COMMIT_ALLOW_NO_CONFIG=1 git commit -m x", BLOCK),
    ("env HUSKY=0 git commit -m x", BLOCK),
    ("cd app && HUSKY=0 git merge topic", BLOCK),
    ("bash -c 'SKIP=ruff git commit -m x'", BLOCK),
    ("sudo -u ci env LEFTHOOK=0 git push", BLOCK),
    ("HUSKY=1 git commit -m x", OK),
    ("LEFTHOOK=true git push", OK),
    ("SKIP= git commit -m x", OK),
    ("HUSKY=0 npm ci", OK),  # the documented way to skip husky's install step, not a hook run
    ("SKIP=lint make test", OK),
    ("git commit -m 'HUSKY=0 is how CI skips install'", OK),
    # ... or left set for the commands that follow
    ("export HUSKY=0", BLOCK),
    ("export SKIP=mypy; git commit -m x", BLOCK),
    ("HUSKY=0; export HUSKY", BLOCK),
    ("declare -x LEFTHOOK=0", BLOCK),
    ("set -gx HUSKY 0", BLOCK),
    ("setx HUSKY 0", BLOCK),
    ("$env:HUSKY = '0'", BLOCK),
    ("$env:SKIP='mypy'; git commit -m x", BLOCK),
    ("Set-Item Env:LEFTHOOK 0", BLOCK),
    ("eval 'export HUSKY=0'", BLOCK),
    ("export HUSKY=1", OK),
    ("echo $HUSKY", OK),
    ("husky=0 git commit -m x", OK),  # POSIX names are case-sensitive: husky reads HUSKY
    # hook managers removing their own hooks
    ("pre-commit uninstall", BLOCK),
    ("pre-commit uninstall -t pre-push", BLOCK),
    ("python3 -m pre_commit uninstall", BLOCK),
    ("python3.12 -m pre_commit uninstall", BLOCK),
    ("uvx pre-commit uninstall", BLOCK),
    ("pipx run pre-commit uninstall", BLOCK),
    ("lefthook uninstall", BLOCK),
    ("npx lefthook uninstall --keep-config", BLOCK),
    ("npx @evilmartians/lefthook uninstall", BLOCK),
    ("pnpm exec husky uninstall", BLOCK),
    ("yarn husky uninstall", BLOCK),
    ("./node_modules/.bin/husky uninstall", BLOCK),
    ("npx husky@4 uninstall", BLOCK),
    ("pre-commit install", OK),
    ("pre-commit run --all-files", OK),
    ("pre-commit run --files uninstall.py", OK),
    ("lefthook run pre-commit", OK),
    ("npm uninstall left-pad", OK),
    ("pip uninstall -y requests", OK),
    ("npx --version", OK),
    ("echo pre-commit uninstall", OK),
    # core.hooksPath in every git config syntax
    ("git config set core.hooksPath /dev/null", BLOCK),
    ("git config --type path core.hooksPath /x", BLOCK),
    ("git config --file .git/config core.hooksPath ''", BLOCK),
    ("git config --replace-all core.hooksPath .hooks", BLOCK),
    ("git config get core.hooksPath", OK),
    ("git config unset core.hooksPath", ASK),
    ("git config --unset core.hooksPath", ASK),
    ("git config --list", OK),
    ("git -c core.hooksPath=/dev/null cherry-pick abc", BLOCK),
    ("git -c core.hooksPath=/dev/null pull", BLOCK),
    # an alias defined here is read for what it runs
    ("git -c alias.ci='commit --no-verify' ci -m x", BLOCK),
    ("git -c 'alias.ci=!git commit -n' ci -m x", BLOCK),
    ("git config alias.ci 'commit --no-verify'", BLOCK),
    ("git config --global alias.p '!HUSKY=0 git push'", BLOCK),
    ("git config set alias.up '!f() { git push --no-verify; }; f'", BLOCK),
    ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.c GIT_CONFIG_VALUE_0='commit -n' git c", BLOCK),
    ("GIT_CONFIG_PARAMETERS=\"'alias.c'='commit --no-verify'\" git c", BLOCK),
    ("A='!git commit --no-verify' git --config-env=alias.c=A c", BLOCK),
    ("git config alias.co checkout", OK),
    ("git config alias.st 'status -sb'", OK),
    ("git -c alias.lg='log --oneline' lg", OK),
    ("git config --get alias.ci", OK),
    # scripts git runs itself
    ("git rebase -x 'git commit --amend --no-edit --no-verify' main", BLOCK),
    ("git rebase --exec='HUSKY=0 git commit --amend --no-edit' main", BLOCK),
    ("git rebase '-xgit commit -n --amend' main", BLOCK),
    ("git submodule foreach --recursive 'git commit -n -m x'", BLOCK),
    ("git rebase -x 'make test' main", OK),
    ("git submodule foreach git pull", OK),
    ("git submodule foreach", OK),
    ("git submodule update --init", OK),
    # plumbing that writes commits or refs with no hook, another repository, a config file from elsewhere: ask
    ("git commit-tree HEAD^{tree} -p HEAD -m wip", ASK),
    ("git update-ref refs/heads/main $(git commit-tree HEAD^{tree} -m x)", ASK),
    ("git update-ref refs/heads/topic abc123", ASK),
    ("git fast-import < dump", ASK),
    ("git update-ref -d refs/heads/old", OK),
    ("git hash-object -w file.txt", OK),
    ("git rev-parse HEAD", OK),
    ("GIT_DIR=/tmp/other.git GIT_WORK_TREE=. git commit -m x", ASK),
    ("git --git-dir=/tmp/other.git push origin main", ASK),
    ("git --git-dir /tmp/other.git commit -m x", ASK),
    ("GIT_COMMON_DIR=/tmp/c git commit -m x", ASK),
    ("export GIT_DIR=/tmp/o.git; git push", ASK),
    ("GIT_DIR=.git git commit -m x", OK),
    ("git --git-dir=./.git/ commit -m x", OK),
    ("GIT_DIR=/tmp/other.git git log", OK),
    ("git -C ../other commit -m x", OK),  # that repository's own hooks run
    ("GIT_CONFIG_GLOBAL=/tmp/g git push", ASK),
    ("GIT_CONFIG_SYSTEM=/tmp/s git commit -m x", ASK),
    ("git -c include.path=/tmp/x commit -m x", ASK),
    ("git -c includeIf.onbranch:main.path=/tmp/x push", ASK),
    ("git config include.path /tmp/x", ASK),
    ("git config --global includeIf.gitdir:~/w/.path /tmp/x", ASK),
    ("git config --get include.path", OK),
    ("GIT_CONFIG_GLOBAL=/tmp/g git log", OK),
    # a block outranks an ask on the same line
    ("git --git-dir=/tmp/o.git commit --no-verify", BLOCK),
    ("git commit-tree HEAD^{tree} -m x; HUSKY=0 git push", BLOCK),
]


def verdict(
    command: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], **env: str
) -> tuple[int, str]:
    monkeypatch.setenv("CHOCK_RAW_COMMAND", command)
    monkeypatch.delenv("CHOCK_TOOL", raising=False)
    monkeypatch.delenv("CHOCK_ARGV_FALLBACK", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()
    return GUARD.run(argv), capsys.readouterr().err


@pytest.mark.parametrize(("command", "want"), ROWS, ids=[c[:70] for c, _ in ROWS])
def test_the_guard_gives_the_verdict(
    command: str, want: int, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, err = verdict(command, monkeypatch, capsys)
    assert code == want, f"{command!r} gave {code}, wanted {want}; stderr={err!r}"
    if want == OK:
        assert err == ""
    else:
        assert err.strip()
        assert err.startswith("BLOCKED: ") == (want == BLOCK)


@pytest.mark.parametrize(
    "command",
    [
        'git commit -m "it\'s done" --no-verify',
        "HUSKY=0 git commit -m 'oops",
        "git config core.hooksPath /dev/null 'x",
        "pre-commit uninstall \\",
        "git -c alias.c='commit --no-verify c",
        'git rebase --exec "git commit -n main',
    ],
)
def test_an_unparsed_line_naming_a_bypass_fails_closed(
    command: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """CHOCK_ARGV_FALLBACK=1 says shlex could not split the line; whatever the lexer recovers, a named bypass is refused."""
    code, err = verdict(command, monkeypatch, capsys, CHOCK_ARGV_FALLBACK="1")
    assert code == BLOCK
    assert err.startswith("BLOCKED: ")


@pytest.mark.parametrize("command", ["echo \"it's fine", "git commit -m \"it's fine", "ls 'a b"])
def test_an_unparsed_line_with_no_bypass_is_allowed(
    command: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert verdict(command, monkeypatch, capsys, CHOCK_ARGV_FALLBACK="1") == (OK, "")


def test_without_the_fallback_flag_quoted_text_stays_data(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert verdict("git commit -m 'HUSKY=0 and core.hooksPath'", monkeypatch, capsys) == (OK, "")


def test_an_ask_prints_the_prompt_first(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    code, err = verdict("git commit-tree HEAD^{tree} -m x", monkeypatch, capsys)
    assert code == ASK
    assert err.splitlines()[0].startswith("git commit-tree writes commits or refs without running any hook")


def test_aliases_nested_past_the_depth_are_asked_about(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An alias that defines an alias that defines an alias... is not read forever; past the depth a person decides."""
    inner = "git status"
    for _ in range(5):
        inner = f"git -c {shlex.quote('alias.a=!' + inner)} a"
    code, err = verdict(inner, monkeypatch, capsys)
    assert code == ASK
    assert "too deeply" in err


def test_an_unparsed_line_fails_closed_without_the_flag_too(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The eval runner and older adapters do not set CHOCK_ARGV_FALLBACK; the guard sees the failed split itself."""
    code, _ = verdict(
        "git commit -m it's --no-verify", monkeypatch, capsys
    )  # the lexer reads "s --no-verify" as one word
    assert code == BLOCK


def test_the_flag_alone_marks_a_line_unparsed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A balanced line the adapter still flagged (its own split failed) is read the fail-closed way."""
    code, _ = verdict("git commit -m 'core.hooksPath is documented'", monkeypatch, capsys, CHOCK_ARGV_FALLBACK="1")
    assert code == BLOCK
