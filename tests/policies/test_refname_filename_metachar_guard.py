"""refname-filename-metachar: the command guard, and the git option reader it uses to find the names it creates."""

from __future__ import annotations

import pytest
from policies import guardkit

POLICY = "refname-filename-metachar"
guard = guardkit.load_guard(POLICY)
git = guardkit.load_guard(POLICY, "refname_git")
SHA = "5c9350738729a2cf1c40f5851628384751cae484"
BLOCK, OK = 1, 0

CASES = [
    # branch: create, rename, copy; listing, deleting and upstream changes create nothing.
    ("git branch 'a;b'", BLOCK),
    (f"git branch {SHA}", BLOCK),
    (f"git branch fix/pin {SHA}", OK),
    ("git branch -f -t 'x|y' origin/main", BLOCK),
    ("git branch -m 'x;y'", BLOCK),
    ("git branch -M old 'x;y'", BLOCK),
    ("git branch --copy old -- -x", BLOCK),
    ("git branch --mov old 'x&y'", BLOCK),
    ("git branch -m 'a;b' fine", OK),
    ("git branch -d 'a;b'", OK),
    ("git branch --del 'a;b'", OK),
    ("git branch -u origin/main 'a;b'", OK),
    ("git branch --set-upstream-to origin/x 'a;b'", OK),
    ("git branch --format '%(refname);' --contains HEAD", OK),
    ("git branch --co=x", OK),
    ("git branch", OK),
    # tag: the name is the first operand once message, file and key values are skipped.
    ("git tag -a -m 'release; notes' v1.0", OK),
    ("git tag -am 'notes' 'v1;x'", BLOCK),
    ("git tag -F msg.txt -s -- -v1", BLOCK),
    (f"git tag --message=ok {SHA}", BLOCK),
    ("git tag --local-user key 'v1|x'", BLOCK),
    ("git tag -l 'v1;*'", OK),
    ("git tag -d 'v1;x'", OK),
    ("git tag -n5", OK),
    # checkout, switch, worktree.
    ("git checkout -b 'x;y' origin/main", BLOCK),
    ("git checkout -B'x;y'", BLOCK),
    ("git checkout --orphan=gh;pages", OK),
    ("git checkout --orphan 'gh;pages'", BLOCK),
    ("git checkout -- 'a;b'", OK),
    ("git checkout main", OK),
    ("git switch -C '-x'", BLOCK),
    ("git switch --create=fix. main", BLOCK),
    ("git switch --force-create fix/ok", OK),
    ("git switch --c 'a;b'", OK),
    ("git switch -b", OK),
    ("git worktree add -B 'x;y' ../wt", BLOCK),
    ("git worktree add --reason why ../wt main", OK),
    ("git worktree list", OK),
    # push and fetch refspecs: the destination is the name created; a deletion creates nothing.
    ("git push origin 'HEAD:x;y'", BLOCK),
    (f"git push origin +main:refs/tags/{SHA}", BLOCK),
    ("git push origin 'x;y'", BLOCK),
    ("git push origin main:", OK),
    ("git push -o ci.skip origin main", OK),
    ("git push --delete origin 'x;y'", OK),
    ("git push origin :'x;y'", OK),
    ("git push", OK),
    ("git fetch origin 'main:x;y'", BLOCK),
    ("git fetch --depth 1 origin 'x;y'", OK),
    (f"git fetch origin {SHA}", OK),
    # update-ref, directly and on stdin.
    (f"git update-ref refs/heads/{SHA} HEAD", BLOCK),
    ("git update-ref -m why refs/heads/ok HEAD", OK),
    ("git update-ref -d 'refs/heads/x;y'", OK),
    (f"git update-ref --stdin <<'EOF'\ncreate refs/heads/{SHA} HEAD\nEOF", BLOCK),
    ("git update-ref --stdin <<'EOF'\nupdate refs/heads/ok HEAD\nverify\ndelete refs/heads/x;y\nEOF", OK),
    # Files: redirect targets, creators' operands, dd of=, git mv, PowerShell path values.
    ("echo x > 'a|b'", BLOCK),
    ("printf x >> out.log 2>&1", OK),
    ("touch 'name.'", BLOCK),
    ("mkdir -p 'build/-x'", BLOCK),
    ("cp -r src 'dst;x'", BLOCK),
    ("mv 'old;name' new", BLOCK),
    ("cp -t dest -- -rf", BLOCK),
    ("ln -s ../shared lib/shared", OK),
    ("dd if=/dev/zero 'of=x;y' bs=1", BLOCK),
    ("dd if=a of=b", OK),
    ("git mv a.txt 'b`id`.txt'", BLOCK),
    ("git add 'a;b'", OK),
    ("New-Item -ItemType File -Path 'a;b'", BLOCK),
    ("Rename-Item a.txt -NewName:'x;y'", BLOCK),
    ("Set-Content -Path notes.txt -Value 'a;b'", OK),
    ("cat 'a;b'", OK),
    ("rm -rf 'old;dir'", OK),
    # Substitution syntax counts when spelled literally; unquoted, the shell expands it.
    ('git checkout -b "x\\$(id)"', BLOCK),
    ("touch 'x${IFS}y'", BLOCK),
    ('touch "$HOME/x" "${OUT}/y"', OK),
    ('git checkout -b "feat/${TICKET}"', OK),
    ("bash -c \"git tag 'v1;x'\"", BLOCK),
]


@pytest.mark.parametrize(("command", "want"), CASES, ids=[c for c, _ in CASES])
def test_the_guard_verdict(command: str, want: int, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("CHOCK_RAW_COMMAND", command)
        patch.setenv("CHOCK_TOOL", "bash")
        code = guard.run(command.split())
    err = capsys.readouterr().err
    assert code == want, err
    assert err.startswith("BLOCKED: ") if want else err == ""


def test_powershell_text_is_read_as_powershell(capsys: pytest.CaptureFixture[str], monkeypatch) -> None:
    monkeypatch.setenv("CHOCK_RAW_COMMAND", "New-Item -Path C:\\work\\'a;b'")
    monkeypatch.delenv("CHOCK_TOOL", raising=False)
    assert guard.run([]) == BLOCK
    assert "a;b" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("args", "want"),
    [
        (["--crea", "x"], ({"--create"}, [], [("--create", "x")])),
        (["--c"], ({"--c"}, [], [])),
        (["-c"], ({"-c"}, [], [("-c", "")])),
        (["--create"], ({"--create"}, [], [("--create", "")])),
        (["--", "-x"], (set(), ["-x"], [])),
        (["-", "x"], (set(), ["-", "x"], [])),
    ],
)
def test_the_option_reader(args: list[str], want: tuple) -> None:
    assert git.parse(args, git.SWITCH) == want


def test_an_unknown_subcommand_creates_nothing() -> None:
    assert git.created_refs("log", ["--oneline", "'a;b'"], "") == []
