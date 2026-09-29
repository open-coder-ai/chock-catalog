"""chock_shellparse: which paths a command may write, and which removals reach a root or home path."""

from __future__ import annotations

import pytest
from policies import guardkit

POLICIES = guardkit.policies_with_shellparse()


@pytest.fixture(params=POLICIES, ids=POLICIES)
def sp(request: pytest.FixtureRequest):
    return guardkit.load_shellparse(request.param)


def one(sp, raw: str):
    found = sp.commands(raw)
    assert len(found) == 1, found
    return found[0]


@pytest.mark.parametrize(
    ("path", "dangerous"),
    [
        ("/", True),
        ("/etc", True),
        ("~", True),
        ("~/work", True),
        ("$HOME", True),
        ("${HOME}/x", True),
        (".", True),
        ("..", True),
        ("$env:USERPROFILE\\x", True),
        ("build", False),
        ("./build", False),
        ("a/b", False),
    ],
)
def test_dangerous_targets(sp, path: str, dangerous: bool) -> None:
    assert sp.is_dangerous_target(path) is dangerous


@pytest.mark.parametrize(
    ("raw", "hit"),
    [
        ("Remove-Item -Recurse C:\\", True),
        ("Remove-Item -Force -Recurse:$true /", True),
        ("Remove-Item -Rec ~/work", True),
        ("rd /s C:\\", True),
        ("Remove-Item -Recurse build", False),
        ("Remove-Item C:\\", False),
        ("del /q x", False),
    ],
)
def test_powershell_removal_of_a_root_or_home(sp, raw: str, hit: bool) -> None:
    cmd = one(sp, raw)
    assert cmd.name in sp.POWERSHELL_REMOVERS
    assert sp.removes_root_recursively(cmd) is hit


def writes(sp, raw: str) -> bool:
    return any(sp.writes_files(c, lambda p: "T" in p) for c in sp.commands(raw))


@pytest.mark.parametrize(
    "raw",
    [
        "echo x > T",
        "echo x >> T",
        "cat <<E > T\nx\nE",
        "tee T",
        "tee -a T",
        "rm T",
        "rm -f T",
        "mv a T",
        "mv T a",
        "touch T",
        "chmod +x T",
        "truncate -s0 T",
        "cp a T",
        "cp -r a T",
        "cp --target-directory=T a",
        "install -m0644 a T",
        "ln -s a T",
        "dd if=a of=T",
        "sed -i s/a/b/ T",
        "sed -ibak s/a/b/ T",
        "sed --in-place s/a/b/ T",
        "python3 -c \"open('T','w')\"",
        "perl -pi -e s/a/b/ T",
        "node -e \"require('fs').writeFileSync('T','')\"",
        "find . -name T -delete",
        "find T -exec rm {} ;",
        "git checkout HEAD~3 -- T",
        "git restore --source=HEAD T",
        "git rm T",
        "git mv a T",
        "Set-Content T x",
        "Set-Content -Path:T x",
        "Add-Content T x",
        "'x' | Out-File T",
        "New-Item T",
        "Remove-Item T",
        "Copy-Item a T",
        "Move-Item a T",
        "sc T x",
        "sudo bash -c 'echo x > T'",
        "cd x && echo y > T",
    ],
)
def test_a_command_that_writes_a_path_is_seen(sp, raw: str) -> None:
    assert writes(sp, raw), raw


@pytest.mark.parametrize(
    "raw",
    [
        "cat T",
        "grep x T",
        "cp T b",
        "cp T b c",
        "cp",
        "install T b",
        "ln -s T b",
        "dd if=T of=b",
        "sed s/a/b/ T",
        "sed -n p T",
        "python3 script.py T",
        "python3 -c 'print(1)'",
        "find T -name x",
        "find . -delete",
        "find T -exec cat {} ;",
        "git status T",
        "git diff T",
        "git checkout main",
        "echo T",
        "ls > other",
        "Get-Content T",
        "Copy-Item T b",
        "rmdir",
        "tee",
    ],
)
def test_a_command_that_only_reads_a_path_is_not_a_write(sp, raw: str) -> None:
    assert not writes(sp, raw), raw
