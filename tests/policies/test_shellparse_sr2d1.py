"""chock_shellparse: arithmetic shifts are not here-documents, env -S runs its string, env -i is recorded, shell options before a script."""

from __future__ import annotations

import pytest
from policies import guardkit

POLICIES = guardkit.policies_with_shellparse()
SEEN = "rm -rf build"


@pytest.fixture(params=POLICIES, ids=POLICIES)
def sp(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CHOCK_TOOL", raising=False)
    return guardkit.load_shellparse(request.param)


def names(sp, raw: str) -> list[str]:
    return [c.name for c in sp.commands(raw)]


@pytest.mark.parametrize(
    "first",
    [
        "echo $((1<<2))",
        "echo $(( 1 <<2 ))",
        "echo $(( (1<<2) + (3<<1) ))",
        "x=$((1<<2))",
        ": ; (( 1<<2 ))",
        "(( x <<= 1 ))",
        "echo ok && (( n = 1<<3 ))",
        "for ((i=1<<2; i<9; i++)); do :; done",
        "if ((1<<2)); then :; fi",
        "echo $[1<<2]",
        "echo $[ 2 <<3 ]",
    ],
)
def test_an_arithmetic_shift_is_not_a_here_document(sp, first: str) -> None:
    assert "rm" in names(sp, f"{first}\n{SEEN}")


def test_a_real_here_document_still_hides_its_body(sp) -> None:
    assert names(sp, f"cat <<EOF\n{SEEN}\nEOF\nls") == ["cat", "ls"]
    assert names(sp, f"echo $((1<<2)); cat <<EOF\n{SEEN}\nEOF\nls")[-2:] == ["cat", "ls"]
    assert "rm" not in names(sp, f"echo $((1<<2)); cat <<-EOF\n\t{SEEN}\n\tEOF\nls")


@pytest.mark.parametrize(
    ("raw", "name", "args"),
    [
        ("env -S 'cat .env'", "cat", [".env"]),
        ("env -S'cat .env'", "cat", [".env"]),
        ("env --split-string='cat .aws/credentials'", "cat", [".aws/credentials"]),
        ("env --split-string 'cat .aws/credentials'", "cat", [".aws/credentials"]),
        ('env --split="cat .npmrc"', "cat", [".npmrc"]),
        ("env -S cat .env", "cat", [".env"]),
        ("env -i -S 'gh auth token'", "gh", ["auth", "token"]),
        ("env -iS 'gh auth token'", "gh", ["auth", "token"]),
        ("env -S 'FOO=1 cat .env'", "cat", [".env"]),
        ("env -S '-i cat .env'", "cat", [".env"]),
        ("sudo env -S 'cat .env'", "cat", [".env"]),
        ("env -S 'sh -c \"cat .env\"'", "cat", [".env"]),
        ("env -u HOME cat .env", "cat", [".env"]),
    ],
)
def test_env_split_string_is_the_command_env_runs(sp, raw: str, name: str, args: list[str]) -> None:
    found = sp.commands(raw)
    assert [(c.name, c.args) for c in found] == [(name, args)]


@pytest.mark.parametrize(
    "raw",
    [
        "env -i git commit -m x",
        "/usr/bin/env -i PATH=/usr/bin git commit -m x",
        "'env' -i git commit -m x",
        "env --ignore-environment git commit -m x",
        "env --ignore-env git commit -m x",
        "env - git commit -m x",
        "env -0i git commit -m x",
        "env -u HOME -i git commit -m x",
        "env -S '-i git commit -m x'",
    ],
)
def test_env_i_marks_the_command_it_runs(sp, raw: str) -> None:
    (cmd,) = sp.commands(raw)
    assert cmd.name == "git"
    assert cmd.env["CHOCK_ENV_WIPED"] == "1"


@pytest.mark.parametrize(
    "raw",
    [
        "env git commit -m x",
        "env -u HOME git commit -m x",
        "env -ui git commit -m x",
        "env -i",
        "git commit -m 'env -i'",
    ],
)
def test_env_without_a_wipe_is_not_marked(sp, raw: str) -> None:
    assert all("CHOCK_ENV_WIPED" not in c.env for c in sp.commands(raw))


@pytest.mark.parametrize(
    "raw",
    [
        "bash -c -- 'claude mcp add x'",
        "eval -- 'claude mcp add x'",
        "sh -c -e 'claude mcp add x'",
        "bash -ec -- 'claude mcp add x'",
    ],
)
def test_options_and_a_double_dash_before_a_script_are_skipped(sp, raw: str) -> None:
    assert names(sp, raw) == ["claude"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("env -S", []),
        ("env --split-string", []),
        ("env -S ''", []),
        ("env --split-st 'ls -l'", ["ls"]),
        ("env --sp 'rm -rf x'", ["rm"]),
        ("env --s 'rm -rf x'", ["rm -rf x"]),
        ("env -- ls", ["ls"]),
        ("env -u -S ls", ["ls"]),
        ("env -uS ls", ["ls"]),
        ("env --ignore-signal=INT ls", ["ls"]),
        ("time - ls", ["-"]),
    ],
)
def test_env_options_that_name_no_string_or_a_different_option(sp, raw: str, expected: list[str]) -> None:
    assert names(sp, raw) == expected


@pytest.mark.parametrize(
    ("raw", "target"),
    [
        ("echo '$[' > target.txt", "target.txt"),
        ('echo "$[" > target.txt', "target.txt"),
        ("echo x$[ > target.txt", "target.txt"),
        ("echo $(( 1 ) > target.txt", "target.txt"),
        ("echo $((1<<2)) > target.txt", "target.txt"),
        ("echo $[1<<2] >> target.txt", "target.txt"),
        ("(( x > 1 )); echo y > target.txt", "target.txt"),
        ("echo $((1<<2)) < target.txt", "target.txt"),
        ("echo $((1<<2)) 2>&1 > target.txt", "target.txt"),
    ],
)
def test_arithmetic_skips_only_the_here_document_openers(sp, raw: str, target: str) -> None:
    written = [path for cmd in sp.commands(raw) for path in (*cmd.writes, *cmd.reads)]
    assert target in written


def test_a_here_document_after_arithmetic_keeps_its_body(sp) -> None:
    found = names(sp, f"echo $((1<<2)); cat <<EOF\n{SEEN}\nEOF\nls")
    assert found == ["echo", "cat", "ls"] or found[-2:] == ["cat", "ls"]
    assert "rm" not in found
