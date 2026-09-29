"""chock_shellparse: the command reader every Python command guard ships a copy of.

Each policy folder must stand alone (a plugin ships only that folder), so the package is copied, not
shared. Every test here runs against every copy, which is also what keeps each copy fully covered.
"""

from __future__ import annotations

import hashlib
import shlex
from pathlib import Path

import pytest
from policies import guardkit

POLICIES = guardkit.policies_with_shellparse()


@pytest.fixture(params=POLICIES, ids=POLICIES)
def sp(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CHOCK_TOOL", raising=False)
    return guardkit.load_shellparse(request.param)


def names(sp, raw: str) -> list[str]:
    return [c.name for c in sp.commands(raw)]


def one(sp, raw: str):
    found = sp.commands(raw)
    assert len(found) == 1, found
    return found[0]


def digest(policy: str) -> dict[str, str]:
    package = guardkit.impl_dir(policy) / guardkit.SHELLPARSE
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in package.glob("*.py")}


def test_every_copy_is_byte_identical() -> None:
    assert len(POLICIES) >= 9
    assert {policy: digest(policy) for policy in POLICIES}.keys() == set(POLICIES)
    assert len({tuple(sorted(digest(policy).items())) for policy in POLICIES}) == 1


def test_only_the_python_guards_ship_a_copy() -> None:
    base = Path(guardkit.ROOT) / "base"
    shipping = {p.name for p in base.iterdir() if (p / "implementations" / guardkit.SHELLPARSE).is_dir()}
    assert shipping == set(POLICIES)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a && b || c; d | e & f\ng", ["a", "b", "c", "d", "e", "f", "g"]),
        ("a |& b", ["a", "b"]),
        ("(cd x && make) ; ls", ["cd", "make", "ls"]),
        ("{ a; b; }", ["a", "b"]),
        ("echo `date`", ["echo", "date"]),
        ("git commit -m ';' --no-verify", ["git"]),
        ("ls # rm -rf /", ["ls"]),
        ("a \\\n b", ["a"]),
        ("", []),
        ("   ", []),
        (";;", []),
    ],
)
def test_a_command_line_splits_into_simple_commands(sp, raw: str, expected: list[str]) -> None:
    assert names(sp, raw) == expected


def test_quotes_and_escapes_are_removed_from_words(sp) -> None:
    cmd = one(sp, 'echo \'a b\' "c d" e\\ f "q\\"x" $\'g\'')
    assert cmd.args[:4] == ["a b", "c d", "e f", 'q"x']


def test_unbalanced_quotes_fall_back_to_a_whitespace_split(sp) -> None:
    assert names(sp, 'echo "oops; rm -rf /') == ["echo", "rm"]
    assert sp.commands("git commit --no-verify -m 'oops")[0].args == ["commit", "--no-verify", "-m", "oops"]


def test_the_fallback_still_sees_redirections_and_an_unclosed_quote_is_one_word(sp) -> None:
    found = sp.commands("echo x > AGENTS.md 'oops")
    assert (found[0].name, found[0].writes, found[0].args) == ("echo", ["AGENTS.md"], ["x", "oops"])
    assert sp.commands("echo hi>out 'oops")[0].writes == ["out"]
    assert sp.commands("echo hi>>out 'oops")[0].args == ["hi", "oops"]
    assert sp.commands("cat < in 'oops")[0].reads == ["in"]
    assert sp.commands("cat 2> err 'oops")[0].writes == ["err"]
    assert sp.commands("echo > ; echo 'oops")[0].writes == []
    assert names(sp, ";'oops") == ["oops"]
    assert names(sp, "> only 'oops") == ["oops"]
    assert sp.commands("git commit -m \"the user's request")[0].args == ["commit", "-m", "the user's request"]
    assert sp.commands("echo 'a b' \"unbalanced c")[0].args == ["a b", "unbalanced c"]
    assert sp.commands("echo C:\\")[0].args == ["C:\\"]


def test_redirections_are_kept_apart_from_the_arguments(sp) -> None:
    cmd = one(sp, "echo hi > out.txt 2>&1")
    assert (cmd.args, cmd.writes) == (["hi"], ["out.txt"])
    assert one(sp, "echo hi >> log").writes == ["log"]
    assert one(sp, "echo hi >| forced").writes == ["forced"]
    assert one(sp, "echo hi &> both").writes == ["both"]
    assert one(sp, "echo hi 2> err").writes == ["err"]
    assert one(sp, "cat < in.txt").reads == ["in.txt"]
    assert one(sp, "cat <<< 'word'").args == []
    assert names(sp, "> only.txt") == [""]
    assert sp.commands("> only.txt")[0].writes == ["only.txt"]


def test_a_heredoc_body_is_kept_and_not_run(sp) -> None:
    cmd = sp.commands("cat <<EOF > f\nrm -rf /\nEOF\nls")
    assert [c.name for c in cmd] == ["cat", "ls"]
    assert cmd[0].doc == "rm -rf /"
    assert cmd[0].writes == ["f"]


def test_a_dash_heredoc_strips_tabs_and_an_unterminated_one_runs_to_the_end(sp) -> None:
    assert sp.commands("cat <<-X\n\tbody\n\tX\nls")[0].doc == "\tbody"
    assert sp.commands("cat <<X\nbody\nno end")[0].doc == "body\nno end"
    assert [c.name for c in sp.commands("cat <<A <<B\none\nA\ntwo\nB\nls")] == ["cat", "ls"]


def test_assignments_before_a_command_are_its_environment(sp) -> None:
    cmd = one(sp, "A=1 B='x y' git status")
    assert cmd.env == {"A": "1", "B": "x y"}
    assert one(sp, "A=1; git status").env == {"A": "1"}
    assert one(sp, "env A=1 git status").env == {"A": "1"}
    assert one(sp, "export A=1 && git status").env == {"A": "1"}


@pytest.mark.parametrize(
    ("raw", "name", "args"),
    [
        ("sudo rm -rf x", "rm", ["-rf", "x"]),
        ("sudo -u root -H rm x", "rm", ["x"]),
        ("doas -u root rm x", "rm", ["x"]),
        ("env -u HOME -i rm x", "rm", ["x"]),
        ("env -- rm x", "rm", ["x"]),
        ("command rm x", "rm", ["x"]),
        ("exec -a name rm x", "rm", ["x"]),
        ("nohup rm x", "rm", ["x"]),
        ("timeout 5 rm x", "rm", ["x"]),
        ("timeout -s KILL 5 rm x", "rm", ["x"]),
        ("nice -n 5 rm x", "rm", ["x"]),
        ("time rm x", "rm", ["x"]),
        ("xargs -n1 rm", "rm", []),
        ("xargs -I{} rm {}", "rm", ["{}"]),
        ("/usr/bin/rm x", "rm", ["x"]),
        ("C:\\tools\\Git.exe status", "git", ["status"]),
        ("if true; then rm x; fi", "rm", ["x"]),
        ("! rm x", "rm", ["x"]),
    ],
)
def test_wrappers_are_looked_through(sp, raw: str, name: str, args: list[str]) -> None:
    found = [c for c in sp.commands(raw) if c.name == name]
    assert found and found[0].args == args


def test_command_v_only_looks_a_program_up(sp) -> None:
    assert names(sp, "command -v git") == []
    assert names(sp, "sudo") == []


@pytest.mark.parametrize(
    "raw",
    [
        "bash -c 'rm -rf /'",
        'sh -c "rm -rf /"',
        "zsh -lc 'rm -rf /'",
        "sudo bash -c 'rm -rf /'",
        "eval 'rm -rf /'",
        "eval rm -rf /",
        "pwsh -Command 'rm -rf /'",
        "powershell -c 'rm -rf /'",
        "cmd /c rm -rf /",
        'bash -c \'bash -c "bash -c \\"rm -rf /\\""\'',
    ],
)
def test_a_shell_c_script_is_read_as_the_commands_it_runs(sp, raw: str) -> None:
    assert [c.name for c in sp.commands(raw)] == ["rm"]


def test_a_script_carries_its_own_redirections_out(sp) -> None:
    found = sp.commands("bash -c 'echo hi' > out.txt")
    assert [c.name for c in found] == ["echo", ""]
    assert found[1].writes == ["out.txt"]


def test_nesting_stops_at_a_fixed_depth(sp) -> None:
    text = "rm x"
    for _ in range(6):
        text = "bash -c " + shlex.quote(text)
    assert sp.commands(text)[0].name == "bash"


def test_the_environment_is_visible_inside_a_script(sp) -> None:
    assert one(sp, "A=1 bash -c 'git status'").env == {"A": "1"}


def test_powershell_is_named_by_the_engine_or_read_from_the_text(sp, monkeypatch: pytest.MonkeyPatch) -> None:
    assert sp.is_powershell("Set-Content a b") is True
    assert sp.is_powershell("ls -Recurse") is True
    assert sp.is_powershell("echo $env:HOME") is True
    assert sp.is_powershell("ls -la") is False
    monkeypatch.setenv("CHOCK_TOOL", "powershell")
    assert sp.is_powershell("ls") is True
    monkeypatch.setenv("CHOCK_TOOL", "PWSH")
    assert sp.is_powershell("ls") is True
    monkeypatch.setenv("CHOCK_TOOL", "bash")
    assert sp.is_powershell("Set-Content a b") is False
    monkeypatch.setenv("CHOCK_TOOL", "unknown")
    assert sp.is_powershell("Set-Content a b") is True
    assert sp.is_powershell("ls") is False


def test_powershell_paths_and_backticks_are_normalised(sp) -> None:
    cmd = one(sp, "Set-Content .github\\workflows\\ci.yml 'x'")
    assert (cmd.name, cmd.args) == ("set-content", [".github/workflows/ci.yml", "x"])
    assert one(sp, "Remove-`Item C:\\x -Recurse").name == "remove-item"


def test_a_windows_path_is_also_read_with_forward_slashes(sp) -> None:
    assert {c.args[0] for c in sp.commands("cat .claude\\settings.json")} == {
        ".claudesettings.json",
        ".claude/settings.json",
    }


def test_git_parts_finds_the_subcommand_past_the_global_options(sp) -> None:
    assert sp.git_parts(["status"]) == ("status", [], [])
    assert sp.git_parts(["-C", "dir", "commit", "-m", "x"]) == ("commit", [], ["-m", "x"])
    assert sp.git_parts(["-c", "a=b", "--config-env=k=V", "--config-env", "j=W", "-p", "push", "-f"]) == (
        "push",
        ["a=b", "k=V", "j=W"],
        ["-f"],
    )
    assert sp.git_parts(["--git-dir=x", "log"]) == ("log", [], [])
    assert sp.git_parts(["--work-tree", "w", "-c"]) == ("", [], [])
    assert sp.git_parts(["-c", "a=b"]) == ("", ["a=b"], [])
    assert sp.git_parts([]) == ("", [], [])


def test_argument_helpers(sp) -> None:
    assert sp.flags_of(["-rf", "--force=1", "x", "-"]) == {"-r", "-f", "--force"}
    assert sp.operands(["-a", "b", "--c", "d"]) == ["b", "d"]
    assert sp.positionals(["--ctx", "prod", "-x", "uninstall", "web"], frozenset({"--ctx"})) == ["uninstall", "web"]
    assert sp.after(["s3", "rm"], "s3") == "rm"
    assert sp.after(["s3"], "s3") == ""
    assert sp.after(["a"], "s3") == ""
    assert sp.abbreviates("--h", "--hard", 4) is False
    assert sp.abbreviates("--har", "--hard", 5) is True
    assert sp.abbreviates("--hard", "--hard", 5) is True
    assert sp.abbreviates("--hxr", "--hard", 5) is False
