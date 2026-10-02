"""block-secret-store-reads: the table loader, the path resolver and the misses its text admits to.

The verdict tables are in guard_cases_files.py and the eval suite; these tests hold the parts a verdict
cannot show: what a broken table does, how paths resolve, and that every probed miss is still a miss and is
named in the policy text, so a fix that closes one has to drop it from the text.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from policies import guardkit
from trees import ROOT

POLICY = "block-secret-store-reads"
IMPL = ROOT / "base" / POLICY / "implementations"
paths = guardkit.load_guard(POLICY, "secret_paths")
GUARD = guardkit.load_guard(POLICY)
TABLE = paths.load()
ENV: dict[str, str] = {}


def text() -> str:
    """The description and the changelog: where the policy admits what it misses."""
    manifest = yaml.safe_load((ROOT / "base" / POLICY / "manifest.yaml").read_text(encoding="utf-8"))
    log = " ".join(c for e in manifest["changelog"] for c in e["changes"])
    return re.sub(r"\s+", " ", manifest["description"] + " " + log[log.index("Known misses") :])


def exit_code(command: str) -> int:
    env = {**os.environ, "CHOCK_RAW_COMMAND": command}
    env.pop("CHOCK_TOOL", None)
    done = subprocess.run(
        [sys.executable, str(IMPL / f"{POLICY}.py"), *command.split()], env=env, capture_output=True, check=False
    )
    return done.returncode


def table_with(tmp_path: Path, **changes: object) -> Path:
    doc = json.loads((IMPL / "data" / "secret_stores.json").read_text(encoding="utf-8"))
    doc.update(changes)
    folder = tmp_path / "data"
    folder.mkdir(exist_ok=True)
    path = folder / "t.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_the_shipped_table_loads_and_names_the_stores_the_roadmap_lists() -> None:
    labels = " ".join(entry.label for entry in TABLE.home)
    for store in (
        "~/.ssh",
        "~/.aws",
        "~/.config/gh",
        "~/.npmrc",
        "~/.pypirc",
        "~/.netrc",
        "~/.kube/config",
        "~/.gnupg",
    ):
        assert store in labels
    assert TABLE.templates == (".example", ".sample", ".template", ".dist")


def test_a_table_with_a_bad_reader_mode_action_or_relative_setting_is_refused(tmp_path: Path) -> None:
    home = [{"id": "x", "label": "x", "paths": [".x"], "action": "maybe", "relative": "sometimes"}]
    path = table_with(tmp_path, home=home, readers={"cat": "slurp"})
    with pytest.raises(paths.data_table.TableError) as caught:
        paths.load(path)
    problems = " ".join(caught.value.problems)
    assert "unknown reader mode 'slurp'" in problems
    assert "x: action must be block or ask" in problems
    assert "x: relative must be always, code or never" in problems


def test_a_table_missing_a_key_is_refused(tmp_path: Path) -> None:
    path = table_with(tmp_path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    del doc["printers"]
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(paths.data_table.TableError):
        paths.load(path)


def test_a_broken_table_is_a_guard_fault_not_a_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = table_with(tmp_path, readers={"cat": "slurp"})
    original = GUARD.store.load
    monkeypatch.setattr(GUARD.store, "load", lambda: original(bad))
    monkeypatch.setenv("CHOCK_RAW_COMMAND", "cat ~/.npmrc")
    assert GUARD.run(["cat"]) == 2
    assert "internal error (TableError)" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("path", "want"),
    [
        ("~/.ssh/id_rsa", ("~", ".ssh", "id_rsa")),
        ("$HOME/.ssh", ("~", ".ssh")),
        ("${HOME}/a/../.ssh", ("~", ".ssh")),
        ("/home/bob/.aws/", ("~", ".aws")),
        ("/Users/bob/x", ("~", "x")),
        ("/root", ("~",)),
        ("/home", ("/", "home")),
        ("/", ("/",)),
        ("C:\\Users\\bob\\.ssh", ("~", ".ssh")),
        ("/mnt/c/Users/bob/.ssh", ("~", ".ssh")),
        ("/etc/../etc/hosts", ("/", "etc", "hosts")),
        ("/../etc", ("/", "etc")),
        ("a/./b//c", ("a", "b", "c")),
        ("../../x", ("..", "..", "x")),
        ("a/../..", ("..",)),
        ("~root/.ssh", ("~", ".ssh")),
        ("$XDG_CONFIG_HOME/gh", ("~", ".config", "gh")),
        ("~/../bob/.ssh", ("~", ".ssh")),
    ],
)
def test_a_path_resolves_to_its_components(path: str, want: tuple[str, ...]) -> None:
    assert paths.resolve(path, ENV) == want


def test_a_relative_path_resolves_against_the_working_directory_the_shell_would_have() -> None:
    assert paths.resolve("id_rsa", ENV, ("~", ".ssh")) == ("~", ".ssh", "id_rsa")
    assert paths.resolve("../.aws", ENV, ("~", ".ssh")) == ("~", ".aws")
    assert paths.resolve("x", ENV, ("/", "srv")) == ("/", "srv", "x")
    assert paths.resolve("x", ENV, ("a", "b")) == ("a", "b", "x")
    assert paths.resolve("/abs", ENV, ("~", ".ssh")) == ("/", "abs")


def test_variables_the_parser_saw_assigned_are_expanded_but_home_is_not_overridden() -> None:
    assert paths.resolve("$D/x", {"D": "~/.ssh"}) == ("~", ".ssh", "x")
    assert paths.resolve("${D}/x", {"D": "/srv"}) == ("/", "srv", "x")
    assert paths.resolve("$HOME/x", {"HOME": "/srv"}) == ("~", "x")
    assert paths.resolve("$A/x", {"A": "$A"}) == ("$A", "x")


def test_braces_expand_and_a_huge_list_is_none() -> None:
    assert sorted(paths.braces("~/.{ssh,aws}/{a,b}")) == ["~/.aws/a", "~/.aws/b", "~/.ssh/a", "~/.ssh/b"]
    assert paths.braces("plain") == ["plain"]
    assert paths.braces("{}") == ["{}"]
    assert paths.braces("{a,b}" * 11) is None


@pytest.mark.parametrize(
    ("op", "store", "want"),
    [
        (".ssh", ".ssh", True),
        (".ss*", ".ssh", True),
        (".s*", ".ssh", True),
        (".*", ".ssh", False),
        ("*", ".ssh", False),
        ("*", "login data", False),
        (".claude.json", ".claude*", True),
        (".claude*", ".claude*", True),
        ("*.tfstate", "*.tfstate", True),
        ("*", "x.tfstate", False),
    ],
)
def test_a_glob_matches_a_store_only_when_it_keeps_three_literal_characters(op: str, store: str, want: bool) -> None:
    assert paths.comp_match(op, store) is want


def test_the_literal_floor_can_be_lowered_for_a_directory_slot() -> None:
    assert paths.comp_match("*", "google-chrome", 0) is True


def test_scan_text_reads_code_for_stores_and_leaves_ordinary_code_alone() -> None:
    scan = lambda code, *, strict=False: paths.scan_text(code, ENV, TABLE, strict=strict)  # noqa: E731
    assert scan("open('/home/u/.ssh/id_rsa')")
    assert scan("join(home, '.npmrc')")
    assert scan("x = '/.npmrc'")
    assert scan("read('/proc/self/environ')")
    assert scan("print(1)") is None
    assert scan("fs.readFileSync('/usr/bin/env')") is None
    assert scan("cat ~/.npmrc", strict=True)
    assert scan("join(home, '.npmrc')", strict=True) is None
    assert scan("jq .env", strict=True) is None


# Each probed miss: the command, and the words the policy text uses to admit it.
MISSES = {
    "a script file that reads the store": ("python3 steal.py", "scripts"),
    "a variable the parser never saw assigned": ("cat $UNSET/.npmrc", "unresolved variables"),
    "a list piped in for xargs": ("xargs cat < list", "xargs"),
    "find piped into xargs": ("find ~/.ssh -type f | xargs cat", "xargs"),
    "a command substitution": ("cat $(echo ~/.npmrc)", "$(...)"),
    "a backtick substitution": ("cat `echo ~/.npmrc`", "$(...)"),
    "a project-level npm file": ("cat .npmrc", "project .npmrc"),
    "a relative store name after a cd it cannot resolve": ("cd $WORK/keys && cat credentials", "cd it cannot resolve"),
    "an editor": ("vim ~/.npmrc", "editors"),
    "git showing a tracked store": ("git show HEAD:.env", "git show"),
    "a command in the command position held in a variable": ("a=cat; $a ~/.aws/credentials", "command-position"),
    "a script piped into a shell": ("echo 'cat ~/.ssh/id_rsa' | sh", "pipe to a shell"),
    "a wrapper the parser does not know": ("strace cat ~/.aws/credentials", "other wrappers"),
    "a recursive search of the project directory": ("grep -rl KEY .", "recursive search of the project"),
    "an interpreter dumping the environment": ("python3 -c 'import os; print(os.environ)'", "environment"),
    "a token printer outside the table": ("op read op://vault/item/field", "other token printers"),
    "kubectl printing a secret": ("kubectl get secret db -o yaml", "other token printers"),
    "a here-string fed to a shell": ("bash <<< 'cat ~/.npmrc'", "here-string"),
}


@pytest.mark.parametrize("name", sorted(MISSES))
def test_a_probed_miss_is_still_a_miss_and_the_policy_text_admits_it(name: str) -> None:
    command, words = MISSES[name]
    assert exit_code(command) == 0, f"{command!r} is now caught: drop the miss from the policy text and this table"
    assert words in text(), f"the policy text must admit: {words}"


def test_every_refusal_names_what_to_do_instead(capsys: pytest.CaptureFixture[str]) -> None:
    for command in ("cat ~/.npmrc", "gh auth token", "env"):
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("CHOCK_RAW_COMMAND", command)
            code = GUARD.run(command.split())
        err = capsys.readouterr().err
        assert code in (1, 3)
        assert "person" in err or "variable you need" in err


def test_the_table_is_read_from_the_copy_beside_the_guard() -> None:
    assert paths.TABLE == IMPL / "data" / "secret_stores.json"
    assert shutil.which("python3") or shutil.which("python")


def test_a_missing_shared_module_is_a_fault_not_a_block() -> None:
    """The imports sit outside run(): a broken copy must still exit 2 and say the command was not checked."""
    runner = (
        "import runpy, sys; sys.modules['secret_readers'] = None; sys.argv = ['g', 'cat', '~/.npmrc']; "
        f"runpy.run_path({str(IMPL / f'{POLICY}.py')!r}, run_name='__main__')"
    )
    done = subprocess.run([sys.executable, "-c", runner], capture_output=True, text=True, check=False, cwd=IMPL)
    assert done.returncode == 2
    assert "internal error (" in done.stderr and "command not checked" in done.stderr


def test_shells_nested_beyond_the_parsers_depth_are_still_judged_then_refused_when_too_deep() -> None:
    inner = "cat ~/.ssh/id_rsa"
    for _ in range(6):
        inner = "bash -c " + shlex.quote(inner)
    assert exit_code(inner) == 1
    benign = "echo hi"
    for _ in range(6):
        benign = "bash -c " + shlex.quote(benign)
    assert exit_code(benign) == 0


def test_a_command_nested_past_the_guards_own_limit_is_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    deep = "echo hi"
    for _ in range(6):
        deep = "bash -c " + shlex.quote(deep)
    monkeypatch.setattr(GUARD, "MAX_DEPTH", 0)
    monkeypatch.setenv("CHOCK_RAW_COMMAND", deep)
    assert GUARD.run(["bash"]) == 1
    assert "nested too deeply" in capsys.readouterr().err


def test_a_table_with_no_readers_is_refused(tmp_path: Path) -> None:
    with pytest.raises(paths.data_table.TableError, match="readers must not be empty"):
        paths.load(table_with(tmp_path, readers={}))
