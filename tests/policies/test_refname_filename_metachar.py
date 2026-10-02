"""refname-filename-metachar: the shared name rules, the script gate over changed paths, and the pre-push hook."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from policies import gatekit, guardkit, scriptkit

POLICY = "refname-filename-metachar"
rules = guardkit.load_guard(POLICY, "refname_rules")
gate = scriptkit.load(POLICY, "refname-filename-metachar-gate.py")
push = scriptkit.load(POLICY, "refname-filename-metachar-pre-push.py")
SHA1 = "5c9350738729a2cf1c40f5851628384751cae484"
SHA256 = "ab" * 32
ZERO = "0" * 40
CRASH = ("traceback (most recent call last)", "syntax error", "syntaxerror", "unexpected eof")


def codes(name: str, **kwargs: bool) -> list[str]:
    return [code for code, _reason in rules.problems(name, **kwargs)]


def test_the_manifest_declares_the_gate_and_the_pre_push_script() -> None:
    hook = scriptkit.manifest(POLICY)["hook"]
    assert hook["gate"]["kind"] == "script"
    assert hook["gate"]["on"] == ["commit", "tool_use"]
    assert hook["gate"]["params"]["script"] == "refname-filename-metachar-gate.py"
    assert hook["script"]["on"] == ["push"]


@pytest.mark.parametrize(
    ("name", "want"),
    [
        ("a\nb", "control"),
        ("a\rb", "control"),
        ("a\x1b[2Jb", "control"),
        ("x" + chr(0x202E) + "txt.exe", "control"),
        ("$(id)", "subst"),
        ("x${IFS}y", "subst"),
        ("x$IFS$9y", "subst"),
        ("a`id`", "subst"),
        ("$'\\x41'", "subst"),
        ("a;b", "operator"),
        ("a&b", "operator"),
        ("a|b", "operator"),
        ("a>b", "operator"),
        ("aWQ= base64 -d", "decode"),
        ("x|base64 --decode", "decode"),
        ("b64decode", "decode"),
        ("-rf", "dash"),
        ("docs/--help.md", "dash"),
        ("notes ", "trailing"),
        ("config.", "trailing"),
        ("a/../b", "dotdot"),
    ],
)
def test_each_rule_names_its_shape(name: str, want: str) -> None:
    assert want in codes(name)


@pytest.mark.parametrize(
    "name",
    [
        "src/app/main.py",
        "meeting notes 2026.md",
        "Foo$Bar.class",
        "pkg/$name.tsx",
        "v1.2.3",
        "feature/np26-ref_names",
        ".github/workflows/ci.yml",
        "./a/./b",
        "base64-decoder.md",
        "base64_data.bin",
    ],
)
def test_plain_names_pass(name: str) -> None:
    assert rules.problems(name) == []


def test_dotdot_is_judged_only_when_asked() -> None:
    assert codes("../b", dotdot=False) == []
    assert codes("../b") == ["dotdot"]


def test_a_reason_is_given_once_per_shape() -> None:
    assert codes("-a/-b") == ["dash"]


@pytest.mark.parametrize(
    "ref",
    [SHA1, SHA1.upper(), SHA256, f"refs/heads/{SHA1}", f"refs/tags/{SHA1}", f"refs/remotes/origin/{SHA1}"],
)
def test_a_ref_shaped_like_a_full_commit_id_is_refused(ref: str) -> None:
    assert [code for code, _ in rules.ref_problems(ref)] == ["sha"]


@pytest.mark.parametrize("ref", [SHA1[:39], SHA1 + "0", f"fix/{SHA1}", "refs/heads/main", "deadbeef", f"refs/x/{SHA1}"])
def test_other_refs_are_not_commit_id_shaped(ref: str) -> None:
    assert rules.ref_problems(ref) == []


def test_a_shown_name_is_escaped_and_bounded() -> None:
    assert rules.shown("a\nb\x1b") == "a\\nb\\x1b"
    assert rules.shown("x" * 200) == "x" * 120 + "..."
    line = rules.describe("file name", "a;b", rules.problems("a;b"))
    assert line.startswith("file name 'a;b' is refused: it has a shell operator")
    assert line.endswith(rules.ADVICE)


# The script gate.


def run_gate(writes: dict[str, str]) -> tuple[int, dict, str]:
    proc = scriptkit.run_script_full(
        POLICY, "refname-filename-metachar-gate.py", Path.cwd(), json.dumps({"writes": writes})
    )
    return proc.returncode, json.loads(proc.stdout), proc.stderr


def test_the_gate_reports_each_refused_path_keyed_by_its_escaped_form() -> None:
    code, document, err = run_gate({"ok.py": "", "a\nb.txt": "", "x;y": "", '"a\\nb"': ""})
    assert code == 1
    assert [(f["path"], f["key"], f["line"], f["rule"]) for f in document["findings"]] == [
        ('"a\\\\nb"', 'name|"a\\\\nb"', 1, "filename"),
        ("a\\nb.txt", "name|a\\nb.txt", 1, "filename"),
        ("x;y", "name|x;y", 1, "filename"),
    ]
    assert "git prints it quoted" in document["findings"][0]["message"]
    assert "\n  file name 'x;y' is refused" in err
    assert err.rstrip().endswith(rules.ADVICE)
    assert not any(marker in err.lower() for marker in CRASH)


def test_the_gate_allows_plain_paths_with_an_empty_document() -> None:
    assert run_gate({"src/a.py": "x", "notes and ideas.md": ""}) == (0, {"findings": []}, "")


def test_a_gate_fault_exits_two_and_says_so(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert gate.main() == 2
    err = capsys.readouterr().err
    assert "internal error (JSONDecodeError)" in err
    assert "Traceback" not in err


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"README.md": "x\n", "legacy;name.txt": "old\n", "tools/sync.sh": "s\n"})


def stage(repo: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text, encoding="utf-8")
    scriptkit.git(repo, "add", "-A", "--", ".")


@pytest.mark.parametrize("name", ["-rf", "a\nb.txt", "r\\x.txt", 'q"x.txt', "tab\there", "x|base64 -d", "trail."])
def test_the_engine_refuses_a_new_path_at_commit(repo: Path, name: str) -> None:
    stage(repo, {name: "x\n"})
    code, err = gatekit.judge(POLICY, repo, gatekit.COMMIT)
    assert code == 1, err
    assert "is refused" in err


def test_the_engine_refuses_a_rename_into_a_bad_name(repo: Path) -> None:
    scriptkit.git(repo, "mv", "tools/sync.sh", "tools/sync`id`.sh")
    code, err = gatekit.judge(POLICY, repo, gatekit.COMMIT)
    assert code == 1, err


def test_the_engine_lets_an_edit_to_an_already_tracked_bad_name_through(repo: Path) -> None:
    stage(repo, {"legacy;name.txt": "new\n", "src/ok.py": "x\n"})
    assert gatekit.judge(POLICY, repo, gatekit.COMMIT)[0] == 0


def test_the_engine_judges_writes_at_tool_use_and_stop(repo: Path) -> None:
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, writes={"$(id).sh": "x"})[0] == 1
    assert gatekit.judge(POLICY, repo, gatekit.STOP, writes={"a;b.md": "x"})[0] == 1
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, writes={"legacy;name.txt": "new"})[0] == 0
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, writes={"src/util.py": "x"})[0] == 0


# The pre-push hook.


def line(remote: str, local: str = SHA1, local_ref: str = "refs/heads/work") -> str:
    return f"{local_ref} {local} {remote} {ZERO}\n"


@pytest.mark.parametrize(
    "remote", [f"refs/heads/{SHA1}", f"refs/tags/{SHA256}", "refs/heads/feat/x;id", "refs/heads/-x", "refs/tags/v1."]
)
def test_a_push_of_a_refused_name_is_refused(remote: str, tmp_path: Path) -> None:
    code, err = scriptkit.run_script(POLICY, "refname-filename-metachar-pre-push.py", tmp_path, line(remote))
    assert code == 1
    assert err.startswith("BLOCKED: pushed ref ")
    assert not any(marker in err.lower() for marker in CRASH)


def test_plain_pushes_and_deletions_pass(tmp_path: Path) -> None:
    stdin = line("refs/heads/feature/np26") + line("refs/tags/v1.2.0") + line("refs/heads/x;id", local=ZERO) + "\n"
    assert scriptkit.run_script(POLICY, "refname-filename-metachar-pre-push.py", tmp_path, stdin) == (0, "")


def test_every_refused_ref_is_named(tmp_path: Path) -> None:
    stdin = line("refs/heads/a;b") + line(f"refs/heads/{SHA1}")
    code, err = scriptkit.run_script(POLICY, "refname-filename-metachar-pre-push.py", tmp_path, stdin)
    assert code == 1
    assert err.count("BLOCKED:") == 2


def test_a_line_git_would_never_write_is_refused() -> None:
    assert push.refused(["refs/heads/a 1 2"]) == ["unreadable pre-push line 'refs/heads/a 1 2'"]


def test_a_pre_push_fault_exits_two(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    def boom(_lines: list[str]) -> list[str]:
        raise ValueError

    monkeypatch.setattr(push, "refused", boom)
    assert push.run("x") == 2
    assert "internal error (ValueError)" in capsys.readouterr().err


def test_the_hook_refuses_a_real_push_of_a_sha_named_branch(tmp_path: Path) -> None:
    """End to end through git: the hook sees the remote name git hands it."""
    remote = tmp_path / "remote.git"
    subprocess.run([scriptkit.GIT, "init", "-q", "--bare", str(remote)], check=True)
    work = scriptkit.init_repo(tmp_path / "w", {"a.txt": "a"})
    hook = work / ".git" / "hooks" / "pre-push"
    script = scriptkit.script_path(POLICY, "refname-filename-metachar-pre-push.py")
    hook.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}"\n', encoding="utf-8")
    hook.chmod(0o755)
    refused = subprocess.run(
        [scriptkit.GIT, "push", "-q", str(remote), f"HEAD:refs/heads/{SHA1}"],
        cwd=work,
        capture_output=True,
        text=True,
        check=False,
    )
    assert refused.returncode != 0
    assert "full commit id" in refused.stderr
    allowed = subprocess.run([scriptkit.GIT, "push", "-q", str(remote), "HEAD:refs/heads/main"], cwd=work, check=False)
    assert allowed.returncode == 0
