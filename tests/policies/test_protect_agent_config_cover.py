"""protect-agent-config: the branches of the shell-guard modules the other tests leave unrun."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
walk = guardkit.load_guard(POLICY, "pathguard")
script = guardkit.load_guard(POLICY, "pathscript")
wrap = guardkit.load_guard(POLICY, "pathwrap")
SCRIPT = Path(guard.__file__)


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in (".git", ".claude", ".cursor", ".chock", "src", "docs"):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


def _run(raw: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "CHOCK_RAW_COMMAND": raw, "CHOCK_HOOK_CWD": str(cwd)}
    return subprocess.run([sys.executable, str(SCRIPT)], env=env, capture_output=True, text=True, check=False)


def _subst(depth: int, inner: str) -> str:
    for _ in range(depth):
        inner = f"echo $({inner})"
    return inner


def test_substitutions_nested_past_the_scan_limit_are_refused_with_the_deep_reason(_repo_root: Path) -> None:
    for inner in ("echo hi", "echo x > .mcp.json", "make"):
        assert guard.check(_subst(9, inner)) == guard.DEEP
    assert guard.check(_subst(8, "echo hi")) is None
    done = _run(_subst(9, "echo hi"), _repo_root)
    assert done.returncode == 1
    assert "nested too deep" in done.stderr


@pytest.mark.parametrize("flag", ["/log:", "/LOG+:", "/unilog:", "/UNILOG+:"])
def test_a_robocopy_log_file_is_a_write_to_its_path(flag: str) -> None:
    assert guard.check(f"robocopy src /srv/out {flag}.mcp.json") == guard.REASON
    assert guard.check(f"robocopy src /srv/out {flag}.claude/settings.json") == guard.REASON
    assert guard.check(f"robocopy src /srv/out {flag}/srv/out.log") is None


@pytest.mark.parametrize("tool", ["robocopy", "xcopy"])
@pytest.mark.parametrize("flag", ["/move", "/MOVE", "/mov"])
def test_a_move_deletes_its_source_so_a_protected_source_is_refused(tool: str, flag: str) -> None:
    for source in (".cursor", ".claude", ".chock", ".git/hooks"):
        assert guard.check(f"{tool} {source} /srv/out {flag}") == guard.REASON, source
    assert guard.check(f"{tool} src /srv/out {flag}") is None


@pytest.mark.parametrize("command", ["su", "flock /srv/l"])
def test_a_long_option_that_carries_a_script_runs_it(command: str) -> None:
    assert guard.check(f"{command} --command='echo x > .mcp.json'") == guard.REASON
    assert guard.check(f"{command} --command 'echo x > .mcp.json'") == guard.REASON
    assert guard.check(f"{command} --command='echo hi'") is None
    assert guard.check(f"{command} --command 'echo hi'") is None


def test_a_wrapper_option_it_does_not_know_leaves_the_command_position_unsure() -> None:
    assert wrap.unwrap("su", ["--command=id"]) == (["id"], False)
    assert wrap.unwrap("su", ["--command", "id"]) == (["id"], False)
    assert wrap.unwrap("su", ["--brand-new", "-c", "id"]) == (["id"], True)
    assert wrap.unwrap("unshare", ["-Z", "make"]) == (["make"], True)
    assert wrap.unwrap("unshare", ["-rZ", "make"]) == (["make"], True)
    assert guard.check("unshare -Z cat .mcp.json") == guard.REASON
    assert guard.check("unshare -Z cat README.md") is None


@pytest.mark.parametrize("raw", ["env -i", "env FOO=bar", "env -u HOME", "env -C src", "env -i -u HOME FOO=bar"])
def test_an_env_with_options_and_no_command_runs_nothing(raw: str) -> None:
    assert guard.check(raw) is None
    assert wrap.env_scripts(raw) == []
    assert guard.check(f"{raw} rm .mcp.json") == guard.REASON


def test_the_walk_refuses_a_nested_shell_the_reader_did_not_unwrap_without_the_depth_check() -> None:
    nested = "echo hi"
    for _ in range(6):
        nested = f"bash -c {shlex.quote(nested)}"
    assert wrap.too_deep(nested)
    assert walk.refuses(nested, guard.PROTECTED, guard.hit, guard.normalise)
    assert not walk.refuses("bash -c 'echo hi'", guard.PROTECTED, guard.hit, guard.normalise)


def test_a_name_below_a_file_is_not_a_directory(_repo_root: Path) -> None:
    (_repo_root / "notes.txt").write_text("x")
    base = str(_repo_root)
    assert script.isdir(base, "notes.txt/x") is False
    assert script.isdir(base, "notes.txt") is False
    assert script.isdir(base, "src") is True
    assert script.isdir(base, "missing/x") is False
    assert guard.check("cp a notes.txt/x") is None
    assert guard.check("cp a notes.txt/x/.mcp.json") == guard.REASON
